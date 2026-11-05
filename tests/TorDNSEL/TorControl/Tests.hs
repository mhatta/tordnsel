{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.TorControl.Tests
-- License     : Public domain (see LICENSE)
--
-- Tests for talking to a current Tor (0.4.9) over the control protocol, and
-- for how the network state manager uses what it learns.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.TorControl.Tests (tests) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import Data.Conduit (runConduit, (.|))
import qualified Data.Conduit.List as CL
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.List as L
import qualified Data.Map as M
import qualified Data.Set as S
import Data.Time (hoursToTimeZone)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Network.Socket
  ( socketPair, Family(AF_UNIX, AF_INET), SocketType(Stream), socketToHandle
  , socket, bind, listen, connect, close, getSocketName, SockAddr(..)
  , defaultProtocol )
import qualified Network.Socket.ByteString as NSB
import Control.Concurrent (threadDelay)
import System.Directory (getTemporaryDirectory, removeFile)
import System.IO
  (IOMode(ReadWriteMode), hClose, hFlush, openBinaryTempFile, hSetBuffering,
   BufferMode(LineBuffering))
import System.Posix.Files
  ( createNamedPipe, createSymbolicLink, getSymbolicLinkStatus, isRegularFile
  , fileMode )
import System.Timeout (timeout)
import Test.HUnit (Test(..), (@=?), (@?), assertFailure)

import TorDNSEL.Files
  (readSmallRegularFile, createFileExclusively, isGroupOrWorldWritable)

import TorDNSEL.Directory.Internals
import TorDNSEL.ExitTest.Request (Cookie(..), createRequest)
import TorDNSEL.ExitTest.Server.Internals
  ( startExitTestServer, terminateExitTestServer, ExitTestServerConfig(..)
  , maxTestClientsPerAddress )
import TorDNSEL.Fixtures
import TorDNSEL.NetworkState.Internals
  ( newConsensus, exitMappingName, takeCookie, acceptTestedAddress
  , maxTestedAddresses, mergeExitAddrsWithNetState )
import TorDNSEL.NetworkState.Storage.Internals
  ( ExitAddress(..), renderExitAddress, readExitAddresses, replaceExitAddresses
  , storePath )
import System.Directory (createDirectory, removeDirectoryRecursive)
import TorDNSEL.NetworkState.Types
import TorDNSEL.TorControl.Internals
import TorDNSEL.Util (encodeBase16, htonl, Port(..))

tests :: Test
tests = TestList [ protocolInfo', safeCookie, authChallenge, cookieFiles
                 , fakeTor, exitTestCookies, exitTestListener, addressMap
                 , replies, consensusEvent, consensus, mapping ]

-- | The PROTOCOLINFO reply of Tor 0.4.9.6 with cookie authentication.
protocolInfo' :: Test
protocolInfo' = TestCase $ do
  let rs = [ Reply ('2','5','0') "PROTOCOLINFO 1" []
           , Reply ('2','5','0') "AUTH METHODS=COOKIE,SAFECOOKIE \
                                 \COOKIEFILE=\"/var/run/tor/control.authcookie\"" []
           , Reply ('2','5','0') "VERSION Tor=\"0.4.9.6\"" []
           , Reply ('2','5','0') "OK" [] ]
  case parseProtocolInfo rs of
    Left e -> fail (e "")
    Right pi' -> do
      TorVersion 0 4 9 6 "" @=? torVersion pi'
      Just "/var/run/tor/control.authcookie" @=? cookieAuth (authMethods pi')
      False @=? nullAuth (authMethods pi')
      True  @=? safeCookieAuth (authMethods pi')

-- | SAFECOOKIE hashes, checked against Python's hmac module:
--
-- > hmac.new(key, bytes(range(32)) + b'\xaa' * 32 + b'\x55' * 32,
-- >          hashlib.sha256).hexdigest()
safeCookie :: Test
safeCookie = TestCase $ do
  let cookie = B.pack (map toEnum [0..31])
      (server, client) = safeCookieHashes cookie (B.replicate 32 '\xaa')
                                                 (B.replicate 32 '\x55')
  "5f7cb5569957c99373e329258545940f029af175da225f4a3125eebf30c24bba"
    @=? encodeBase16 server
  "9f99f2c4b75c91123ca5c6c6e3f76a9ef7fbd9471053cbe34454a4269cc39f7c"
    @=? encodeBase16 client

-- | Cookie files are read with a length limit, and only if they're regular
-- files: no FIFOs (which would block) or devices (which could be endless).
cookieFiles :: Test
cookieFiles = TestCase $ do
  tmp <- getTemporaryDirectory
  (path, h) <- openBinaryTempFile tmp "cookie"
  B.hPut h (B.replicate 100 'x') >> hClose h
  r1 <- readSmallRegularFile 33 path
  33 @=? B.length r1
  removeFile path
  r2 <- E.try (readSmallRegularFile 33 "/dev/zero")
  isLeft' r2 @? "/dev/zero accepted"
  let fifo = path ++ ".fifo"
  createNamedPipe fifo 0o600
  r3 <- timeout 2000000 (E.try (readSmallRegularFile 33 fifo))
  removeFile fifo
  case r3 of
    Nothing -> assertFailure "reading a FIFO blocked"
    Just r  -> isLeft' r @? "FIFO accepted"
  -- createFileExclusively replaces a symbolic link rather than writing
  -- through it, and sets the mode despite the umask
  (victim, hv) <- openBinaryTempFile tmp "victim"
  B.hPut hv (B.pack "victim") >> hClose hv
  let pidFile = victim ++ ".pid"
  createSymbolicLink victim pidFile
  hp <- createFileExclusively pidFile 0o644
  B.hPut hp (B.pack "1234\n") >> hClose hp
  B.readFile victim >>= (B.pack "victim" @=?)
  st <- getSymbolicLinkStatus pidFile
  (True, 0o644) @=? (isRegularFile st, fileMode st `mod` 0o1000)
  mapM_ removeFile [victim, pidFile]
  (True, False) @=? (isGroupOrWorldWritable 0o1777, isGroupOrWorldWritable 0o755)
  where
    isLeft' :: Either E.IOException a -> Bool
    isLeft' = either (const True) (const False)

-- | A fake Tor on the control port: whatever it claims, we never send it a
-- cookie file's contents.
fakeTor :: Test
fakeTor = TestCase $ do
  tmp <- getTemporaryDirectory
  (secret, h) <- openBinaryTempFile tmp "secret"
  B.hPut h (B.pack "32 bytes of a secret file.......") >> hClose h
  (short, h') <- openBinaryTempFile tmp "short"
  B.hPut h' (B.pack "too short") >> hClose h'
  let cookieOnly = "AUTH METHODS=COOKIE COOKIEFILE=\"" ++ secret ++ "\""
      wrongLength = "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"" ++ short ++ "\""
  -- COOKIE only: refuse without sending anything after PROTOCOLINFO
  (ok1, sent1) <- talkTo True cookieOnly
  (False, ["PROTOCOLINFO 1"]) @=? (ok1, map (B.map toUpperC) sent1)
  -- SAFECOOKIE, but the "cookie" isn't 32 bytes: same
  (ok2, sent2) <- talkTo True wrongLength
  (False, ["PROTOCOLINFO 1"]) @=? (ok2, map (B.map toUpperC) sent2)
  -- a fake that never answers QUIT doesn't hang us (the QUIT wait is 5 s)
  r3 <- timeout 15000000 (talkTo False cookieOnly)
  fmap fst r3 @=? Just False
  mapM_ removeFile [secret, short]
  where
    toUpperC c = if c >= 'a' && c <= 'z' then toEnum (fromEnum c - 32) else c
    -- Run openConnection against a fake Tor sending the given AUTH line, and
    -- answering QUIT or not.
    -- Return whether opening succeeded and the lines the fake Tor received.
    talkTo answerQuit authLine = do
      (ours, theirs) <- socketPair AF_UNIX Stream 0
      ourH <- socketToHandle ours ReadWriteMode
      theirH <- socketToHandle theirs ReadWriteMode
      hSetBuffering theirH LineBuffering
      done <- newEmptyMVar
      _ <- forkIO $ do
        l1 <- B.hGetLine theirH
        B.hPut theirH . B.pack $ concat
          [ "250-PROTOCOLINFO 1\r\n250-", authLine, "\r\n"
          , "250-VERSION Tor=\"0.4.9.6\"\r\n250 OK\r\n" ]
        hFlush theirH
        -- anything else we receive, until we're closed
        rest <- collect answerQuit theirH
        putMVar done (l1 : rest)
      r <- E.try (openConnection ourH Nothing (\n -> return (B.replicate n 'n')))
      ok <- case r of
        Left (_ :: E.SomeException) -> hClose ourH >> return False
        Right conn -> closeConnection conn >> return True
      sent <- takeMVar done
      return (ok, map (B.takeWhile (/= '\r')) . filter (not . isQuit) $ sent)
    collect answerQuit hd = do
      r <- E.try (B.hGetLine hd)
      case r of
        Left (_ :: E.IOException) -> return []
        Right l | B.null l -> return []
                | isQuit l, answerQuit -> do
                    B.hPut hd (B.pack "250 closing connection\r\n")
                    hFlush hd >> hClose hd
                    return [l]
                | otherwise -> (l :) `fmap` collect answerQuit hd
    isQuit l = B.map toUpperC (B.take 4 l) == B.pack "QUIT"

-- | Exit test cookies work once, and a router gets at most
-- 'maxTestedAddresses' tested exit addresses.
exitTestCookies :: Test
exitTestCookies = TestCase $ do
  let c = Cookie (B.replicate 32 'c')
      m = M.fromList [(c, 'x')]
      (first', m') = takeCookie c m
      (second', _) = takeCookie c m'
  (Just 'x', Nothing) @=? (first', second')
  let t = posixSecondsToUTCTime 0
      router n = Router Nothing (Just $ TestResults t
                   (M.fromList [(fromIntegral a, t) | a <- [1 .. n]])) True t
  acceptTestedAddress (Router Nothing Nothing True t) 7 @? "first address refused"
  acceptTestedAddress (router (maxTestedAddresses - 1)) 1000 @? "room refused"
  not (acceptTestedAddress (router maxTestedAddresses) 1000) @? "over the cap"
  acceptTestedAddress (router maxTestedAddresses) 1 @? "known address refused"
  -- stored results with more addresses than that (written before the limit,
  -- say) are cut down to the most recent when loaded
  let rid = ridA
      stored = ExitAddress rid t t (M.fromList
                 [ (fromIntegral a, posixSecondsToUTCTime (fromIntegral a))
                 | a <- [1 .. 3 * maxTestedAddresses] ])
      loaded = mergeExitAddrsWithNetState [stored] emptyNetworkState
      kept = maybe [] (M.keys . tstAddresses) $
               rtrTestResults =<< M.lookup rid (nsRouters loaded)
  [fromIntegral a | a <- [2 * maxTestedAddresses + 1 .. 3 * maxTestedAddresses]]
    @=? kept
  kept @=? M.keys (nsAddrs loaded)
  -- the store is written to disk and read back, even out of order
  tmp <- getTemporaryDirectory
  (dirFile, hd) <- openBinaryTempFile tmp "state"
  hClose hd >> removeFile dirFile >> createDirectory dirFile
  _ <- replaceExitAddresses dirFile (nsRouters loaded)
  [ea] <- readExitAddresses dirFile
  (eaRouterID ea, M.keys (eaAddresses ea)) @=? (rid, kept)
  let one r a = ExitAddress r t t (M.singleton a t)
  B.writeFile (dirFile ++ storePath) . B.concat . map renderExitAddress $
    [one ridC 3, one ridA 1, one ridB 2]
  back <- readExitAddresses dirFile
  L.sort [ridA, ridB, ridC] @=? map eaRouterID back
  removeDirectoryRecursive dirFile

-- | One host can't take all the exit test listener's handlers: past the
-- limit, its connections are closed at once, and other hosts (exits) are
-- still served.
exitTestListener :: Test
exitTestListener = TestCase $ do
  listener <- socket AF_INET Stream defaultProtocol
  bind listener (SockAddrInet 0 (htonl 0x7f000001))
  listen listener 64
  addr <- getSocketName listener
  got <- newEmptyMVar
  server <- startExitTestServer [(addr, Just listener)] ExitTestServerConfig
    { etscfNotifyNewExitAddress = \_ cookie a -> putMVar got (cookie, a)
    , etscfConcClientLimit      = 100
    , etscfListenAddrs          = S.singleton addr }
  let from src = do
        c <- socket AF_INET Stream defaultProtocol
        bind c (SockAddrInet 0 (htonl src))
        connect c addr
        return c
  silent <- mapM (const $ from 0x7f000001) [1 .. maxTestClientsPerAddress]
  threadDelay 100000
  extra <- from 0x7f000001
  closed <- timeout 1000000 (E.try (NSB.recv extra 1))
  case closed of
    Just (Right "")                   -> return ()
    Just (Left (_ :: E.IOException))  -> return ()
    _ -> assertFailure "connection over the limit kept open"
  -- another address is still served
  let cookie = Cookie (B.replicate 32 'k')
  other <- from 0x7f000002
  NSB.sendAll other (createRequest "127.0.0.1" (Port 80) cookie)
  r <- timeout 2000000 (takeMVar got)
  Just (cookie, 0x7f000002) @=? r
  mapM_ close (extra : other : silent)
  terminateExitTestServer Nothing server

-- | Parsing Tor's reply to AUTHCHALLENGE.
authChallenge :: Test
authChallenge = TestCase $ do
  let hash  = B.replicate 64 'A'
      nonce = B.replicate 64 '0'
      ok    = B.concat ["AUTHCHALLENGE SERVERHASH=", hash, " SERVERNONCE=", nonce]
  Right (B.replicate 32 '\xaa', B.replicate 32 '\0')
    @=? either (Left . ($ "")) Right (parseAuthChallenge ok)
  mapM_ (\t -> isLeft' (parseAuthChallenge t) @? ("accepted " ++ B.unpack t))
    [ "AUTHCHALLENGE SERVERHASH=" `B.append` hash
    , B.concat ["AUTHCHALLENGE SERVERHASH=", B.take 62 hash, " SERVERNONCE=", nonce]
    , B.concat ["AUTHCHALLENGE SERVERHASH=", B.take 63 hash, "x SERVERNONCE=", nonce]
    , B.concat ["SOMETHING SERVERHASH=", hash, " SERVERNONCE=", nonce] ]
  where
    isLeft' :: Either ShowS a -> Bool
    isLeft' = either (const True) (const False)

-- | ADDRMAP events: the UTC EXPIRES field wins over the local time.
addressMap :: Test
addressMap = TestCase $ do
  let tz = hoursToTimeZone 9
      parse = either (Left . ($ "")) (Right . expiry) . parseAddressMap tz
      expiry (AddrMap _ _ e) = show e
  Right "2026-10-24 12:00:00" @=?
    parse "example.com 192.0.2.1 \"2026-10-24 21:00:00\" \
          \EXPIRES=\"2026-10-24 12:00:00\" CACHED=\"NO\""
  -- without EXPIRES (Tor before 0.2.0.x) the local time zone is used
  Right "2026-10-24 12:00:00" @=?
    parse "example.com 192.0.2.1 \"2026-10-24 21:00:00\""
  Right "Never" @=? parse "example.com 192.0.2.1 NEVER"

-- | Raw control port output, including an asynchronous NEWCONSENSUS event
-- interleaved with command replies.
replies :: Test
replies = TestCase $ do
  rs <- runConduit $ CL.sourceList chunks .| c_replies .| CL.consume
  map (map repCode) rs @=?
    [ [('2','5','0')]
    , [('6','5','0'), ('6','5','0')]
    , [('2','5','0'), ('2','5','0')] ]
  case rs of
    [_, Reply _ "NEWCONSENSUS" doc : _, _] ->
      2 @=? length (filter ("r " `B.isPrefixOf`) doc)
    _ -> fail "unexpected replies"
  where
    chunks = [ "250 OK\r\n650+NEWCONSENSUS\r\n"
             , B.unlines (map (`B.append` "\r") nsLines)
             , ".\r\n650 OK\r\n"
             , "250-tdeadbeef.tordnsel-test.invalid=10.0.0.1.A4C3850084D6BF"
             , "6C605C8C259A089F5FDF017621.exit\r\n250 OK\r\n" ]

consensusEvent :: Test
consensusEvent = TestCase $ do
  ref <- newIORef (-1, [])
  let EventHandler code handler = newConsensusEvent $ \errs rss ->
        writeIORef ref (length errs, map rsRouterID rss)
  "NEWCONSENSUS" @=? code
  handler [ Reply ('6','5','0') "NEWCONSENSUS" nsLines
          , Reply ('6','5','0') "OK" [] ]
  (n,rids) <- readIORef ref
  0 @=? n
  [ "A4C3850084D6BF6C605C8C259A089F5FDF017621"
    , "CB35CCC5FB63DF0B41485D2E73DA07C1C70470CC" ]
    @=? map encodeBase16RouterIDUpper rids
  where encodeBase16RouterIDUpper = B.map toUpperC . encodeBase16RouterID
        toUpperC c = if c >= 'a' && c <= 'f' then toEnum (fromEnum c - 32) else c

-- | A new consensus is a complete list: routers missing from it are no
-- longer considered running, listed ones are refreshed.
consensus :: Test
consensus = TestCase $ do
  let later = posixSecondsToUTCTime (now + 3600)
      rs rid = RS rid later True
      ns' = newConsensus later [rs ridA, rs ridC] networkState
      running rid = rtrIsRunning <$> M.lookup rid (nsRouters ns')
      lastStatus rid = rtrLastStatus <$> M.lookup rid (nsRouters ns')
  (Just True, Just False, Just True) @=?
    (running ridA, running ridB, running ridC)
  Just later @=? lastStatus ridA
  Just (posixSecondsToUTCTime now) @=? lastStatus ridB
  -- addresses are untouched
  nsAddrs networkState @=? nsAddrs ns'
  S.size (M.keysSet $ nsRouters ns') @=? 3

-- | Exit tests connect to a unique, controller-mapped hostname.
mapping :: Test
mapping = TestCase $ do
  let name = exitMappingName (Cookie $ B.pack ['\xde','\xad','\xbe','\xef']
                                        `B.append` B.replicate 28 '\0')
  "tdeadbeef000000000000.tordnsel-test.invalid" @=? name
  B.all (\c -> c `elem` (['a'..'z'] ++ ['0'..'9'] ++ "-.")) name
    @? "a valid destination for MAPADDRESS"

nsLines :: [B.ByteString]
nsLines =
  [ "r test005eb pMOFAITWv2xgXIwlmgifX98BdiE /sfG4X/TZbkh9wwokg8g9hf89BU \
    \2038-01-01 00:00:00 10.200.0.12 5005 0"
  , "s Exit Fast Guard HSDir Running V2Dir Valid"
  , "w Bandwidth=56"
  , "p accept 1-65535"
  , "r test004ea yzXMxftj3wtBSF0uc9oHwccEcMw jmCdf8iX+yHkp/wC4Eik+MP8d7M \
    \2038-01-01 00:00:00 10.200.0.11 5004 0"
  , "s Exit Fast Guard HSDir Running V2Dir Valid"
  , "w Bandwidth=214"
  , "p accept 1-65535" ]
