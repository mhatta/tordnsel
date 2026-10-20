{-# LANGUAGE OverloadedStrings  #-}
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

import qualified Data.ByteString.Char8 as B
import Data.Conduit (runConduit, (.|))
import qualified Data.Conduit.List as CL
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Map as M
import qualified Data.Set as S
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import Test.HUnit (Test(..), (@=?), (@?))

import TorDNSEL.Directory.Internals
import TorDNSEL.ExitTest.Request (Cookie(..))
import TorDNSEL.Fixtures
import TorDNSEL.NetworkState.Internals
  (newConsensus, exitMappingName)
import TorDNSEL.NetworkState.Types
import TorDNSEL.TorControl.Internals

tests :: Test
tests = TestList [protocolInfo', replies, consensusEvent, consensus, mapping]

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
