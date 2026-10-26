{-# LANGUAGE OverloadedStrings  #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Server.Tests
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- DNS server tests: parsing of the three exit list query types and the
-- responses generated for them.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.DNS.Server.Tests (tests) where

import Control.Concurrent (forkIO, threadDelay, killThread)
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import qualified Data.Map as M
import qualified Data.List as L
import Data.Time.Clock.POSIX (POSIXTime)
import Network.Socket
  ( Socket, socket, Family(AF_INET), SocketType(Datagram, Stream), SockAddr(..)
  , bind, listen, accept, connect, getSocketName, close )
import qualified Network.Socket.ByteString as NSB
import System.Timeout (timeout)
import Test.HUnit (Test(..), (@=?), (@?), assertFailure)

import TorDNSEL.DNS
import TorDNSEL.DNS.Internals (Packet(..), encodeMessage, decodeMessage, tcpFrame)
import TorDNSEL.DNS.Server.Internals
import TorDNSEL.ExitList
import TorDNSEL.Fixtures
import TorDNSEL.Util

tests :: Test
tests = TestList
  [ TestList . map TestCase $
      [ dropAuthZone authZone queryName @=? Just query
      , parseExitListQuery lists query @=? FullQuery query'
      ]
  , TestLabel "query parsing" parsing
  , TestLabel "responses" responses
  , TestLabel "truncation" truncation
  , TestLabel "rate limiting" rateLimiting
  , TestLabel "TCP" tcp
  ]
  where
    query = toLabels ["ip-port","1","2","3","4","80","10","0","0","1"]
    queryName = toName [ "1","0","0","10","80","4","3","2","1"
                       , "ip-port","torhosts","example","com" ]
    query' = IPPort { queryAddr = ip "10.0.0.1", destAddr = ip "1.2.3.4"
                    , destPort = 80 }

parsing :: Test
parsing = TestList . map TestCase $
  [ FullQuery (IPList (ip "1.2.3.4") "examplenet")
      @=? parse ["list","examplenet","1","2","3","4"]
  , FullQuery (IPList (ip "1.2.3.4") "examplenet")
      @=? parse ["LIST","ExampleNet","1","2","3","4"]
  , FullQuery (IPMe (ip "1.2.3.4") 6667) @=? parse ["me","6667","1","2","3","4"]
  -- prefixes of valid names are empty non-terminals (QNAME minimisation)
  , PartialQuery @=? parse ["ip-port"]
  , PartialQuery @=? parse ["ip-port","1","2","3","4","80","10"]
  , PartialQuery @=? parse ["list","examplenet"]
  , PartialQuery @=? parse ["me","80","1"]
  -- and everything else doesn't exist
  , NoSuchName @=? parse ["ip-port","1","2","3","4","80","10","0","0","1","5"]
  , NoSuchName @=? parse ["ip-port","256"]
  , NoSuchName @=? parse ["ip-port","1","2","3","4","65536"]
  , NoSuchName @=? parse ["list","nosuchlist"]
  , NoSuchName @=? parse ["me","x"]
  , NoSuchName @=? parse ["www"]
  , NoSuchName @=? parseExitListQuery M.empty (toLabels ["list"])
  ]
  where parse = parseExitListQuery lists . toLabels

responses :: Test
responses = TestCase $ do
  sock <- socket AF_INET Datagram 0
  let conf = dnsConf sock
      ask src qt labels = dnsResponse conf src
        (query (toName $ labels ++ ["torhosts","example","com"]) qt) now
        networkState
      fromV4 a = SockAddrInet 40000 (htonl $ ip a)

  -- query type 1
  let (t1,r1) = ask client TA ["11","0","0","10","80","4","3","2","1","ip-port"]
  typ "t1" Positive t1
  NoError @=? msgRCode r1
  [A (rrNameOf r1) ttl 0x7f000002] @=? msgAnswers r1
  let (t2,r2) = ask client TA ["11","0","0","10","25","4","3","2","1","ip-port"]
  typ "t2" Negative t2
  NXDomain @=? msgRCode r2
  -- an exit whose exit address was found by active testing
  let (t3,_) = ask client TA ["99","0","0","10","80","4","3","2","1","ip-port"]
  typ "t3" Positive t3
  -- the RFC 5782 test address is always listed
  let (t4,_) = ask client TA ["2","0","0","127","80","4","3","2","1","ip-port"]
  typ "t4" Positive t4
  -- TXT records explain the listing
  let (_,r5) = ask client TTXT ["11","0","0","10","80","4","3","2","1","ip-port"]
  case msgAnswers r5 of
    [TXT _ _ [txt]] -> "10.0.0.11 is a Tor exit" `B.isPrefixOf` txt @? "TXT"
    other -> assertFailure $ "unexpected TXT answer " ++ show other
  -- other record types: NOERROR without data (RFC 2308)
  let (_,r6) = ask client (UnsupportedType 28)
                   ["11","0","0","10","80","4","3","2","1","ip-port"]
  (NoError, []) @=? (msgRCode r6, msgAnswers r6)
  -- empty non-terminal
  let (_,r7) = ask client TA ["4","3","ip-port"]
  (NoError, []) @=? (msgRCode r7, msgAnswers r7)

  -- query type 2
  let (t8,_) = ask client TA ["11","0","0","10","examplenet","list"]
  typ "t8" Positive t8
  let (t9,_) = ask client TA ["13","0","0","10","examplenet","list"]
  typ "t9" Negative t9
  let (_,r10) = ask client TA ["11","0","0","10","othernet","list"]
  NXDomain @=? msgRCode r10

  -- query type 3: the destination is whoever asks, and nothing is cached
  let (t11,r11) = ask (fromV4 "192.0.2.80") TA ["11","0","0","10","443","me"]
  typ "t11" Positive t11
  [0] @=? map rrTTL (msgAnswers r11)
  let (t12,r12) = ask (fromV4 "192.0.2.80") TA ["13","0","0","10","443","me"]
  typ "t12" Negative t12
  [(0,0)] @=? [(t,m) | SOA _ t _ _ _ _ _ _ m <- msgAuthority r12]
  let (t13,_) = ask (fromV4 "198.51.100.1") TA ["13","0","0","10","443","me"]
  typ "t13" Positive t13
  -- an IPv6 client can't be reached by an IPv4 exit address
  let (t14,_) = ask (SockAddrInet6 40000 0 (0x20010db8,0,0,1) 0) TA
                    ["11","0","0","10","443","me"]
  typ "t14" Negative t14

  -- a router whose descriptor is older than 48 hours is no longer listed
  let (t15,_) = ask client TA ["12","0","0","10","80","4","3","2","1","ip-port"]
  typ "t15" Negative t15

  -- EDNS(0): echo an OPT record; reject unknown versions with BADVERS
  let edns v = query (toName ["torhosts","example","com"]) TSOA
                 `withAdditional` [UnsupportedResourceRecord (DomainName [])
                                     (v * 0x10000 + 0x8000) TOPT
                                     (UnsupportedClass 4096) B.empty]
      withAdditional m rrs = m { msgAdditional = rrs }
      (_,r16) = dnsResponse conf client (edns 0) now networkState
      (_,r17) = dnsResponse conf client (edns 1) now networkState
  Just (EDNS 1232 0 0 True) @=? findEDNS r16
  (NoError, Just (EDNS 1232 1 0 True))
    @=? (msgRCode r17, findEDNS r17)

  -- queries outside our zone are refused
  let (_,r18) = dnsResponse conf client (query (toName ["example","org"]) TA)
                            now networkState
  Refused @=? msgRCode r18

  -- QCLASS * is answered like IN; other classes have no data
  let withClass qc m = m { msgQuestion = (msgQuestion m) { qClass = qc } }
      name19 = toName ["11","0","0","10","80","4","3","2","1","ip-port"
                      ,"torhosts","example","com"]
      (t19,r19) = dnsResponse conf client (withClass AnyClass (query name19 TA))
                              now networkState
      (_,r20) = dnsResponse conf client
                  (withClass (UnsupportedClass 3) (query name19 TA)) now
                  networkState
  typ "t19" Positive t19
  [A name19 ttl 0x7f000002] @=? msgAnswers r19
  (NXDomain, []) @=? (msgRCode r20, msgAnswers r20)
  where
    client = SockAddrInet 40000 (htonl $ ip "192.0.2.1")
    typ label a b = (label, show' a) @=? (label, show' b)
    show' Positive = "Positive" :: String
    show' Negative = "Negative"
    show' Other    = "Other"
    rrNameOf m = qName (msgQuestion m)

-- | Responses too big for UDP are truncated, so that clients retry over TCP.
truncation :: Test
truncation = TestCase $ do
  let name = toName ["torhosts","example","com"]
      big = (query name TTXT)
              { msgQR = True
              , msgAnswers = replicate 4 (TXT name ttl [B.replicate 200 'x']) }
      withEDNS size m = m { msgAdditional = [UnsupportedResourceRecord
                              (DomainName []) 0 TOPT (UnsupportedClass size)
                              B.empty] }
  512  @=? udpPayloadLimit (query name TA)
  1232 @=? udpPayloadLimit (withEDNS 4096 $ query name TA)
  512  @=? udpPayloadLimit (withEDNS 100 $ query name TA)
  case decodeMessage . Packet =<< encodeResponse 512 big of
    Just m  -> (True, [], [], []) @=?
                 (msgTC m, msgAnswers m, msgAuthority m, msgAdditional m)
    Nothing -> assertFailure "no truncated response"
  -- the OPT record survives truncation
  case decodeMessage . Packet =<< encodeResponse 512 (withEDNS 1232 big) of
    Just m  -> (True, 1) @=? (msgTC m, length (msgAdditional m))
    Nothing -> assertFailure "no truncated response with EDNS"
  -- it fits in 1232 bytes, and certainly over TCP
  fmap (msgTC) (decodeMessage . Packet =<< encodeResponse 1232 big)
    @=? Just False
  -- queries are never truncated
  Nothing @=? encodeResponse 20 (query name TA)

-- | Token buckets per client network.
rateLimiting :: Test
rateLimiting = TestCase $ do
  let run :: POSIXTime -> SockAddr -> RateLimiter -> [RateDecision]
          -> IO RateLimiter
      run _ _ rl [] = return rl
      run t a rl (expected:rest) = do
        let (d, rl') = rateLimit 2 t a rl
        expected @=? d
        run t a rl' rest
      v4 x = SockAddrInet 40000 (htonl $ ip x)
  rl1 <- run 100 (v4 "192.0.2.1") emptyRateLimiter
           [Allow, Allow, Slip, Drop, Slip, Drop]
  -- the same /24 shares the bucket; another network doesn't
  rl2 <- run 100 (v4 "192.0.2.200") rl1 [Slip]
  rl3 <- run 100 (v4 "192.0.3.1") rl2 [Allow, Allow, Slip]
  -- half a second later, there's one token again; a second later, two
  rl4 <- run 100.5 (v4 "192.0.2.1") rl3 [Allow, Drop]
  _   <- run 102 (v4 "192.0.2.1") rl4 [Allow, Allow, Slip]
  -- IPv6 clients are grouped by /56
  let v6 b = SockAddrInet6 40000 0 (0x20010db8, b, 0, 1) 0
  rl5 <- run 100 (v6 0x00000100) emptyRateLimiter [Allow, Allow, Slip]
  _   <- run 100 (v6 0x000001ff) rl5 [Drop]
  _   <- run 100 (v6 0x00000200) rl5 [Allow]
  -- networks whose buckets have filled up again are forgotten
  let (_, rl6) = rateLimit 2 103 (v4 "198.51.100.1") rl3
  M.keys (rlBuckets rl6) @=? [rateKey (v4 "198.51.100.1")]
  -- at most so many networks are tracked; others are treated as limited
  let step (ds, rl) a = let (d, rl') = rateLimitWith 2 5 100 (v4 a) rl
                        in (d : ds, rl')
      (ds7, rl7) = L.foldl' step ([], emptyRateLimiter)
                     ["192.0.2.1", "192.0.3.1", "192.0.4.1", "192.0.5.1"
                     , "192.0.2.2"]
  [Allow, Allow, Slip, Drop, Allow] @=? reverse ds7
  2 @=? M.size (rlBuckets rl7)

-- | DNS over TCP on a real connection: pipelined queries are answered in
-- order, and idle or broken connections are closed.
tcp :: Test
tcp = TestCase $ do
  listener <- socket AF_INET Stream 0
  bind listener (SockAddrInet 0 (htonl $ ip "127.0.0.1"))
  listen listener 5
  addr <- getSocketName listener
  let name = toName ["torhosts","example","com"]
      handler _ q = return . Just $ q { msgQR = True, msgAnswers =
                      [A name ttl (fromIntegral (msgID q))] }
      -- accept the next connection, in the background, closing it after 4
      -- queries or 300 ms of idleness
      serve = serveWith 300000
      serveWith idle = do
        _ <- forkIO $ do
          (s, a) <- accept listener
          serveTCPConnection s a (return idle) 4 (\_ _ -> return ())
                             handler `E.finally` close s
        return ()
      connectTo = do
        c <- socket AF_INET Stream 0
        connect c addr
        return c
      frame i = tcpFrame . unPacket . encodeMessage $
                  (query name TA) { msgID = i }
      readResponse c = do
        mbLen <- recvN c 2
        case mbLen of
          Just l | [h, lo] <- B.unpack l -> do
            body <- recvN c (fromEnum h * 256 + fromEnum lo)
            return $ decodeMessage . Packet =<< body
          _ -> return Nothing

  -- two queries in one segment, one split over two
  serve
  c <- connectTo
  NSB.sendAll c (frame 1 `B.append` frame 2)
  let f3 = frame 3
  NSB.sendAll c (B.take 5 f3) >> threadDelay 50000 >> NSB.sendAll c (B.drop 5 f3)
  rs <- mapM (const $ readResponse c) [1 :: Int, 2, 3]
  map (fmap msgID) rs @=? map Just [1, 2, 3]
  map (fmap (map aAddr . msgAnswers)) rs @=? map (Just . (:[])) [1, 2, 3]
  -- then it's closed after being idle
  closed <- timeout 2000000 (NSB.recv c 1)
  Just B.empty @=? closed
  close c

  -- something that isn't a DNS message ends the connection
  serve
  c' <- connectTo
  NSB.sendAll c' (B.pack "\0\3abc")
  closed' <- timeout 2000000 (NSB.recv c' 1)
  Just B.empty @=? closed'
  close c'

  -- after 4 queries (the limit given above) the connection is closed, long
  -- before the 5 s idle timeout
  serveWith 5000000
  c'' <- connectTo
  NSB.sendAll c'' (B.concat $ map frame [1 .. 4])
  rs' <- mapM (const $ readResponse c'') [1 :: Int .. 4]
  map (fmap msgID) rs' @=? map Just [1, 2, 3, 4]
  closed'' <- timeout 1000000 (NSB.recv c'' 1)
  Just B.empty @=? closed''
  close c'' >> close listener

  -- one client network gets at most maxTCPConnectionsPerNetwork connections
  tcpListener <- socket AF_INET Stream 0
  bind tcpListener (SockAddrInet 0 (htonl $ ip "127.0.0.1"))
  listen tcpListener 32
  tcpAddr <- getSocketName tcpListener
  udp <- socket AF_INET Datagram 0
  server <- forkIO $ runTCPServer id (dnsConf udp) { dnsTCPSocket = tcpListener }
  let open1 = do
        c3 <- socket AF_INET Stream 0
        connect c3 tcpAddr
        return c3
  conns <- mapM (const open1) [0 .. maxTCPConnectionsPerNetwork]
  threadDelay 200000
  -- the last one was closed at once; the others are still open
  let isOpen c3 = do
        r <- E.try (timeout 100000 (NSB.recv c3 1))
        return $ case r of
          Right Nothing -> True
          Right (Just _) -> False
          Left (_ :: E.IOException) -> False
  opens <- mapM isOpen conns
  (replicate maxTCPConnectionsPerNetwork True ++ [False]) @=? opens
  mapM_ close conns
  killThread server >> close tcpListener >> close udp
  where
    recvN c n = go n []
      where go 0 acc = return . Just . B.concat $ reverse acc
            go k acc = do
              bs <- NSB.recv c k
              if B.null bs then return Nothing else go (k - B.length bs) (bs:acc)

-- | A DNS query.
query :: DomainName -> Type -> Message
query name qt = Message 0x1234 False StandardQuery False False True False
                        False False NoError (Question name qt IN) [] [] []

dnsConf :: Socket -> DNSConfig
dnsConf sock = DNSConfig
  { dnsSocket = sock
  , dnsTCPSocket = sock
  , dnsAuthZone = authZone
  , dnsMyName = toName ["ns","example","com"]
  , dnsSOA = SOA zone ttl (toName ["ns","example","com"])
                 (toName ["hostmaster","example","com"]) 0 ttl ttl ttl ttl
  , dnsNS = NS zone ttl (toName ["ns","example","com"])
  , dnsA = Nothing
  , dnsLists = lists
  , dnsRateLimit = 0
  , dnsByteStats = \_ _ -> return ()
  , dnsRespStats = const $ return () }
  where zone = toName ["torhosts","example","com"]

lists :: NamedLists
lists = M.fromList
  [("examplenet", [AddrPortPattern (ip "1.2.3.4") 0xffffffff 6667 6667])]

authZone :: DomainName
authZone = DomainName $ map Label ["com","example","torhosts"]

toLabels :: [B.ByteString] -> [Label]
toLabels = map Label

toName :: [B.ByteString] -> DomainName
toName = DomainName . toLabels
