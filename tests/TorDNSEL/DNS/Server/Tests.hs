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

import qualified Data.ByteString.Char8 as B
import qualified Data.Map as M
import Network.Socket
  (Socket, socket, Family(AF_INET), SocketType(Datagram), SockAddr(..))
import Test.HUnit (Test(..), (@=?), (@?), assertFailure)

import TorDNSEL.DNS
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
  where
    client = SockAddrInet 40000 (htonl $ ip "192.0.2.1")
    typ label a b = (label, show' a) @=? (label, show' b)
    show' Positive = "Positive" :: String
    show' Negative = "Negative"
    show' Other    = "Other"
    rrNameOf m = qName (msgQuestion m)

-- | A DNS query.
query :: DomainName -> Type -> Message
query name qt = Message 0x1234 False StandardQuery False False True False
                        False False NoError (Question name qt IN) [] [] []

dnsConf :: Socket -> DNSConfig
dnsConf sock = DNSConfig
  { dnsSocket = sock
  , dnsAuthZone = authZone
  , dnsMyName = toName ["ns","example","com"]
  , dnsSOA = SOA zone ttl (toName ["ns","example","com"])
                 (toName ["hostmaster","example","com"]) 0 ttl ttl ttl ttl
  , dnsNS = NS zone ttl (toName ["ns","example","com"])
  , dnsA = Nothing
  , dnsLists = lists
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
