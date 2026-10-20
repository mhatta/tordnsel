{-# LANGUAGE OverloadedStrings  #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Web.Tests
-- License     : Public domain (see LICENSE)
--
-- Web interface tests.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.Web.Tests (tests) where

import qualified Data.ByteString.Char8 as B
import qualified Data.Map as M
import Network.Socket (socket, Family(AF_INET), SocketType(Stream), SockAddr(..))
import Test.HUnit (Test(..), (@=?), (@?))

import TorDNSEL.ExitList
import TorDNSEL.Fixtures
import TorDNSEL.Util
import TorDNSEL.Web.Internals

tests :: Test
tests = TestList [requests, json, TestCase endpoints]

requests :: Test
requests = TestList . map TestCase $
  [ Just (Request "GET" "/api/v1/ip-port"
                  [("ip","10.0.0.11"),("port","80"),("dest","1.2.3.4")])
      @=? parseRequest "GET /api/v1/ip-port?ip=10.0.0.11&port=80&dest=1.2.3.4 \
                       \HTTP/1.1\r\nHost: example.com"
  , Just (Request "HEAD" "/a b" [("x","1 2"),("y","")])
      @=? parseRequest "HEAD /a%20b?x=1+2&y= HTTP/1.0"
  , Nothing @=? parseRequest "GET /a%2 HTTP/1.1"
  , Nothing @=? parseRequest "GET http://example.com/ HTTP/1.1"
  , Nothing @=? parseRequest "garbage"
  , Just "a+b c" @=? urlDecode False "a+b%20c"
  , Just "a b c" @=? urlDecode True "a+b%20c"
  ]

json :: Test
json = TestCase $
  "{\"a\":\"q\\\"\\\\\\u000a\",\"b\":[1,true,null]}" @=?
    renderJSON (JObject [ ("a", JString "q\"\\\n")
                        , ("b", JArray [JNumber 1, JBool True, JNull]) ])

endpoints :: IO ()
endpoints = do
  sock <- socket AF_INET Stream 0
  let conf = WebConfig sock lists Nothing (return ())
      get' path client = handleRequest conf now networkState client local
        (maybe (error "bad request") id $ parseRequest $
           B.concat ["GET ", path, " HTTP/1.1"])
      local = SockAddrInet 80 (htonl $ ip "198.51.100.80")
      client = SockAddrInet 40000 (htonl $ ip "192.0.2.1")
      body = respBody
      status = respStatus

  -- query type 1
  let r1 = get' "/api/v1/ip-port?ip=10.0.0.11&port=80&dest=1.2.3.4" client
  (200, "{\"query\":\"ip-port\",\"ip\":\"10.0.0.11\",\"dest\":\"1.2.3.4\",\
        \\"port\":80,\"listed\":true}\n") @=? (status r1, body r1)
  "\"listed\":false" `B.isInfixOf`
    body (get' "/api/v1/ip-port?ip=10.0.0.11&port=25&dest=1.2.3.4" client)
    @? "port 25 is rejected"
  400 @=? status (get' "/api/v1/ip-port?ip=10.0.0.11&dest=1.2.3.4" client)
  400 @=? status (get' "/api/v1/ip-port?ip=x&port=80&dest=1.2.3.4" client)

  -- query type 2
  "\"listed\":true" `B.isInfixOf`
    body (get' "/api/v1/list?ip=10.0.0.13&list=ExampleNet" client)
    @? "list query"
  404 @=? status (get' "/api/v1/list?ip=10.0.0.13&list=nope" client)
  "{\"examplenet\":[\"198.51.100.0/24:6667\"]}\n" @=?
    body (get' "/api/v1/lists" client)

  -- query type 3: the destination is the HTTP client
  "\"listed\":false" `B.isInfixOf`
    body (get' "/api/v1/me?ip=10.0.0.13&port=443" client)
    @? "me query, client outside 198.51.100.0/24"
  "\"listed\":true" `B.isInfixOf`
    body (get' "/api/v1/me?ip=10.0.0.13&port=443"
               (SockAddrInet 40000 (htonl $ ip "198.51.100.9")))
    @? "me query, client inside 198.51.100.0/24"

  -- check.torproject.org compatible API: is the client a Tor exit able to
  -- reach this server?
  "{\"IsTor\":true,\"IP\":\"10.0.0.99\"}\n" @=?
    body (get' "/api/ip" (SockAddrInet 1234 (htonl $ ip "10.0.0.99")))
  "{\"IsTor\":false,\"IP\":\"192.0.2.1\"}\n" @=? body (get' "/api/ip" client)
  -- 10.0.0.13 only exits to 198.51.100.0/24, which includes our address
  "{\"IsTor\":true,\"IP\":\"10.0.0.13\"}\n" @=?
    body (get' "/api/ip" (SockAddrInet 1234 (htonl $ ip "10.0.0.13")))

  -- bulk lists
  "10.0.0.11\n10.0.0.99\n" @=?
    body (get' "/torbulkexitlist?ip=192.0.2.1&port=80" client)
  "10.0.0.11\n10.0.0.13\n10.0.0.99\n" @=? body (get' "/torbulkexitlist" client)
  "10.0.0.11\n10.0.0.13\n10.0.0.99\n" @=?
    body (get' "/torbulkexitlist?ip=198.51.100.1" client)
  "ExitNode 6161616161616161616161616161616161616161\n\
  \Published 2027-01-15 07:00:00\n\
  \LastStatus 2027-01-15 08:00:00\n\
  \ExitAddress 10.0.0.99 2027-01-15 07:50:00\n" @=?
    body (get' "/exit-addresses" client)

  -- misc
  404 @=? status (get' "/nope" client)
  let post = handleRequest conf now networkState client local
               (Request "POST" "/api/ip" [])
  (405, Just "GET, HEAD") @=? (status post, lookup "Allow" (respHeaders post))
  let headR = handleRequest conf now networkState client local
                (Request "HEAD" "/api/ip" [])
  True @=? respHead headR
  "HTTP/1.1 200 OK\r\n" `B.isPrefixOf` renderResponse headR @? "status line"
  "\r\n\r\n" `B.isSuffixOf` renderResponse headR @? "HEAD has no body"
  where
    lists = M.fromList
      [("examplenet", [AddrPortPattern (ip "198.51.100.0") 0xffffff00
                                       6667 6667])]
