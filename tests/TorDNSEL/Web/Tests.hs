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

import Control.Concurrent (threadDelay)
import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import qualified Data.Map as M
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.Socket
  ( socket, Family(AF_INET), SocketType(Stream), SockAddr(..), bind, listen
  , connect, getSocketName, close )
import qualified Network.Socket.ByteString as NSB
import System.Timeout (timeout)
import Test.HUnit (Test(..), (@=?), (@?), (@?=))


import TorDNSEL.AddressPattern
import TorDNSEL.ExitList
import TorDNSEL.Fixtures
import TorDNSEL.Util
import TorDNSEL.Statistics.Internals (Stats(..), renderMetrics)
import TorDNSEL.Web.Internals

tests :: Test
tests = TestList [ requests, json, TestCase endpoints, TestCase limits
                 , TestCase terminateAfterRequest ]

-- | One client can't take all the handlers, and must send its request
-- promptly.
limits :: IO ()
limits = do
  listener <- socket AF_INET Stream 0
  bind listener (SockAddrInet 0 (htonl $ ip "127.0.0.1"))
  listen listener 32
  addr <- getSocketName listener
  web <- startWebServer
           (WebConfig listener M.empty Nothing (return ()) [] [] (return ""))
  let open1 = do
        c <- socket AF_INET Stream 0
        connect c addr
        return c
      -- closed (or answered with an error before being closed) in time
      closedWithin us c = do
        r <- E.try (timeout us (NSB.recv c 1))
        return $ case r of
          Right (Just _)  -> True
          Right Nothing   -> False
          Left (_ :: E.IOException) -> True
  silent <- mapM (const open1) [1 .. 8 :: Int]
  threadDelay 100000
  -- the ninth connection from this address is closed at once
  ninth <- open1
  closedWithin 1000000 ninth >>= (@? "ninth connection kept open")
  -- the silent ones are closed after the 3 s request timeout
  t0 <- getPOSIXTime
  closed <- mapM (closedWithin 5000000) silent
  t1 <- getPOSIXTime
  and closed @? "silent connections kept open"
  (t1 - t0 < 4) @? "silent connections closed too late"
  -- and then requests are served again
  c <- open1
  NSB.sendAll c "GET /api/v1/lists HTTP/1.0\r\n\r\n"
  r <- timeout 2000000 (NSB.recv c 100)
  fmap (B.isPrefixOf "HTTP/1.1 200") r @=? Just True
  mapM_ close (c : ninth : silent)
  terminateWebServer Nothing web

-- | The server terminates even when told to while a handler is finishing:
-- the handler's exit signal may arrive after the request to terminate.
terminateAfterRequest :: IO ()
terminateAfterRequest = mapM_ (const once) [1 .. 50 :: Int]
  where
    once = do
      listener <- socket AF_INET Stream 0
      bind listener (SockAddrInet 0 (htonl $ ip "127.0.0.1"))
      listen listener 8
      addr <- getSocketName listener
      web <- startWebServer
               (WebConfig listener M.empty Nothing (return ()) [] [] (return ""))
      c <- socket AF_INET Stream 0
      connect c addr
      NSB.sendAll c "GET /api/v1/lists HTTP/1.0\r\n\r\n"
      _ <- timeout 2000000 (NSB.recv c 100)
      close c
      done <- timeout 5000000 (terminateWebServer Nothing web)
      close listener
      done @?= Just ()

requests :: Test
requests = TestList . map TestCase $
  [ Just (Request "GET" "/api/v1/ip-port"
                  [("ip","10.0.0.11"),("port","80"),("dest","1.2.3.4")]
                  [("host","example.com")])
      @=? parseRequest "GET /api/v1/ip-port?ip=10.0.0.11&port=80&dest=1.2.3.4 \
                       \HTTP/1.1\r\nHost: example.com"
  , Just (Request "HEAD" "/a b" [("x","1 2"),("y","")] [])
      @=? parseRequest "HEAD /a%20b?x=1+2&y= HTTP/1.0"
  -- header names are lower-cased and values trimmed; lines without a colon
  -- are ignored
  , Just [("x-forwarded-for","192.0.2.7, 10.0.0.1"),("a","b:c")]
      @=? fmap reqHeaders (parseRequest "GET / HTTP/1.1\r\n\
            \X-Forwarded-For:  192.0.2.7, 10.0.0.1 \r\nbogus\r\nA: b:c")
  , Nothing @=? parseRequest "GET /a%2 HTTP/1.1"
  , Nothing @=? parseRequest "GET http://example.com/ HTTP/1.1"
  , Nothing @=? parseRequest "garbage"
  -- address patterns, as for HTTPTrustedProxy
  , Just [ Net4 (ip "127.0.0.1") 0xffffffff, Net4 (ip "10.1.0.0") 0xffff0000
         , Addr6 (0, 0, 0, 1) ]
      @=? hush (parseAddressPatterns "127.0.0.1, 10.1.2.3/16 ::1")
  , Nothing @=? hush (parseAddressPatterns "10.0.0.0/33")
  , Nothing @=? hush (parseAddressPatterns "example.com")
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
  let conf = WebConfig sock lists Nothing (return ()) [] []
                       (return "tordnsel_up 1\n")
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

  -- "exit": is the address an exit at all, and which relays exit from it
  (200, "{\"query\":\"exit\",\"ip\":\"10.0.0.99\",\"listed\":true,\
        \\"fingerprints\":[\"6161616161616161616161616161616161616161\"]}\n")
    @=? (\r -> (status r, body r)) (get' "/api/v1/exit?ip=10.0.0.99" client)
  "\"listed\":false" `B.isInfixOf` body (get' "/api/v1/exit?ip=10.0.0.12" client)
    @? "exit query, router not running"
  400 @=? status (get' "/api/v1/exit?ip=10.0.0" client)

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
               (Request "POST" "/api/ip" [] [])
  (405, Just "GET, HEAD") @=? (status post, lookup "Allow" (respHeaders post))
  let headR = handleRequest conf now networkState client local
                (Request "HEAD" "/api/ip" [] [])
  True @=? respHead headR
  "HTTP/1.1 200 OK\r\n" `B.isPrefixOf` renderResponse headR @? "status line"
  "\r\n\r\n" `B.isSuffixOf` renderResponse headR @? "HEAD has no body"

  -- X-Forwarded-For is believed only from trusted proxies, read from the
  -- right, skipping trusted proxies
  let proxied = conf { webTrustedProxies =
                         [Net4 (ip "10.1.0.0") 0xffff0000, Net4 (ip "127.0.0.1") 0xffffffff] }
      viaProxy xff peer = respBody $ handleRequest proxied now networkState peer
        local (Request "GET" "/api/ip" [] [("x-forwarded-for", xff)])
      proxy = SockAddrInet 40000 (htonl $ ip "127.0.0.1")
      -- the value of "IP" in {"IsTor":...,"IP":"..."}
      ipOf' b = B.takeWhile (/= '"') . B.drop 6 . snd $
                  B.breakSubstring "\"IP\":\"" b
  "10.0.0.99" @=? ipOf' (viaProxy "1.1.1.1, 10.0.0.99, 10.1.2.3" proxy)
  "\"IsTor\":true" `B.isInfixOf` viaProxy "10.0.0.99" proxy
    @? "a Tor exit behind the proxy"
  -- from a client that isn't a trusted proxy, the header is ignored
  "192.0.2.1" @=? ipOf' (viaProxy "10.0.0.99" client)
  -- all trusted: the leftmost; malformed: the proxy itself
  "10.1.9.9" @=? ipOf' (viaProxy "10.1.9.9, 10.1.2.3" proxy)
  "127.0.0.1" @=? ipOf' (viaProxy "10.0.0.99, junk" proxy)
  "2001:db8::1" @=? ipOf' (viaProxy "[2001:db8::1]" proxy)

  -- /metrics: only for the configured clients; for others it doesn't exist
  let metricsReq = Request "GET" "/metrics" [] []
      allowed = conf { webMetricsAllowFrom = [Net4 (ip "192.0.2.0") 0xffffff00] }
  m1 <- metricsResponse conf client metricsReq
  404 @=? status m1
  m2 <- metricsResponse allowed client metricsReq
  (200, "tordnsel_up 1\n") @=? (status m2, body m2)
  m3 <- metricsResponse allowed (SockAddrInet 40000 (htonl $ ip "198.51.100.9"))
                        metricsReq
  404 @=? status m3
  -- rendered from the statistics and the network state
  let text = renderMetrics "9.9" (Stats 10 20 3 4 5 6 7 8) 1700000000 now
                           networkState
      has l = (l `elem` B.lines text) @? ("missing: " ++ B.unpack l)
  mapM_ has
    [ "tordnsel_build_info{version=\"9.9\"} 1"
    , "tordnsel_start_time_seconds 1700000000"
    , "tordnsel_dns_received_bytes_total 10"
    , "tordnsel_dns_responses_total{result=\"positive\"} 4"
    , "tordnsel_dns_responses_total{result=\"rate_limited\"} 8"
    , "tordnsel_http_requests_total 7"
    -- ridB's descriptor is three days old
    , "tordnsel_relays{state=\"known\"} 3"
    , "tordnsel_relays{state=\"running\"} 2"
    , "tordnsel_running_exits 2"
    -- 10.0.0.11 and 10.0.0.99 (tested) for ridA, 10.0.0.13 for ridC
    , "tordnsel_exit_addresses 3"
    , "tordnsel_tested_exit_addresses 1"
    , "# TYPE tordnsel_dns_responses_total counter" ]
  where
    lists = M.fromList
      [("examplenet", [AddrPortPattern (ip "198.51.100.0") 0xffffff00
                                       6667 6667])]
