-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.DNS.Server.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (pattern guards, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Implements a DNS server thread that answers DNS queries for exit list
-- information, as described in @doc/torel-design.md@:
--
-- [Query type 1, \"ip-port\"]
--   @{IP1}.{port}.{IP2}.ip-port.{zone}@ is listed iff {IP1} is a Tor exit
--   that permits connections to {port} on {IP2}.
--
-- [Query type 2, \"list\"]
--   @{IP}.{listname}.list.{zone}@ is listed iff {IP} is a Tor exit that
--   permits connections to any member of the operator-configured list
--   {listname}.
--
-- [Query type 0, \"exit\"]
--   @{IP}.{zone}@ is listed iff {IP} is a Tor exit (one whose exit policy
--   permits connections somewhere). This is the form of the Tor Project's
--   own exit list service; TXT records give the relays' fingerprints.
--
-- [Query type 3, \"me\"]
--   @{IP}.{port}.me.{zone}@ is listed iff {IP} is a Tor exit that permits
--   connections to {port} on the host that sent the query. Because the answer
--   depends on who asks, it is sent with a TTL of zero so that resolvers
--   don't hand it to other clients.
--
-- Listed names have an A record of 127.0.0.2 and a TXT record explaining the
-- listing. Unlisted names are NXDOMAIN; names that are a proper prefix of a
-- valid query exist as empty non-terminals (NOERROR with no data), which keeps
-- resolvers using QNAME minimisation (RFC 9156) working.
--
-- Queries are answered over UDP and TCP (RFC 7766). Over UDP, responses can
-- be rate limited per client network ('rateLimit').
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.DNS.Server.Internals where

import Prelude hiding (log)
import qualified Control.Exception as E
import Control.Monad (when, guard, forever)
import Data.Bits ((.|.), (.&.), shiftL)
import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef')
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (toLower, toUpper, isDigit)
import qualified Data.List as L
import qualified Data.Map as M
import Data.Maybe (isJust, isNothing, maybeToList)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Word (Word32)
import Network.Socket (Socket, HostAddress, SockAddr(..), accept)
import Control.Concurrent (threadDelay)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.DNS
import TorDNSEL.Directory (encodeBase16RouterID)
import TorDNSEL.ExitList
import TorDNSEL.Log
import TorDNSEL.NetworkState
import TorDNSEL.NetworkState.Types
import TorDNSEL.Util

-- | The DNS server configuration.
data DNSConfig
  = DNSConfig
  { dnsSocket   :: !Socket         -- ^ The server's bound UDP socket.
  , dnsTCPSocket :: !Socket        -- ^ The server's listening TCP socket.
  , dnsAuthZone :: !DomainName     -- ^ The zone we're authoritative for.
  , dnsMyName   :: !DomainName     -- ^ The domain name where we're located.
  , dnsSOA      :: !ResourceRecord -- ^ Our SOA record.
  , dnsNS       :: !ResourceRecord -- ^ Our own NS record.
  -- | The A record we return for our authoritative zone.
  , dnsA        :: !(Maybe ResourceRecord)
  -- | Operator-configured lists of destinations for \"list\" queries.
  , dnsLists    :: !NamedLists
  -- | Responses per second allowed over UDP to each client network, or 0
  -- for no limit (see 'rateLimit').
  , dnsRateLimit :: !Int
  -- | Answer \"me\" queries about the client subnet a resolver gives us
  -- (RFC 7871) rather than about the resolver.
  , dnsClientSubnet :: !Bool
  -- | An action invoked with bytes received and sent for recording statistics.
  , dnsByteStats :: !(Int -> Int -> IO ())
  -- | A statistics tracking action invoked with each response.
  , dnsRespStats :: !(ResponseType -> IO ()) }

instance Eq DNSConfig where
  x == y = all (\(===) -> x === y)
    [ eq dnsSocket, eq dnsTCPSocket, eq dnsAuthZone, eq dnsMyName, eq dnsSOA
    , eq dnsNS, eq dnsA, eq dnsLists, eq dnsRateLimit, eq dnsClientSubnet ]
    where
      eq :: Eq b => (a -> b) -> a -> a -> Bool
      eq = on (==)

-- | The response type reported in statistics. 'Positive' and 'Negative' are for
-- valid DNSEL queries.
-- 'Limited' counts queries we didn't answer fully because of the rate
-- limit (truncated or dropped).
data ResponseType = Positive | Negative | Other | Limited

-- | A handle to the DNS server.
newtype DNSServer = DNSServer ThreadId

instance Thread DNSServer where
  threadId (DNSServer tid) = tid

-- | An internal type for messages sent to the DNS server thread.
data DNSMessage
  = Reconfigure (DNSConfig -> DNSConfig) (IO ()) -- ^ Reconfigure the DNS server
  | Terminate ExitReason -- ^ Terminate the DNS server gracefully

-- This is to please the Exception instance.
instance Show DNSMessage where
  showsPrec _ (Terminate a)     = ("Terminate " ++) . shows a
  showsPrec _ (Reconfigure _ _) = ("Reconfigure" ++)

instance E.Exception DNSMessage

-- | Given an initial 'DNSConfig', start the DNS server and return a handle to
-- it. Link the DNS server to the calling thread.
startDNSServer :: DNSConfig -> IO DNSServer
startDNSServer initConf = do
  log Info "Starting DNS server."
  limiter <- newIORef emptyRateLimiter
  fmap DNSServer . forkLinkIO $ E.mask $ \restore -> loop limiter restore initConf
  where
    loop :: IORef RateLimiter -> (forall a. IO a -> IO a) -> DNSConfig -> IO ()
    loop limiter restore conf = do
      -- The TCP server runs in its own thread for the current config, and is
      -- restarted whenever we're reconfigured.
      tcp <- forkIO . restore $ runTCPServer restore conf
      r <- E.tryJust fromExitSignal . restore $
             runServer (dnsSocket conf) (dnsByteStats conf)
                       (dnsUDPHandler limiter conf)
      killThread tcp
      case r of
        Left (_,Reconfigure reconf signal) -> do
          let newConf = reconf conf
          when (conf /= newConf) $
            log Notice "Reconfiguring DNS server."
          when (dnsSocket conf /= dnsSocket newConf) $
            closeSocket $ dnsSocket conf
          when (dnsTCPSocket conf /= dnsTCPSocket newConf) $
            closeSocket $ dnsTCPSocket conf
          signal
          loop limiter restore newConf
        Left (_,Terminate reason) -> do
          log Info "Terminating DNS server."
          exit reason
        Right _ -> loop limiter restore conf -- impossible

-- | Reconfigure the DNS server synchronously with the given function. If the
-- server exits abnormally before reconfiguring itself, throw its exit signal in
-- the calling thread.
reconfigureDNSServer :: (DNSConfig -> DNSConfig) -> DNSServer -> IO ()
reconfigureDNSServer reconf (DNSServer tid) =
  sendSyncMessage (throwTo tid . exitReason . Reconfigure reconf) tid

-- | Terminate the DNS server gracefully. The optional parameter specifies the
-- amount of time in microseconds to wait for the thread to terminate. If the
-- thread hasn't terminated by the timeout, an uncatchable exit signal will be
-- sent.
terminateDNSServer :: Maybe Int -> DNSServer -> IO ()
terminateDNSServer mbWait (DNSServer tid) =
  terminateThread mbWait tid (throwTo tid $ exitReason $ Terminate NormalExit)

-- | Accept connections on the TCP socket and serve each in its own thread
-- ('serveTCPConnection'): at most 'maxTCPConnections' at a time, and at most
-- 'maxTCPConnectionsPerNetwork' from one client network (as for 'rateKey'),
-- so that one client can't take them all. Connections beyond that are closed
-- right away; clients will retry. Connections are closed after
-- 'maxTCPQueriesPerConnection' queries, or when idle for 'tcpIdleTimeout', or
-- only 'tcpBusyIdleTimeout' when more than half the connections are in use
-- (RFC 7766, section 6.2.3).
runTCPServer :: (forall a. IO a -> IO a) -> DNSConfig -> IO ()
runTCPServer restore conf = do
  active <- newIORef (0 :: Int, M.empty :: M.Map RateKey Int)
  let reserve key = atomicModifyIORef' active $ \(n, perNet) ->
        let k = M.findWithDefault 0 key perNet
        in if n >= maxTCPConnections || k >= maxTCPConnectionsPerNetwork
             then ((n, perNet), False)
             else ((n + 1, M.insert key (k + 1) perNet), True)
      release key = atomicModifyIORef' active $ \(n, perNet) ->
        ((n - 1, M.update (\k -> if k <= 1 then Nothing else Just (k - 1))
                           key perNet), ())
      idle = do
        (n, _) <- readIORef active
        return $ if 2 * n > maxTCPConnections then tcpBusyIdleTimeout
                                              else tcpIdleTimeout
  forever $ do
    r <- E.try . accept $ dnsTCPSocket conf
    case r of
      -- E.g. too many open files. Don't spin.
      Left (e :: E.IOException) -> do
        log Warn "Accepting a DNS connection over TCP failed: " e
        threadDelay 1000000
      Right (sock, addr) -> do
        let key = rateKey addr
        ok <- reserve key
        if not ok
          then closeSocket sock
          else do
            let done = closeSocket sock >> release key
                serve = serveTCPConnection sock addr idle
                          maxTCPQueriesPerConnection
                          (dnsByteStats conf) (dnsHandler conf)
            _ <- forkIO (restore (ignoreErrors serve) `E.finally` done)
                   `E.onException` done
            return ()
  where
    -- A connection that fails (e.g. the client resets it) concerns no-one
    -- else.
    ignoreErrors io = io `E.catch` \(_ :: E.IOException) -> return ()

-- | How many DNS over TCP connections we serve at the same time.
maxTCPConnections :: Int
maxTCPConnections = 128

-- | How many of them may come from one client network.
maxTCPConnectionsPerNetwork :: Int
maxTCPConnectionsPerNetwork = 8

-- | How many queries we answer on one connection before closing it.
maxTCPQueriesPerConnection :: Int
maxTCPQueriesPerConnection = 100

-- | How long, in microseconds, a DNS over TCP connection may be idle.
tcpIdleTimeout :: Int
tcpIdleTimeout = 10 * 1000000

-- | ... and when more than half of the connections are in use.
tcpBusyIdleTimeout :: Int
tcpBusyIdleTimeout = 2 * 1000000

-- | 'dnsHandler' with the per-client rate limit applied, for UDP.
dnsUDPHandler
  :: IORef RateLimiter -> DNSConfig -> SockAddr -> Message -> IO (Maybe Message)
dnsUDPHandler limiter conf src msg
  | dnsRateLimit conf <= 0 || msgQR msg = dnsHandler conf src msg
  | otherwise = do
      now <- getPOSIXTime
      decision <- atomicModifyIORef' limiter $ \rl ->
        let (d, rl') = rateLimit (dnsRateLimit conf) now src rl in (rl', d)
      case decision of
        Allow -> dnsHandler conf src msg
        -- A truncated response makes a real client retry over TCP, which
        -- can't be spoofed; it's no bigger than the query.
        Slip  -> do
          dnsRespStats conf Limited
          return . Just . truncateMessage $
            msg { msgQR = True, msgAA = False, msgRA = False
                , msgAD = False, msgAdditional = [] }
        Drop  -> dnsRespStats conf Limited >> return Nothing

-- | A stateful wrapper for 'dnsResponse'.
dnsHandler :: DNSConfig -> SockAddr -> Message -> IO (Maybe Message)
{-# INLINE dnsHandler #-}
dnsHandler conf src msg
  -- draft-arends-dnsext-qr-clarification-00
  | msgQR msg = return Nothing
  | otherwise = do
      now <- getPOSIXTime
      ns <- readNetworkState
      let (typ,resp) = dnsResponse conf src msg now ns
      dnsRespStats conf typ
      return $ Just resp

-- | Given our config data, the address a query came from and the query itself,
-- parse the exit list query contained therein and generate an appropriate DNS
-- response based on our knowledge of the current state of the Tor network.
dnsResponse :: DNSConfig -> SockAddr -> Message -> POSIXTime -> NetworkState
            -> (ResponseType, Message)
{-# INLINE dnsResponse #-}
dnsResponse c src msg now ns = withEDNS $ case () of
  _ | msgOpCode msg /= StandardQuery -- RFC 3425
    -> (Other, r { msgAA = False, msgRCode = NotImplemented
                 , msgAnswers = [], msgAuthority = [dnsSOA c] })
    -- RFC 6891: we only speak EDNS version 0
    | Just e <- edns, ednsVersion e > 0
    -> (Other, r { msgAA = False, msgRCode = fst badVersRCode
                 , msgAnswers = [], msgAuthority = [] })
    -- malformed EDNS options (RFC 6891, section 7) or client subnet option
    -- (RFC 7871, section 7.1.1)
    | Just e <- edns, isNothing (ednsOptions e) || badSubnet
    -> (Other, r { msgAA = False, msgRCode = FormatError
                 , msgAnswers = [], msgAuthority = [] })
    -- draft-koch-dns-unsolicited-queries-01
    | isNothing mbQLabels
    -> (Other, r { msgAA = False, msgRCode = Refused
                 , msgAnswers = [], msgAuthority = [dnsSOA c] })
    -- Our data is all in class IN; QCLASS * asks for that too.
    | qc /= IN, qc /= AnyClass -> (Other, nxDomain soa)
    -- a request matching our authoritative zone
    | Just [] <- mbQLabels -> case qt of
        TA | Just a <- dnsA c
             -> (Other, noErr { msgAnswers = [a], msgAuthority = [dnsNS c] })
        TNS  -> (Other, noErr { msgAnswers = [dnsNS c], msgAuthority = [] })
        TSOA -> (Other, noErr { msgAnswers = [dnsSOA c]
                              , msgAuthority = [dnsNS c] })
        TAny -> (Other, noErr { msgAnswers = [dnsSOA c, dnsNS c] ++
                                maybeToList (dnsA c)
                              , msgAuthority = [dnsNS c] })
        _    -> (Other, emptyAnswer soa)
    | Just qLabels <- mbQLabels -> case parseExitListQuery (dnsLists c) qLabels of
        -- an empty non-terminal on the way to a valid query
        PartialQuery -> (Other, emptyAnswer soa)
        NoSuchName   -> (Other, nxDomain soa)
        FullQuery query
          | isListed query -> positive query
          | otherwise      -> (Negative, nxDomain (soaFor query))
    | otherwise -> (Other, nxDomain soa) -- impossible
  where
    edns = findEDNS msg
    withEDNS (typ,resp) = case edns of
      Nothing -> (typ, resp)
      Just e  -> (typ, resp { msgAdditional =
                                [ednsRecord ext (ednsDO e) subnetReply] })
        where ext | ednsVersion e > 0 = snd badVersRCode
                  | otherwise         = 0

    -- The client subnet option (RFC 7871). A "me" query is about the client
    -- the resolver asks for, so its answer depends on the subnet, which we
    -- say with a scope equal to the source prefix; other answers don't
    -- depend on it (scope 0).
    subnetData = edns >>= ednsOptions >>= lookup clientSubnetOption
    subnet = subnetData >>= parseClientSubnet
    badSubnet = isJust subnetData && isNothing subnet
    useSubnet q = dnsClientSubnet c && isMeQuery q && isJust subnet
    subnetReply = case subnet of
      Just cs | rCodeOK -> [(clientSubnetOption, renderClientSubnet cs
                               { csScopePrefix = if usedSubnet
                                                   then csSourcePrefix cs
                                                   else 0 })]
      _ -> []
    rCodeOK = not badSubnet
    usedSubnet = case mbQLabels >>= Just . parseExitListQuery (dnsLists c) of
      Just (FullQuery q) -> useSubnet q
      _                  -> False

    -- The IPv4 address the destination of a "me" query is, if any: the
    -- client subnet's address if we use it, otherwise the asker's.
    requester q
      | useSubnet q = subnet >>= clientSubnetIPv4
      | otherwise   = requesterIPv4 src

    isListed q = queryAddr q == testAddress ||
                 maybe False (isExitTo now ns (queryAddr q))
                       (queryDestination (dnsLists c) (requester q) q)

    positive q
      | qt `elem` [TA, TTXT, TAny] =
          (Positive, noErr { msgAnswers = [rr | (t,rr) <- records, wanted t]
                           , msgAuthority = [dnsNS c] })
      -- RFC 2308
      | otherwise = (Positive, emptyAnswer (soaFor q))
      where
        records = [ (TA,   A name (ttlFor q) testAddress)
                  , (TTXT, TXT name (ttlFor q) (txtFor q)) ]
        wanted t = qt == TAny || qt == t

    -- Like the Tor Project's service, "exit" queries are explained by the
    -- fingerprints of the exits (upper case hex).
    txtFor q@(IPExit a)
      | fps@(_:_) <- exitFingerprints now ns a anyDestination
      = map (B.map toUpper . encodeBase16RouterID) fps
      | otherwise = [explainListing q]
    txtFor q = [explainListing q]

    -- Answers to "me" queries depend on the asker, so they mustn't be cached,
    -- not even negatively (RFC 2308 uses the SOA's TTL and MINIMUM).
    ttlFor q | isMeQuery q = 0
             | otherwise   = ttl
    soaFor q | isMeQuery q = uncacheable soa
             | otherwise   = soa
    uncacheable (SOA n _ m rn se re rt ex _) = SOA n 0 m rn se re rt ex 0
    uncacheable rr                           = rr
    soa = dnsSOA c

    mbQLabels = dropAuthZone (dnsAuthZone c) name
    noErr = r { msgAA = True, msgRCode = NoError }
    emptyAnswer s = noErr { msgAnswers = [], msgAuthority = [s] }
    nxDomain s = r { msgAA = True, msgRCode = NXDomain, msgAnswers = []
                   , msgAuthority = [s] }
    r = msg { msgQR = True, msgTC = False, msgRA = False, msgAD = False
            , msgAdditional = [] }
    question = msgQuestion msg
    name = qName question
    (qt,qc) = (qType question, qClass question)

-- | Given @authZone@, a sequence of labels ordered from top to bottom
-- representing our authoritative zone, return @Just labels@ if @name@ is a
-- subdomain of @authZone@, where @labels@ is the lower part of @name@ ordered
-- from top to bottom. Otherwise, return Nothing.
--
-- For example:
--
-- >  dropAuthZone \"com.example.torhosts\"
-- >               \"1.0.0.10.80.4.3.2.1.ip-port.torhosts.example.com\"
--
-- would return
--
-- >  Just \"ip-port.1.2.3.4.80.10.0.0.1\"
dropAuthZone :: DomainName -> DomainName -> Maybe [Label]
{-# INLINE dropAuthZone #-}
dropAuthZone (DomainName authZone) (DomainName name) =
  dropAuthZone' authZone (reverse name)
  where
    dropAuthZone' (Label x:xs) (Label y:ys)
      | x == B.map toLower y = dropAuthZone' xs ys
    dropAuthZone' [] ys      = Just ys
    dropAuthZone' _  _       = Nothing

--------------------------------------------------------------------------------
-- Exit list queries

-- | Queries asking whether there's a Tor exit node at a specific IP address.
data ExitListQuery
  -- | Query type 1 from @doc/torel-design.md@:
  -- @{IP1}.{port}.{IP2}.ip-port.{zone}@.
  = IPPort
  { -- | The address of the candidate exit node.
    queryAddr :: !HostAddress,
    -- | The destination address.
    destAddr  :: !HostAddress,
    -- | The destination port.
    destPort  :: !Port
  }
  -- | Query type 2: @{IP}.{listname}.list.{zone}@.
  | IPList
  { queryAddr :: !HostAddress,
    -- | The name of the configured destination list.
    listName  :: !ListName
  }
  -- | Query type 3: @{IP}.{port}.me.{zone}@. The destination address is the
  -- address the query came from.
  | IPMe
  { queryAddr :: !HostAddress,
    destPort  :: !Port
  }
  -- | @{IP}.{zone}@: is the address a Tor exit at all? Compatible with the
  -- Tor Project's exit list service.
  | IPExit
  { queryAddr :: !HostAddress
  } deriving Eq

instance Show ExitListQuery where
  showsPrec _ (IPPort qAddr dAddr dPort) =
    cat "query ip: " (inet_htoa qAddr) " dest ip: " (inet_htoa dAddr)
        " dest port: " dPort
  showsPrec _ (IPList qAddr name) =
    cat "query ip: " (inet_htoa qAddr) " list: " name
  showsPrec _ (IPMe qAddr dPort) =
    cat "query ip: " (inet_htoa qAddr) " dest: requester port: " dPort
  showsPrec _ (IPExit qAddr) =
    cat "query ip: " (inet_htoa qAddr) " dest: anywhere"

-- | The result of parsing the part of a query name below our zone.
data ParsedQuery
  = FullQuery !ExitListQuery -- ^ A complete exit list query.
  | PartialQuery             -- ^ A proper prefix of a possible query.
  | NoSuchName               -- ^ Neither.
  deriving (Eq, Show)

-- | Is this a query whose answer depends on who is asking?
isMeQuery :: ExitListQuery -> Bool
isMeQuery IPMe{} = True
isMeQuery _      = False

-- | The address used to test DNSBL configurations (RFC 5782, section 5).
-- It is always listed.
testAddress :: HostAddress
testAddress = 0x7f000002

-- | The destination a query asks about, given the configured lists and the
-- IPv4 address of the host a \"me\" query is about. 'Nothing' means no Tor
-- exit node can reach the destination: an unknown list, or a \"me\" query
-- about an IPv6 host (we only have exit policies for IPv4).
queryDestination
  :: NamedLists -> Maybe HostAddress -> ExitListQuery -> Maybe Destination
queryDestination _ _ (IPPort _ dAddr dPort) = Just $ DestAddrPort dAddr dPort
queryDestination lists _ (IPList _ name)  = DestAnyOf `fmap` M.lookup name lists
queryDestination _ _ (IPExit _)           = Just anyDestination
queryDestination _ me (IPMe _ dPort)      = (`DestAddrPort` dPort) `fmap` me

-- | The IPv4 address of the host a query came from, if it has one.
requesterIPv4 :: SockAddr -> Maybe HostAddress
requesterIPv4 (SockAddrInet _ addr)                     = Just (ntohl addr)
requesterIPv4 (SockAddrInet6 _ _ (0, 0, 0xffff, addr) _) = Just addr
requesterIPv4 _                                         = Nothing

-- | A short human-readable explanation of a positive answer, returned in TXT
-- records (RFC 5782, section 2.1).
explainListing :: ExitListQuery -> ByteString
explainListing q = B.pack $ case q of
  IPPort a d p -> inet_htoa a ++ " is a Tor exit node permitting connections \
                                  \to " ++ inet_htoa d ++ ":" ++ show p
  IPList a n   -> inet_htoa a ++ " is a Tor exit node permitting connections \
                                  \to list " ++ B.unpack n
  IPMe a p     -> inet_htoa a ++ " is a Tor exit node permitting connections \
                                  \to port " ++ show p ++ " of the querying host"
  IPExit a     -> inet_htoa a ++ " is a Tor exit node"

-- | Parse an exit list query from a sequence of labels ordered from top to
-- bottom representing the query portion of a domain name, e.g.
-- @\"ip-port.{IP2}.{port}.{IP1}\"@. Prefixes of valid queries are recognised
-- so that they can be answered as empty non-terminals.
parseExitListQuery :: NamedLists -> [Label] -> ParsedQuery
parseExitListQuery lists labels = case map (B.map toLower . unLabel) labels of
  []           -> PartialQuery
  typ : rest
    | typ == B.pack "ip-port" -> parseWith [octet, octet, octet, octet, port,
                                            octet, octet, octet, octet]
                                           ipPort rest
    | typ == B.pack "list", not (M.null lists)
                              -> parseWith [listLabel, octet, octet, octet,
                                            octet]
                                           ipList rest
    | typ == B.pack "me"      -> parseWith [port, octet, octet, octet, octet]
                                           ipMe rest
    -- {IP}.{zone}: the labels from the top are the address in the usual order
    | octet typ               -> parseWith [octet, octet, octet, octet]
                                           ipExit (typ : rest)
  _            -> NoSuchName
  where
    parseWith fields mk xs
      | length xs > length fields          = NoSuchName
      | not . and $ zipWith ($) fields xs  = NoSuchName
      | length xs < length fields          = PartialQuery
      | otherwise = maybe NoSuchName FullQuery (mk xs)

    ipPort [a,b,c,d,p,e,f,g,h] =
      IPPort `fmap` toAddress [e,f,g,h] `ap'` toAddress [a,b,c,d] `ap'` toPort p
    ipPort _ = Nothing
    ipList [n,a,b,c,d] = (`IPList` n) `fmap` toAddress [a,b,c,d]
    ipList _ = Nothing
    ipMe [p,a,b,c,d] = IPMe `fmap` toAddress [a,b,c,d] `ap'` toPort p
    ipMe _ = Nothing
    ipExit [a,b,c,d] = IPExit `fmap` toAddress [a,b,c,d]
    ipExit _ = Nothing

    ap' mf mx = do { f <- mf; x <- mx; return (f x) }

    octet bs = isDecimal 3 bs && maybe False (<= 255) (readDecimal bs)
    port bs  = isDecimal 5 bs && maybe False (<= 65535) (readDecimal bs)
    listLabel n = n `M.member` lists

    isDecimal maxLen bs = not (B.null bs) && B.length bs <= maxLen &&
                          B.all isDigit bs
    readDecimal bs = case B.readInt bs of
      Just (n,rest) | B.null rest -> Just n
      _                           -> Nothing

    toPort bs = fromIntegral `fmap` (guard (port bs) >> readDecimal bs)
    toAddress xs = do
      os <- mapM readDecimal xs
      guard $ all (<= 255) os
      return $! L.foldl' (.|.) 0 . zipWith shiftL (map fromIntegral os) $
                [24,16..]

-- | The time-to-live set for caching.
ttl :: Word32
ttl = 30 * 60

--------------------------------------------------------------------------------
-- Rate limiting

-- | What to do with a query from a client that may be over its rate limit.
data RateDecision
  = Allow -- ^ Answer it.
  | Slip  -- ^ Send a truncated response, so that a real client retries
          --   over TCP.
  | Drop  -- ^ Don't answer.
  deriving (Eq, Show)

-- | The clients we've seen recently: a token bucket per client network.
data RateLimiter = RateLimiter
  { rlBuckets   :: !(M.Map RateKey Bucket)
  , rlLastPurge :: !POSIXTime
    -- | Queries refused because we track too many networks already.
  , rlOverflow  :: !Int }

-- | A client network: an IPv4 /24 or an IPv6 /56. Rate limiting by network
-- rather than by address stops an attacker from spreading spoofed queries
-- over neighbouring addresses, as other response rate limiting schemes do.
data RateKey = Net4 !Word32 | Net6 !Word32 !Word32
  deriving (Eq, Ord, Show)

-- | Tokens left, when they were last counted, and how many queries have been
-- refused since then.
data Bucket = Bucket !Double !POSIXTime !Int
  deriving Show

-- | No clients seen.
emptyRateLimiter :: RateLimiter
emptyRateLimiter = RateLimiter M.empty 0 0

-- | The most client networks we keep track of. Queries spoofed from random
-- networks could otherwise make the state grow with the query rate. While we
-- track this many, queries from other networks are treated as over their
-- limit (so every second one still gets a truncated response).
maxRateBuckets :: Int
maxRateBuckets = 100000

-- | Given the number of responses per second allowed to each client network,
-- the current time and a query's source, decide what to do with the query.
--
-- Each network may send bursts of up to @rate@ queries and @rate@ queries per
-- second on average. Of the queries over the limit, every second one is
-- answered with a truncated response ('Slip') and the rest are dropped: a
-- spoofed flood is then reflected at a fraction of its own size, while real
-- clients still get through over TCP (cf. BIND's RRL "slip 2").
rateLimit :: Int -> POSIXTime -> SockAddr -> RateLimiter -> (RateDecision, RateLimiter)
rateLimit = rateLimitWith maxRateBuckets

-- | 'rateLimit' tracking at most the given number of networks.
rateLimitWith :: Int -> Int -> POSIXTime -> SockAddr -> RateLimiter
              -> (RateDecision, RateLimiter)
rateLimitWith maxBuckets rate now src (RateLimiter buckets lastPurge overflow)
  | not (key `M.member` buckets'), M.size buckets' >= maxBuckets =
      ( if even overflow then Slip else Drop
      , RateLimiter buckets' lastPurge' (overflow + 1) )
  | otherwise =
      (decision, RateLimiter (M.insert key bucket' buckets') lastPurge' overflow)
  where
    rate' = fromIntegral rate :: Double
    key = rateKey src
    Bucket tokens _ refused = refill now $
      M.findWithDefault (Bucket rate' now 0) key buckets
    (decision, bucket')
      | tokens >= 1  = (Allow, Bucket (tokens - 1) now refused)
      | even refused = (Slip,  Bucket tokens now (refused + 1))
      | otherwise    = (Drop,  Bucket tokens now (refused + 1))
    refill t (Bucket k t0 n) =
      Bucket (min rate' (k + rate' * realToFrac (t - t0))) t n
    -- Forget networks whose buckets are full again, at most once a second.
    (buckets', lastPurge')
      | now - lastPurge >= 1 =
          (M.filter (\b -> not (full (refill now b))) buckets, now)
      | otherwise = (buckets, lastPurge)
    full (Bucket k _ _) = k >= rate'

-- | The client network an address belongs to.
rateKey :: SockAddr -> RateKey
rateKey (SockAddrInet _ addr)            = Net4 (ntohl addr .&. 0xffffff00)
rateKey (SockAddrInet6 _ _ (a, b, _, _) _) = Net6 a (b .&. 0xffffff00)
rateKey _                                = Net4 0
