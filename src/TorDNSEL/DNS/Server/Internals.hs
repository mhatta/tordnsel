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
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.DNS.Server.Internals where

import Prelude hiding (log)
import qualified Control.Exception as E
import Control.Monad (when, guard)
import Data.Bits ((.|.), shiftL)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Dynamic (Typeable)
import Data.Char (toLower, isDigit)
import qualified Data.List as L
import qualified Data.Map as M
import Data.Maybe (isNothing, maybeToList)
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.Word (Word32)
import Network.Socket (Socket, HostAddress, SockAddr(..))

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.DNS
import TorDNSEL.ExitList
import TorDNSEL.Log
import TorDNSEL.NetworkState
import TorDNSEL.NetworkState.Types
import TorDNSEL.Util

-- | The DNS server configuration.
data DNSConfig
  = DNSConfig
  { dnsSocket   :: !Socket         -- ^ The server's bound UDP socket.
  , dnsAuthZone :: !DomainName     -- ^ The zone we're authoritative for.
  , dnsMyName   :: !DomainName     -- ^ The domain name where we're located.
  , dnsSOA      :: !ResourceRecord -- ^ Our SOA record.
  , dnsNS       :: !ResourceRecord -- ^ Our own NS record.
  -- | The A record we return for our authoritative zone.
  , dnsA        :: !(Maybe ResourceRecord)
  -- | Operator-configured lists of destinations for \"list\" queries.
  , dnsLists    :: !NamedLists
  -- | An action invoked with bytes received and sent for recording statistics.
  , dnsByteStats :: !(Int -> Int -> IO ())
  -- | A statistics tracking action invoked with each response.
  , dnsRespStats :: !(ResponseType -> IO ()) }

instance Eq DNSConfig where
  x == y = all (\(===) -> x === y)
    [ eq dnsSocket, eq dnsAuthZone, eq dnsMyName, eq dnsSOA, eq dnsNS, eq dnsA
    , eq dnsLists ]
    where
      eq :: Eq b => (a -> b) -> a -> a -> Bool
      eq = on (==)

-- | The response type reported in statistics. 'Positive' and 'Negative' are for
-- valid DNSEL queries.
data ResponseType = Positive | Negative | Other

-- | A handle to the DNS server.
newtype DNSServer = DNSServer ThreadId

instance Thread DNSServer where
  threadId (DNSServer tid) = tid

-- | An internal type for messages sent to the DNS server thread.
data DNSMessage
  = Reconfigure (DNSConfig -> DNSConfig) (IO ()) -- ^ Reconfigure the DNS server
  | Terminate ExitReason -- ^ Terminate the DNS server gracefully
  deriving Typeable

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
  fmap DNSServer . forkLinkIO $ E.mask $ \restore -> loop restore initConf
  where
    loop :: (forall a. IO a -> IO a) -> DNSConfig -> IO ()
    loop restore conf = do
      r <- E.tryJust fromExitSignal . restore $
             runServer (dnsSocket conf) (dnsByteStats conf) (dnsHandler conf)
      case r of
        Left (_,Reconfigure reconf signal) -> do
          let newConf = reconf conf
          when (conf /= newConf) $
            log Notice "Reconfiguring DNS server."
          when (dnsSocket conf /= dnsSocket newConf) $
            closeSocket $ dnsSocket conf
          signal
          loop restore newConf
        Left (_,Terminate reason) -> do
          log Info "Terminating DNS server."
          exit reason
        Right _ -> loop restore conf -- impossible

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
    -- draft-koch-dns-unsolicited-queries-01
    | isNothing mbQLabels
    -> (Other, r { msgAA = False, msgRCode = Refused
                 , msgAnswers = [], msgAuthority = [dnsSOA c] })
    | qc /= IN -> (Other, nxDomain soa)
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
      Just e  -> (typ, resp { msgAdditional = [ednsRecord ext (ednsDO e)] })
        where ext | ednsVersion e > 0 = snd badVersRCode
                  | otherwise         = 0

    isListed q = queryAddr q == testAddress ||
                 maybe False (isExitTo now ns (queryAddr q))
                       (queryDestination (dnsLists c) src q)

    positive q
      | qt `elem` [TA, TTXT, TAny] =
          (Positive, noErr { msgAnswers = [rr | (t,rr) <- records, wanted t]
                           , msgAuthority = [dnsNS c] })
      -- RFC 2308
      | otherwise = (Positive, emptyAnswer (soaFor q))
      where
        records = [ (TA,   A name (ttlFor q) testAddress)
                  , (TTXT, TXT name (ttlFor q) [explainListing q]) ]
        wanted t = qt == TAny || qt == t

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
  } deriving Eq

instance Show ExitListQuery where
  showsPrec _ (IPPort qAddr dAddr dPort) =
    cat "query ip: " (inet_htoa qAddr) " dest ip: " (inet_htoa dAddr)
        " dest port: " dPort
  showsPrec _ (IPList qAddr name) =
    cat "query ip: " (inet_htoa qAddr) " list: " name
  showsPrec _ (IPMe qAddr dPort) =
    cat "query ip: " (inet_htoa qAddr) " dest: requester port: " dPort

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
-- address the query came from. 'Nothing' means no Tor exit node can reach
-- the destination: an unknown list, or a \"me\" query from an IPv6 host
-- (we only have exit policies for IPv4).
queryDestination :: NamedLists -> SockAddr -> ExitListQuery -> Maybe Destination
queryDestination _ _ (IPPort _ dAddr dPort) = Just $ DestAddrPort dAddr dPort
queryDestination lists _ (IPList _ name)  = DestAnyOf `fmap` M.lookup name lists
queryDestination _ src (IPMe _ dPort)     = case src of
  SockAddrInet _ addr -> Just $ DestAddrPort (ntohl addr) dPort
  SockAddrInet6 _ _ (0, 0, 0xffff, addr) _ -> Just $ DestAddrPort addr dPort
  _ -> Nothing

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
