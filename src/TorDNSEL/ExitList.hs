-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.ExitList
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : Masayuki Hatta <mhatta@mhatta.org>
-- Stability   : alpha
-- Portability : portable
--
-- Answering exit list questions against our current view of the Tor network.
-- This is shared by the DNS interface and the web interface, which by design
-- provide the same data (see @doc/torel-design.md@).
--
-- The basic question is always the same: /is there a running Tor exit node
-- whose traffic leaves the Tor network from address A, and whose exit policy
-- permits connections to some destination D?/ The destination is
--
--   * a single address and port (query type 1, \"ip-port\"),
--
--   * any member of a named, operator-configured list of address\/port
--     patterns (query type 2, \"list\"), or
--
--   * a port on the host asking the question (query type 3, \"me\").
--
-----------------------------------------------------------------------------

module TorDNSEL.ExitList (
  -- * Destinations
    Destination(..)
  , AddrPortPattern(..)
  , parseAddrPortPattern
  , showAddrPortPattern
  , policyAcceptsDestination
  , policyAcceptsSome
  , descriptorAcceptsDestination

  -- * Named lists
  , ListName
  , NamedLists
  , parseNamedList
  , maxListPrefix

  -- * Queries
  , isExitTo
  , exitAddressesTo
  , routersExitingFrom
  , exitFingerprints
  , isRunning
  , maxRouterAge
  , anyDestination
  ) where

import Control.Monad (when, unless)
import Control.Monad.Except (MonadError(throwError))
import Data.Bits ((.&.), shiftL, popCount)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (isAlphaNum, toLower)
import qualified Data.Map as M
import Data.Map (Map)
import Data.Maybe (mapMaybe)
import qualified Data.Set as S
import Data.Time.Clock.POSIX (POSIXTime)
import Data.Word (Word32)
import Network.Socket (HostAddress)

import TorDNSEL.Directory
import TorDNSEL.Directory.Internals
  ( Rect, netRect, wholeRect, exitPolicyAcceptsSome )
import TorDNSEL.NetworkState.Types
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Destinations

-- | Where a connection leaving the Tor network is headed.
data Destination
  = DestAddrPort !HostAddress !Port -- ^ A single IPv4 address and port.
  | DestAnyOf ![AddrPortPattern]    -- ^ Any member of a set of patterns.
  | DestAny                         -- ^ Any address and port at all.
  deriving (Eq, Show)

-- | An IPv4 network and an inclusive port range, e.g. @192.0.2.0/24:6660-6669@.
data AddrPortPattern = AddrPortPattern
  { patAddress   :: !HostAddress -- ^ Network address (already masked).
  , patMask      :: !HostAddress -- ^ Network mask.
  , patBeginPort :: !Port        -- ^ First port of the range.
  , patEndPort   :: !Port        -- ^ Last port of the range.
  } deriving (Eq, Ord, Show)

-- | The widest network prefix accepted in a named list. The design document
-- warns that address masks wider than \/8 are worrying, so we refuse them.
maxListPrefix :: Int
maxListPrefix = 8

-- | Parse an address\/port pattern of the form
-- @ADDRESS[\/BITS]:PORT[-PORT][,PORT[-PORT]...]@, returning one pattern per
-- port range. 'throwError' in the monad if the pattern is malformed.
parseAddrPortPattern :: MonadError ShowS m => ByteString -> m [AddrPortPattern]
parseAddrPortPattern bs
  | (addrSpec',portSpecs) <- B.spanEnd (/= ':') bs
  , Just (addrSpec,':') <- unsnoc addrSpec'
  , not (B.null portSpecs) =
      prependError (cat "Malformed address/port pattern " (esc 64 bs) ": ") $ do
        (addr,mask) <- parseNet addrSpec
        ranges <- mapM parseRange $ B.split ',' portSpecs
        return [AddrPortPattern addr mask b e | (b,e) <- ranges]
  | otherwise = throwError $ cat "Malformed address/port pattern "
                                 (esc 64 bs) '.'
  where
    parseNet spec = case B.split '/' spec of
      [addr] -> do
        a <- inet_atoh addr
        return (a, 0xffffffff)
      [addr,bits] -> do
        a <- inet_atoh addr
        n <- readInt bits
        when (n < maxListPrefix || n > 32) $
          throwError $ cat "Prefix length " n " is out of range (must be \
                           \between " maxListPrefix " and 32)."
        let mask = 0xffffffff `shiftL` (32 - n) :: Word32
        return (a .&. mask, mask)
      _ -> throwError ("Malformed network." ++)
    parseRange spec = case B.split '-' spec of
      [p] -> do
        port <- parsePort p
        return (port, port)
      [b,e] -> do
        b' <- parsePort b
        e' <- parsePort e
        unless (b' <= e') $ throwError ("Begin port is greater than end port." ++)
        return (b', e')
      _ -> throwError ("Malformed port range." ++)

-- | Render a pattern in the syntax accepted by 'parseAddrPortPattern'.
showAddrPortPattern :: AddrPortPattern -> String
showAddrPortPattern p =
  inet_htoa (patAddress p) ++ bits ++ ":" ++ ports
  where
    bits | patMask p == 0xffffffff = ""
         | otherwise = '/' : show (popCount $ patMask p)
    ports | patBeginPort p == patEndPort p = show (patBeginPort p)
          | otherwise = show (patBeginPort p) ++ "-" ++ show (patEndPort p)

-- | Does an exit policy accept a connection to the destination?
policyAcceptsDestination :: Destination -> ExitPolicy -> Bool
{-# INLINE policyAcceptsDestination #-}
policyAcceptsDestination (DestAddrPort a p) = exitPolicyAccepts a p
policyAcceptsDestination (DestAnyOf pats)   = policyAcceptsSome pats
policyAcceptsDestination DestAny            = exitPolicyAcceptsSome [wholeRect]

-- | Does an exit policy accept a connection to at least one address\/port
-- covered by the given patterns? (See 'exitPolicyAcceptsSome'.)
policyAcceptsSome :: [AddrPortPattern] -> ExitPolicy -> Bool
policyAcceptsSome pats = exitPolicyAcceptsSome (map patternRect pats)

patternRect :: AddrPortPattern -> Rect
patternRect p = netRect (patAddress p) (patMask p)
                        (fromIntegral $ patBeginPort p)
                        (fromIntegral $ patEndPort p)

-- | Does a router's descriptor say it accepts connections to the
-- destination? As 'policyAcceptsDestination', but answering for any
-- destination from what the descriptor keeps ('descExitsAnywhere').
descriptorAcceptsDestination :: Destination -> Descriptor -> Bool
{-# INLINE descriptorAcceptsDestination #-}
descriptorAcceptsDestination DestAny d = descExitsAnywhere d
descriptorAcceptsDestination dest    d = policyAcceptsDestination dest
                                           (descExitPolicy d)

-- | A destination matching every IPv4 address and port.
anyDestination :: Destination
anyDestination = DestAny

--------------------------------------------------------------------------------
-- Named lists

-- | The name of an operator-configured list, in lower case.
type ListName = ByteString

-- | Operator-configured lists of address\/port patterns, by name.
type NamedLists = Map ListName [AddrPortPattern]

-- | Parse the value of an @ExitList@ config line:
-- @NAME PATTERN [PATTERN ...]@. List names are case-insensitive DNS labels.
parseNamedList :: MonadError ShowS m => ByteString
               -> m (ListName, [AddrPortPattern])
parseNamedList line = case B.words line of
  name:pats@(_:_) -> do
    unless (validName name) $
      throwError $ cat "Invalid exit list name " (esc 64 name) "; list names \
                       \must be DNS labels made of letters, digits and '-'."
    pats' <- concat `fmap` mapM parseAddrPortPattern pats
    return (B.map toLower name, pats')
  _ -> throwError $ cat "Malformed exit list " (esc 128 line)
                        "; expected a name followed by address/port patterns."
  where
    validName n = not (B.null n) && B.length n <= 63 &&
                  B.all (\c -> isAlphaNum c || c == '-') n &&
                  B.head n /= '-' && B.last n /= '-'

--------------------------------------------------------------------------------
-- Queries

-- | We consider a router to be running if it published a descriptor less than
-- 48 hours ago: \"After a Tor server op turns off their server, it stops
-- publishing server descriptors. We should consider that server's IP address
-- to still represent a Tor node until 48 hours after its last descriptor was
-- published.\"
maxRouterAge :: POSIXTime
maxRouterAge = 60 * 60 * 48

-- | Is the router whose descriptor this is still considered running?
isRunning :: POSIXTime -> Descriptor -> Bool
{-# INLINE isRunning #-}
isRunning now d = now - descPublished d < maxRouterAge

-- | The descriptors of routers whose traffic may leave the Tor network from
-- the given address: either the address they advertise, or an address we saw
-- in an exit test through them.
routersExitingFrom :: NetworkState -> HostAddress -> [Descriptor]
routersExitingFrom s addr =
  maybe [] (mapMaybe lookupDesc . S.elems) (addr `M.lookup` nsAddrs s)
  where lookupDesc rid = rtrDescriptor =<< rid `M.lookup` nsRouters s

-- | Is there a running Tor exit node exiting from the given address whose exit
-- policy permits connections to the destination?
isExitTo :: POSIXTime -> NetworkState -> HostAddress -> Destination -> Bool
{-# INLINE isExitTo #-}
isExitTo now s addr dest = any ok (routersExitingFrom s addr)
  where ok d = isRunning now d && descriptorAcceptsDestination dest d

-- | The identities of the running Tor exit nodes exiting from the given
-- address whose exit policy permits connections to the destination.
exitFingerprints
  :: POSIXTime -> NetworkState -> HostAddress -> Destination -> [RouterID]
exitFingerprints now s addr dest =
  [ descRouterID d | d <- routersExitingFrom s addr, isRunning now d
                   , descriptorAcceptsDestination dest d ]

-- | All addresses from which running Tor exit nodes whose exit policy permits
-- connections to the destination may exit, in ascending order.
exitAddressesTo :: POSIXTime -> NetworkState -> Destination -> [HostAddress]
exitAddressesTo now s dest =
  [addr | (addr,rids) <- M.toAscList (nsAddrs s), any ok (S.elems rids)]
  where
    ok rid = case rtrDescriptor =<< rid `M.lookup` nsRouters s of
      Just d -> isRunning now d && descriptorAcceptsDestination dest d
      Nothing -> False
