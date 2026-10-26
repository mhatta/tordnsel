-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.AddressPattern
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : Masayuki Hatta <mhatta@mhatta.org>
-- Stability   : alpha
-- Portability : portable
--
-- Sets of client addresses given in the configuration, such as the reverse
-- proxies whose X-Forwarded-For headers we trust or the hosts allowed to
-- fetch metrics: IPv4 addresses or networks (@192.0.2.0\/24@) and IPv6
-- addresses (@::1@).
--
-----------------------------------------------------------------------------

module TorDNSEL.AddressPattern (
    AddressPattern(..)
  , parseAddressPatterns
  , matchesAny
  , hostAddressOf
  , HostAddressAny(..)
  ) where

import Control.Monad.Except (MonadError(throwError))
import Data.Bits ((.&.), complement, shiftL)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (isSpace)
import Network.Socket (HostAddress, HostAddress6, SockAddr(..))

import TorDNSEL.Util

-- | An IPv4 network (address and mask, the address already masked) or a
-- single IPv6 address.
data AddressPattern
  = Net4 !HostAddress !HostAddress
  | Addr6 !HostAddress6
  deriving (Eq, Show)

-- | The host part of a socket address, with IPv4-mapped IPv6 addresses
-- (as on a dual-stack socket) turned back into IPv4 ones.
data HostAddressAny = Host4 !HostAddress | Host6 !HostAddress6
  deriving (Eq, Ord, Show)

hostAddressOf :: SockAddr -> Maybe HostAddressAny
hostAddressOf (SockAddrInet _ a)                      = Just (Host4 (ntohl a))
hostAddressOf (SockAddrInet6 _ _ (0, 0, 0xffff, a) _) = Just (Host4 a)
hostAddressOf (SockAddrInet6 _ _ a _)                 = Just (Host6 a)
hostAddressOf _                                       = Nothing

-- | Does an address match one of the patterns?
matchesAny :: [AddressPattern] -> HostAddressAny -> Bool
matchesAny pats host = any match pats
  where
    match (Net4 net mask) | Host4 a <- host = a .&. mask == net
    match (Addr6 a6)      | Host6 a <- host = a == a6
    match _ = False

-- | Parse addresses and networks separated by spaces or commas. 'throwError'
-- in the monad if one is malformed.
parseAddressPatterns :: MonadError ShowS m => ByteString -> m [AddressPattern]
parseAddressPatterns = mapM parse1 . filter (not . B.null) .
                       B.splitWith (\c -> isSpace c || c == ',')
  where
    parse1 spec
      | B.elem ':' spec = Addr6 `fmap` inet_atoh6 spec
      | otherwise = case B.split '/' spec of
          [a] -> do
            a' <- inet_atoh a
            return $! Net4 a' 0xffffffff
          [a, bits]
            | Just (n, rest) <- B.readInt bits, B.null rest, n >= 0, n <= 32 -> do
                a' <- inet_atoh a
                let mask | n == 0    = 0
                         | otherwise = complement 0 `shiftL` (32 - n)
                return $! Net4 (a' .&. mask) mask
          _ -> throwError $ cat "Malformed address or network " (esc 64 spec) '.'
