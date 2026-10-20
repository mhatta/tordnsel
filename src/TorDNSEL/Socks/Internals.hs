{-# OPTIONS_GHC -fno-warn-unused-binds #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Socks.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (dynamic exceptions, newtype deriving)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Making a TCP connection using the SOCKS4A protocol. Support for various
-- Tor extensions to SOCKS is sketched out.
--
-- See <https://spec.torproject.org/socks-extensions.html> for
-- details.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Socks.Internals (
  -- * Connections
    withSocksConnection

  -- * Data types
  , Request(..)
  , Command(..)
  , Response(..)
  , Result(..)

  -- * Serialization
  , encodeRequest
  , decodeResponse

  -- * Errors
  , SocksError(..)
  ) where

import qualified Control.Exception as E
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.Typeable (Typeable)
import Network.Socket (HostAddress)
import System.IO (Handle, BufferMode(NoBuffering), hClose, hSetBuffering)

import Control.DeepSeq

import Data.Binary (Binary(..), getWord8, putWord8)
import Data.Binary.Get (runGetOrFail, getWord32be)
import Control.Monad (when)
import Data.Binary.Put (runPut, putWord32be, putByteString)

import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Connections

-- | Open a Socks connection to an IP address\/domain name and port. The handle
-- will be closed if an exception occurs during the given 'IO' action. Throw a
-- 'SocksError' if the connection request fails.
withSocksConnection :: Handle -> Address -> Port -> IO a -> IO a
withSocksConnection handle addr port io = (`E.finally` hClose handle) $ do
  hSetBuffering handle NoBuffering
  B.hPut handle . encodeRequest $ Request Connect addr port
  r <- decodeResponse =<< B.hGet handle 8
  case r of
    Just (Response Granted _ _) -> io
    Just (Response result _ _)  -> E.throwIO (SocksError result)
    _                           -> E.throwIO SocksProtocolError

--------------------------------------------------------------------------------
-- Data types

-- | A Socks4a request.
data Request = Request
  { -- | The Socks4 command code (with Tor extensions).
    soCommand :: !Command,
    -- | The requested destination: either an IPv4 address or a domain name.
    soReqDest :: !Address,
    -- | The requested destination port.
    soReqPort :: !Port }

-- A Socks4a command (with Tor extensions).
data Command
  = Connect    -- ^ Connect to the requested destination.
  | Resolve    -- ^ Resolve a domain name.
  | ConnectDir -- ^ Establish a secure connection to a Tor directory.

-- | A Socks4 response.
data Response = Response
  { soResult   :: !Result      -- ^ The result code.
  , soRespAddr :: !HostAddress -- ^ The destination address.
  , soRespPort :: !Port        -- ^ The destination port.
  }

instance NFData Response where
  rnf = rwhnf

-- | A Socks4 result code.
data Result
  = Granted           -- ^ Request granted
  | Failed            -- ^ Request rejected or failed
  | IdentdUnreachable -- ^ Request rejected because SOCKS server cannot connect
                      -- to identd on the client
  | IdentdMismatch    -- ^ Request rejected because the client program and
                      -- identd report different user-ids
  deriving Eq

instance Show Result where
  show Granted           = "Request granted"
  show Failed            = "Request rejected or failed"
  show IdentdUnreachable = "Request rejected because SOCKS server cannot \
                           \connect to identd on the client"
  show IdentdMismatch    = "Request rejected because the client program and \
                           \identd report different user-ids"

--------------------------------------------------------------------------------
-- Serialization

-- | Encode a Socks4 request.
encodeRequest :: Request -> ByteString
encodeRequest = B.concat . L.toChunks . runPut . putRequest
  where
    putRequest req = do
      putWord8 4
      putWord8 $ case soCommand req of
        Connect    -> 1
        Resolve    -> 0xf0
        ConnectDir -> 0xf2
      put $ soReqPort req
      case soReqDest req of
        IPv4Addr addr -> do
          put addr
          putWord8 0
        Addr addr -> do
          putWord32be 1
          putWord8 0
          putByteString addr
          putWord8 0

-- | Decode a Socks4 response.
--
-- XXX We just fight lazy decoding here -- we should replace `binary` with
-- `cereal`. ( See `DNS`. )
decodeResponse :: ByteString -> IO (Maybe Response)
decodeResponse resp =
  case runGetOrFail getResponse (L.fromChunks [resp]) of
    Right (_, _, r) -> (Just $!! r) `seq` return (Just r)
    Left _          -> return Nothing
  where
    getResponse = do
      v <- getWord8
      when (v /= 0) $ fail "unexpected socks4 response version"
      cd <- getWord8
      res <- case cd of
            90 -> return Granted
            91 -> return Failed
            92 -> return IdentdUnreachable
            93 -> return IdentdMismatch
            _  -> fail "unknown socks4 result code"
      port <- get
      addr <- getWord32be
      return $! Response res addr port

--------------------------------------------------------------------------------
-- Errors

-- | A Socks error.
data SocksError
  = SocksError !Result -- ^ A known Socks error code.
  | SocksProtocolError -- ^ The response doesn't follow the Socks protocol.
  deriving Typeable

instance Show SocksError where
  showsPrec _ (SocksError result) = cat "Socks error: " result
  showsPrec _ SocksProtocolError  = cat "Socks protocol error"

instance E.Exception SocksError
