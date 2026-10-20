-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Random
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- Generating cryptographically strong random data.
--
-- Earlier versions seeded OpenSSL's PRNG from a kernel random device and used
-- @RAND_bytes@. Modern kernels provide a non-blocking, cryptographically
-- strong CSPRNG through @\/dev\/urandom@, so we simply keep a handle to it
-- open (it is opened before we chroot or drop privileges) and read from it
-- directly. This removes the dependency on libcrypto.
--
-----------------------------------------------------------------------------

module TorDNSEL.Random (
    randBytes
  , openRandomDevice
  , seedPRNG
  ) where

import Control.Concurrent.MVar (MVar, newMVar, withMVar)
import Control.Monad (filterM)
import qualified Data.ByteString as B
import System.Directory (doesFileExist)
import System.IO
  (Handle, openFile, IOMode(ReadMode), hSetBuffering, BufferMode(NoBuffering))
import System.IO.Unsafe (unsafePerformIO)

-- | Serialise reads from the random device so that concurrent callers never
-- receive overlapping or short reads.
randomLock :: MVar ()
{-# NOINLINE randomLock #-}
randomLock = unsafePerformIO $ newMVar ()

-- | Return @n@ bytes of random data read from the given random device.
randBytes :: Handle -> Int -> IO B.ByteString
randBytes random n = withMVar randomLock $ \_ -> go n []
  where
    go 0 acc = return $! B.concat (reverse acc)
    go k acc = do
      bs <- B.hGetSome random k
      if B.null bs
        then ioError $ userError "randBytes: unexpected EOF on random device"
        else go (k - B.length bs) (bs : acc)

-- | Open a kernel random number device if one exists. @\/dev\/urandom@ is
-- preferred because it never blocks once the kernel CSPRNG is initialised.
openRandomDevice :: IO (Either ShowS Handle)
openRandomDevice = do
  devs <- filterM doesFileExist ["/dev/urandom", "/dev/random"]
  case devs of
    dev:_ -> do
      h <- openFile dev ReadMode
      hSetBuffering h NoBuffering
      return (Right h)
    []    -> return $ Left ("Kernel random number device not found." ++)

-- | Retained for compatibility: make sure the random device is readable.
-- There is no user-space PRNG to seed any more.
seedPRNG :: Handle -> IO ()
seedPRNG random = randBytes random 1 >> return ()
