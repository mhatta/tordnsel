{-# LANGUAGE CPP #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Files
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : Masayuki Hatta <mhatta@mhatta.org>
-- Stability   : alpha
-- Portability : non-portable (POSIX)
--
-- Opening files whose names we don't fully trust, without following
-- symbolic links into places we didn't mean, blocking on FIFOs, or reading
-- endless devices.
--
-----------------------------------------------------------------------------

module TorDNSEL.Files (
    readSmallRegularFile
  , createFileExclusively
  , isGroupOrWorldWritable
  ) where

import qualified Control.Exception as E
import Data.Bits ((.&.))
import qualified Data.ByteString as B
import System.IO (Handle, hClose)
import System.IO.Error (mkIOError, userErrorType, isDoesNotExistError)
import System.Posix.Files
  ( getFdStatus, isRegularFile, removeLink, groupWriteMode, otherWriteMode
  , setFdMode )
import System.Posix.IO
  ( openFd, OpenMode(..), OpenFileFlags(..), defaultFileFlags, fdToHandle
  , closeFd )
import System.Posix.Types (Fd, FileMode)

-- | Read at most @n@ bytes from a regular file. The file is opened without
-- blocking, so that a FIFO can't stall us, and anything other than a regular
-- file (a FIFO, a device such as @\/dev\/zero@) is refused. Throw an
-- 'IOError' if the file can't be read or isn't a regular file.
readSmallRegularFile :: Int -> FilePath -> IO B.ByteString
readSmallRegularFile n path = do
  fd <- openReadNonBlocking path
  h <- fdToHandle fd `E.onException` closeFd fd
  (`E.finally` hClose h) $ do
    st <- getFdStatus fd
    if isRegularFile st
      then B.hGet h n
      else E.throwIO $ mkIOError userErrorType "not a regular file" Nothing
                                 (Just path)

-- | Create a new file for writing with the given mode, replacing any file or
-- symbolic link of that name. The file is created with @O_CREAT|O_EXCL@,
-- which never follows a symbolic link: if one appears between removing the
-- old name and creating the file, creating it fails instead.
createFileExclusively :: FilePath -> FileMode -> IO Handle
createFileExclusively path mode = do
  removeLink path `E.catch` \e ->
    if isDoesNotExistError e then return () else E.throwIO e
  fd <- openCreateExclusive path mode
  -- The mode given to open(2) is subject to the umask; set it as asked.
  (setFdMode fd mode >> fdToHandle fd) `E.onException` closeFd fd

-- | Can users other than the owner write to this file or directory?
isGroupOrWorldWritable :: FileMode -> Bool
isGroupOrWorldWritable m = m .&. (groupWriteMode + otherWriteMode) /= 0

openReadNonBlocking :: FilePath -> IO Fd
openCreateExclusive :: FilePath -> FileMode -> IO Fd
#if MIN_VERSION_unix(2,8,0)
openReadNonBlocking path =
  openFd path ReadOnly defaultFileFlags { nonBlock = True }
openCreateExclusive path mode =
  openFd path WriteOnly defaultFileFlags { exclusive = True
                                         , creat = Just mode }
#else
openReadNonBlocking path =
  openFd path ReadOnly Nothing defaultFileFlags { nonBlock = True }
openCreateExclusive path mode =
  openFd path WriteOnly (Just mode) defaultFileFlags { exclusive = True }
#endif
