-----------------------------------------------------------------------------
-- |
-- Module      : Main
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : portable
--
-- Unit tests.
--
-----------------------------------------------------------------------------

-- #hide
module Main (main) where

import Control.Monad (when)
import Data.IORef (newIORef, readIORef, writeIORef)
import System.Exit (exitFailure)
import Test.HUnit (runTestTT, Test(..), Counts(..))

import TorDNSEL.Control.Concurrent.Link (withLinksDo)

import qualified TorDNSEL.Config.Tests as Config
import qualified TorDNSEL.Directory.Tests as Directory
import qualified TorDNSEL.DNS.Tests as DNS
import qualified TorDNSEL.DNS.Server.Tests as DNS.Server
import qualified TorDNSEL.ExitList.Tests as ExitList
import qualified TorDNSEL.Properties as Properties
import qualified TorDNSEL.TorControl.Tests as TorControl
import qualified TorDNSEL.Web.Tests as Web

-- Some tests start TorDNSEL's threads, which need withLinksDo; it may only be
-- used once, in the main thread.
main :: IO ()
main = do
  result <- newIORef Nothing
  withLinksDo $ writeIORef result . Just =<< runTests
  counts <- maybe exitFailure return =<< readIORef result
  when (errors counts + failures counts > 0) exitFailure
  where
   runTests = runTestTT . TestList $
    [ Config.tests, Directory.tests, DNS.tests, DNS.Server.tests
    , ExitList.tests, TorControl.tests, Web.tests, Properties.tests ]
