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
import System.Exit (exitFailure)
import Test.HUnit (runTestTT, Test(..), Counts(..))

import qualified TorDNSEL.Config.Tests as Config
import qualified TorDNSEL.Directory.Tests as Directory
import qualified TorDNSEL.DNS.Tests as DNS
import qualified TorDNSEL.DNS.Server.Tests as DNS.Server

main :: IO ()
main = do
  counts <- runTestTT . TestList $
    [Config.tests, Directory.tests, DNS.tests, DNS.Server.tests]
  when (errors counts + failures counts > 0) exitFailure
