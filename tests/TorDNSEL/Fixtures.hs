{-# LANGUAGE OverloadedStrings  #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Fixtures
-- License     : Public domain (see LICENSE)
--
-- A small synthetic view of the Tor network shared by several tests.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.Fixtures (networkState, now, ip, ridA, ridB, ridC) where

import qualified Data.ByteString.Char8 as B
import qualified Data.Map as M
import qualified Data.Set as S
import Data.Time.Clock.POSIX (POSIXTime, posixSecondsToUTCTime)
import Network.Socket (HostAddress)

import TorDNSEL.Directory.Internals
import TorDNSEL.NetworkState.Types
import TorDNSEL.Util

-- | A small network: 10.0.0.11 exits anywhere except port 25 and was also
-- seen exiting from 10.0.0.99; 10.0.0.12 published its last descriptor three
-- days ago; 10.0.0.13 only permits connections to 198.51.100.0/24.
networkState :: NetworkState
networkState = NetworkState
  { nsAddrs = M.fromList
      [ (ip "10.0.0.11", S.singleton ridA)
      , (ip "10.0.0.99", S.singleton ridA)
      , (ip "10.0.0.12", S.singleton ridB)
      , (ip "10.0.0.13", S.singleton ridC) ]
  , nsRouters = M.fromList
      [ (ridA, (router $ Desc (ip "10.0.0.11") (now - 3600) ridA policyA)
                 { rtrTestResults = Just $ TestResults (utc $ now - 3600)
                     (M.singleton (ip "10.0.0.99") (utc $ now - 600)) })
      , (ridB, router $ Desc (ip "10.0.0.12") (now - 3 * 86400) ridB policyA)
      , (ridC, router $ Desc (ip "10.0.0.13") (now - 3600) ridC policyC) ] }
  where
    router d = Router (Just d) Nothing True (utc now)
    utc = posixSecondsToUTCTime
    policyA = [ Rule Reject 0 0 25 25, Rule Accept 0 0 0 65535 ]
    policyC = [ Rule Accept (ip "198.51.100.0") 0xffffff00 0 65535
              , Rule Reject 0 0 0 65535 ]

-- | Three router identities.
ridA, ridB, ridC :: RouterID
ridA = RtrId (B.replicate 20 'a')
ridB = RtrId (B.replicate 20 'b')
ridC = RtrId (B.replicate 20 'c')

-- | The current time in the fixture.
now :: POSIXTime
now = 1800000000

-- | Parse a dotted-quad address.
ip :: B.ByteString -> HostAddress
ip = either (error . ($ "")) id . inet_atoh
