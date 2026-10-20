{-# LANGUAGE OverloadedStrings  #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.ExitList.Tests
-- License     : Public domain (see LICENSE)
--
-- Tests for destination patterns, named lists and exit policy evaluation
-- over sets of destinations.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.ExitList.Tests (tests) where

import qualified Data.ByteString.Char8 as B
import Data.Either (isLeft)
import Network.Socket (HostAddress)
import Test.HUnit (Test(..), (@=?), (@?))

import TorDNSEL.Directory.Internals
import TorDNSEL.Document
import TorDNSEL.ExitList
import TorDNSEL.Util

tests :: Test
tests = TestList [patterns, namedLists, someAccepted]

patterns :: Test
patterns = TestList . map TestCase $
  [ Just [AddrPortPattern (ip "192.0.2.10") 0xffffffff 6667 6667]
      @=? hush (parseAddrPortPattern "192.0.2.10:6667")
  , Just [ AddrPortPattern (ip "198.51.100.0") 0xffffff00 6660 6669
         , AddrPortPattern (ip "198.51.100.0") 0xffffff00 7000 7000 ]
      @=? hush (parseAddrPortPattern "198.51.100.7/24:6660-6669,7000")
  , isErr (parseAddrPortPattern "10.0.0.0/7:80") @? "masks wider than /8"
  , isErr (parseAddrPortPattern "10.0.0.1:90-80") @? "reversed port range"
  , isErr (parseAddrPortPattern "10.0.0.1") @? "missing port"
  , isErr (parseAddrPortPattern "10.0.0.256:80") @? "bad address"
  , "198.51.100.0/24:6660-6669" @=?
      showAddrPortPattern (AddrPortPattern (ip "198.51.100.0") 0xffffff00
                                           6660 6669)
  ]

namedLists :: Test
namedLists = TestList . map TestCase $
  [ Just ("examplenet", [ AddrPortPattern (ip "192.0.2.10") 0xffffffff 6667 6667
                        , AddrPortPattern (ip "192.0.2.11") 0xffffffff 6697 6697 ])
      @=? hush (parseNamedList "ExampleNet 192.0.2.10:6667 192.0.2.11:6697")
  , isErr (parseNamedList "examplenet") @? "list without patterns"
  , isErr (parseNamedList "example.net 192.0.2.10:6667") @? "dots in names"
  , isErr (parseNamedList "-bad 192.0.2.10:6667") @? "leading hyphen"
  ]

someAccepted :: Test
someAccepted = TestList . map TestCase $
  -- an IRC network: two servers on 6667
  [ True  @=? accepts irc "accept *:*"
  , False @=? accepts irc "reject *:6667\naccept *:*"
  , True  @=? accepts irc "reject 192.0.2.10:*\naccept *:*"
  , False @=? accepts irc "reject 192.0.2.10:*\nreject 192.0.2.11:*\naccept *:*"
  , True  @=? accepts irc "reject 192.0.2.0/24:1-6666\naccept *:*"
  , False @=? accepts irc "accept *:80\naccept *:443\nreject *:*"
  -- Tor's default "no matching rule" behaviour is to accept
  , True  @=? accepts irc "reject 10.0.0.0/8:*"
  -- a range: accepted only if some address/port in it is
  , True  @=? accepts range "reject 198.51.100.0/25:*\naccept *:*"
  , False @=? accepts range "reject 198.51.100.0/24:6660-6669\naccept *:*"
  , True  @=? accepts range "reject 198.51.100.0/24:6660-6668\naccept *:*"
  , True  @=? accepts range
                "reject 198.51.100.0/24:6661-6669\naccept 198.51.100.200:6660"
  , False @=? accepts range
                "reject 198.51.100.0/24:6661-6669\nreject *:6660\naccept *:*"
  -- agrees with exitPolicyAccepts on single destinations
  , and [ policyAcceptsSome [AddrPortPattern a 0xffffffff p p] (policy pol)
            == exitPolicyAccepts a p (policy pol)
        | a <- map ip ["192.0.2.10", "198.51.100.200", "10.1.2.3"]
        , p <- [22, 25, 80, 443, 6667]
        , pol <- [ "reject *:25\naccept *:*"
                 , "accept 10.0.0.0/8:22-80\nreject *:*"
                 , "reject 198.51.100.0/24:*\naccept *:443\nreject *:*" ] ]
      @? "single destinations"
  ]
  where
    irc = [ AddrPortPattern (ip "192.0.2.10") 0xffffffff 6667 6667
          , AddrPortPattern (ip "192.0.2.11") 0xffffffff 6667 6667 ]
    range = [AddrPortPattern (ip "198.51.100.0") 0xffffff00 6660 6669]
    accepts pats = policyAcceptsSome pats . policy
    policy :: B.ByteString -> ExitPolicy
    policy = either (error . ($ "")) id . parseExitPolicy . parseDocument
           . B.lines

isErr :: Either ShowS a -> Bool
isErr = isLeft

ip :: B.ByteString -> HostAddress
ip = either (error . ($ "")) id . inet_atoh
