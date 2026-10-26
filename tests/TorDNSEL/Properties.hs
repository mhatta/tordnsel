{-# OPTIONS_GHC -Wno-orphans #-}
-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Properties
-- License     : Public domain (see LICENSE)
--
-- QuickCheck properties of the parts of TorDNSEL that read untrusted input:
-- the DNS decoder (fed by anyone who can send us a packet), the SOCKS and
-- control port parsers, and the UDP rate limiter.
--
-- Each property runs as one HUnit test case, so that the test suite keeps a
-- single runner.
--
-----------------------------------------------------------------------------

-- #hide
module TorDNSEL.Properties (tests) where

import qualified Control.Exception as E
import Control.Monad (replicateM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.List as L
import qualified Data.Bits as Bits
import Data.Word (Word8)
import Network.Socket (SockAddr(..))
import Test.HUnit (Test(..), assertFailure)
import Test.QuickCheck

import TorDNSEL.DNS.Internals
import TorDNSEL.DNS.Server.Internals
  (RateDecision(..), rateLimit, emptyRateLimiter)
import TorDNSEL.Socks.Internals (Response(..), Result(..), decodeResponse)
import TorDNSEL.TorControl.Internals (parseAuthChallenge)
import TorDNSEL.ExitTest.Request (getRequest)
import TorDNSEL.Web.Internals (parseRequest)
import Network.Socket
  (socketPair, Family(AF_UNIX), SocketType(Stream), socketToHandle)
import System.IO (IOMode(ReadWriteMode), hClose)
import TorDNSEL.Util (Port(..), htonl)

tests :: Test
tests = TestList
  [ prop "decoding arbitrary bytes doesn't crash" decodeTotal
  , prop "decoding damaged messages doesn't crash" decodeDamaged
  , prop "decode . encode == id" roundTrip
  , prop "re-encoding a decoded message loses nothing" reencode
  , prop "EDNS options: round trip, and total" ednsOptionsProp
  , prop "client subnet option: round trip, and total" clientSubnetProp
  , prop "SOCKS responses: round trip, and total" socks
  , prop "AUTHCHALLENGE replies: parsing is total" authChallenge
  , prop "HTTP requests: parsing is total" httpRequests
  , prop "exit test requests: reading them doesn't crash" exitTestRequests
  , prop "the rate limiter allows at most rate*(1+t) queries" rateBound ]

-- | Turn a property into a test case.
prop :: Testable p => String -> p -> Test
prop name p = TestLabel name . TestCase $ do
  r <- quickCheckWithResult stdArgs { maxSuccess = 500, chatty = False } p
  case r of
    Success {} -> return ()
    _          -> assertFailure (name ++ ":\n" ++ output r)

-- | Evaluate a value to WHNF, failing the property if that throws.
noException :: a -> Property
noException x = ioProperty $ do
  r <- E.try (E.evaluate x)
  return $ case r of
    Left (e :: E.SomeException) -> counterexample (show e) False
    Right _                     -> property True

--------------------------------------------------------------------------------
-- DNS

decodeTotal :: Property
decodeTotal = forAll bytes $ \bs ->
  noException (decodeMessage (Packet bs))
  where
    -- Mostly short strings, with headers that claim records.
    bytes = oneof [ B.pack <$> arbitrary
                  , B.append header . B.pack <$> arbitrary ]
    header = B.pack [0,1, 0,0, 0,1, 0,2, 0,1, 0,1]

-- | Valid messages with bytes changed, inserted or cut off: the decoder may
-- reject them, but must not crash.
decodeDamaged :: Property
decodeDamaged = forAll damagedMessage $ \bs ->
  noException (decodeMessage (Packet bs))

-- | An encoded message, damaged.
damagedMessage :: Gen B.ByteString
damagedMessage = do
  msg <- arbitrary
  damage (unPacket $ encodeMessage msg)
  where
    damage bs = oneof
      [ do i <- choose (0, B.length bs - 1)
           w <- arbitrary
           return $ B.concat [B.take i bs, B.singleton w, B.drop (i + 1) bs]
      , do i <- choose (0, B.length bs)
           return (B.take i bs)
      , do i <- choose (0, B.length bs)
           ws <- listOf1 arbitrary
           return $ B.concat [B.take i bs, B.pack ws, B.drop i bs]
      -- a compression pointer somewhere
      , do i <- choose (12, max 12 (B.length bs - 2))
           p <- choose (0, 0x3fff :: Int)
           let ptr = B.pack [0xc0 + fromIntegral (p `div` 256), fromIntegral p]
           return $ B.concat [B.take i bs, ptr, B.drop (i + 2) bs] ]

roundTrip :: Message -> Property
roundTrip msg =
  let pkt = encodeMessage msg
  in counterexample (show pkt) $ decodeMessage pkt === Just msg

-- | Whatever the decoder accepts, it can read back from our encoding of it:
-- nothing it produces is something we can't send.
reencode :: Property
reencode = forAll damagedMessage $ \bs ->
  case decodeMessage (Packet bs) of
    Nothing  -> property True
    Just msg -> decodeMessage (encodeMessage msg) === Just msg

instance Arbitrary Message where
  arbitrary = do
    q <- arbitrary
    Message <$> arbitrary <*> arbitrary <*> opCode <*> arbitrary
            <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
            <*> arbitrary <*> rCode <*> pure q
            <*> records q <*> records q <*> records q
    where
      opCode = elements [StandardQuery, InverseQuery, ServerStatusRequest]
               `orElse` (UnknownOpCode <$> choose (3, 15))
      rCode = elements [NoError, FormatError, ServerFailure, NXDomain
                       , NotImplemented, Refused]
              `orElse` (UnknownRCode <$> choose (6, 15))
      -- Records are often about the question's name, so that name
      -- compression has something to do.
      records q = do
        n <- choose (0, 3)
        replicateM n $ do
          rr <- arbitrary
          sameName <- arbitrary
          return $ if sameName then rr { rrName = qName q } else rr

instance Arbitrary Question where
  arbitrary = Question <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ResourceRecord where
  arbitrary = oneof
    [ A <$> arbitrary <*> arbitrary <*> arbitrary
    , NS <$> arbitrary <*> arbitrary <*> arbitrary
    , SOA <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
          <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
          <*> arbitrary
    , TXT <$> arbitrary <*> arbitrary <*> strings
    , do (t, c) <- ((,) <$> arbitrary <*> arbitrary) `suchThat` unsupported
         UnsupportedResourceRecord <$> arbitrary <*> arbitrary <*> pure t
           <*> pure c <*> (B.pack <$> resize 64 (listOf arbitrary)) ]
    where
      -- A few character strings of up to 255 bytes, the most there can be.
      strings = do
        n <- choose (0, 3)
        replicateM n $ B.pack <$> (vector =<< choose (0, 255))
      -- Records we decode as A, NS, SOA or TXT can't be unsupported.
      unsupported (t, c) = not (c == IN && t `elem` [TA, TNS, TSOA, TTXT])

instance Arbitrary DomainName where
  arbitrary = do
    n <- choose (0, 5)
    DomainName <$> replicateM n arbitrary

instance Arbitrary Label where
  -- Labels from a small alphabet, so that names share suffixes and get
  -- compressed. At most 49 bytes, so that five of them fit in a name.
  arbitrary = do
    len <- frequency [(9, choose (1, 8)), (1, choose (1, 49))]
    Label . BC.pack <$> replicateM len (elements "abc-0")

instance Arbitrary Type where
  arbitrary = elements [TA, TNS, TSOA, TTXT, TOPT, TAny]
              `orElse` (UnsupportedType <$> arbitrary `suchThat`
                          (`notElem` [1, 2, 6, 16, 41, 255]))

instance Arbitrary Class where
  arbitrary = elements [IN, AnyClass]
              `orElse` (UnsupportedClass <$> arbitrary `suchThat`
                          (`notElem` [1, 255]))

orElse :: Gen a -> Gen a -> Gen a
orElse a b = frequency [(3, a), (1, b)]

ednsOptionsProp :: Property
ednsOptionsProp = valid .&&. total
  where
    valid = forAll (listOf ((,) <$> arbitrary <*> (B.pack <$> resize 40 (listOf arbitrary)))) $
      \opts -> parseEDNSOptions (renderEDNSOptions opts) === Just opts
    total = forAll (B.pack <$> arbitrary) $ \bs ->
      noException (maybe () (const ()) (parseEDNSOptions bs))

clientSubnetProp :: Property
clientSubnetProp = valid .&&. total
  where
    -- a valid IPv4 or IPv6 subnet: the right number of address bytes, and
    -- no bits beyond the prefix
    valid = forAll genSubnet $ \cs ->
      parseClientSubnet (renderClientSubnet cs) === Just cs
    genSubnet = do
      (family, maxBits) <- elements [(1, 32), (2, 128 :: Int)]
      source <- choose (0, maxBits)
      bytes <- vector ((source + 7) `div` 8)
      let bytes' | source `mod` 8 == 0 || null bytes = bytes
                 | otherwise = init bytes ++
                     [last bytes Bits..&. (0xff `Bits.shiftL` (8 - source `mod` 8))]
      return $ ClientSubnet family (fromIntegral source) 0 (B.pack bytes')
    total = forAll (B.pack <$> arbitrary) $ \bs ->
      noException (maybe () (const ()) (parseClientSubnet bs))

--------------------------------------------------------------------------------
-- SOCKS and the control port

socks :: Property
socks = valid .&&. total
  where
    valid = forAll ((,,) <$> choose (90, 93) <*> arbitrary <*> arbitrary) $
      \(code, addr, port) ->
        let bs = B.pack ([0, code] ++ be16 port ++ be32 addr)
        in fmap summary (decodeResponse bs)
             === Just (code, addr, port)
    total = forAll (B.pack <$> arbitrary) $ noException . decodeResponse
    summary (Response res addr (Port port)) = (resultCode res, addr, port)
    resultCode Granted           = 90
    resultCode Failed            = 91
    resultCode IdentdUnreachable = 92
    resultCode IdentdMismatch    = 93 :: Word8
    be16 x = map fromIntegral [x `div` 256, x `mod` 256]
    be32 x = map (\s -> fromIntegral (x `div` (2 ^ (s :: Int)) `mod` 256))
                 [24, 16, 8, 0]

authChallenge :: Property
authChallenge = forAll text $ \t ->
  noException (either (const ()) (const ()) (parseAuthChallenge t))
  where
    text = BC.pack <$> oneof
      [ arbitrary
      , (\a b -> "AUTHCHALLENGE SERVERHASH=" ++ a ++ " SERVERNONCE=" ++ b)
          <$> hex <*> hex ]
    hex = listOf (elements "0123456789abcdefABCDEFxyz")

-- | Lines that look a bit like HTTP: a request line, header-ish lines (with
-- and without colons) and some body.
httpish :: Gen B.ByteString
httpish = do
  reqLine <- elements [ "POST / HTTP/1.0", "POST / HTTP/1.1", "GET / HTTP/1.1"
                      , "GET /api/v1/ip-port?ip=1.2.3.4&port=80&dest=5.6.7.8 HTTP/1.1"
                      , "GET /%zz HTTP/1.0", "" ]
  hs <- listOf $ oneof
    [ elements [ "Content-Type: application/octet-stream", "Content-Length: 32"
               , "Content-Length", "content-type", "Content-Length: x", ":"
               , "Host: example.com" ]
    , BC.unpack . B.pack <$> listOf arbitrary ]
  body <- B.pack <$> resize 64 (listOf arbitrary)
  let crlf = "\r\n"
  return $ B.concat [ BC.pack (reqLine ++ crlf ++ concatMap (++ crlf) hs ++ crlf)
                    , body ]

httpRequests :: Property
httpRequests = forAll (oneof [httpish, B.pack <$> arbitrary]) $ \bs ->
  noException (maybe () (const ()) (parseRequest bs))

-- | 'getRequest' reads from anyone who connects to an exit test listener.
exitTestRequests :: Property
exitTestRequests = forAll httpish $ \bs -> ioProperty $ do
  (a, b) <- socketPair AF_UNIX Stream 0
  ha <- socketToHandle a ReadWriteMode
  hb <- socketToHandle b ReadWriteMode
  B.hPut hb bs >> hClose hb
  r <- E.try (getRequest ha >>= E.evaluate)
  hClose ha
  return $ case r of
    Left (e :: E.SomeException)
      | Just (_ :: E.IOException) <- E.fromException e -> property True
      | otherwise -> counterexample (show e) False
    Right _ -> property True

--------------------------------------------------------------------------------
-- Rate limiting

-- | Whatever the timing of the queries from one network, no more than
-- @rate@ (the burst) plus @rate@ per elapsed second are allowed.
rateBound :: Property
rateBound =
  forAll (choose (1, 20)) $ \rate ->
  forAll (listOf (choose (0, 300 :: Int))) $ \gaps ->
    let times = scanl1 (+) (map (\ms -> fromIntegral ms / 1000) gaps)
        src = SockAddrInet 4000 (htonl 0xc0000201)
        step (rl, allowed) t =
          let (d, rl') = rateLimit rate (1000 + t) src rl
          in (rl', if d == Allow then allowed + 1 else allowed)
        (_, n) = L.foldl' step (emptyRateLimiter, 0 :: Int) times
        elapsed = if null times then 0 else last times - head times
        bound = fromIntegral rate * (1 + realToFrac elapsed) :: Double
    in counterexample (show (n, bound)) $ fromIntegral n <= bound + 1e-9
