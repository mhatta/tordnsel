{-# OPTIONS_GHC -fno-warn-type-defaults #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Statistics.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (bang patterns, GHC primitives)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- Making load information available external to the process.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Statistics.Internals where

import Prelude hiding (log)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.MVar (MVar, newMVar, modifyMVar_, readMVar)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import qualified Data.Map as M
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Control.Concurrent.QSem (QSem, newQSem, waitQSem, signalQSem)
import qualified Control.Exception as E
import Control.Monad (when, forever)
import Control.Monad.Fix (fix)
import qualified Data.ByteString.Char8 as B
import Data.Maybe
import qualified Data.Set as S
import Network.Socket (accept, socketToHandle, Socket)
import System.IO (hClose, IOMode(ReadWriteMode))
import System.IO.Unsafe (unsafePerformIO)
import System.Timeout

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.DNS.Server
import TorDNSEL.Directory (Descriptor(..))
import TorDNSEL.ExitList
import TorDNSEL.NetworkState (readNetworkState)
import TorDNSEL.NetworkState.Types
import TorDNSEL.Log
import TorDNSEL.Util

-- | Cumulative counts of bytes transferred, datagrams received, and responses
-- sent.
data Stats = Stats
  { bytesRecv, bytesSent, dgramsRecv, positives
  , negatives, others, httpRequests, rateLimited :: !Integer }

-- | The current statistics state.
statsState :: MVar Stats
{-# NOINLINE statsState #-}
statsState = unsafePerformIO . newMVar $ Stats 0 0 0 0 0 0 0 0

-- | When we started, for metrics. Set by 'startStatsServer'.
startTimeRef :: IORef POSIXTime
{-# NOINLINE startTimeRef #-}
startTimeRef = unsafePerformIO $ newIORef 0

-- | An internal type for messages sent to the stats server thread.
data StatsMessage
  = NewClient Socket -- ^ A new client has connected.
  | Terminate ExitReason -- ^ Terminate the stats server gracefully.
  | Exit ThreadId ExitReason -- ^ An exit signal sent to the stats server.

-- | A handle to a stats server.
data StatsServer = StatsServer (StatsMessage -> IO ()) ThreadId

instance Thread StatsServer where
  threadId (StatsServer _ tid) = tid

-- | An internal type representing the current stats server state.
data StatsState = StatsState
  { listenerTid     :: !(ThreadId)
  , handlers        :: !(S.Set ThreadId)
  , terminateReason :: !(Maybe ExitReason) }

-- | Given the runtime directory, bind and return the listening statistics
-- socket.
bindStatsSocket :: FilePath -> IO Socket
bindStatsSocket runtimeDir =
  bindListeningUnixDomainStreamSocket (statsSocketPath runtimeDir) 0o666

-- | Given a listening socket, start a server offering access to load statistics
-- through a Unix domain stream socket in our runtime directory. Link the server
-- thread to the calling thread.
startStatsServer :: Socket -> IO StatsServer
startStatsServer listenSock = do
  log Info "Starting statistics server."
  getPOSIXTime >>= writeIORef startTimeRef
  statsChan <- newChan
  statsServerTid <- forkLinkIO $ do
    setTrapExit $ (writeChan statsChan .) . Exit
    handlerQSem <- newQSem maxStatsHandlers
    initListenerTid <- forkListener statsChan listenSock handlerQSem

    flip fix (StatsState initListenerTid S.empty Nothing) $ \loop (!s) -> do
      message <- readChan statsChan
      case message of
        NewClient client -> do
          handlerTid <- forkLinkIO . (`E.finally` signalQSem handlerQSem) .
            E.bracket (socketToHandle client ReadWriteMode) hClose $ \handle ->
              timeout handlerTimeout $
                B.hPut handle . renderStats =<< readMVar statsState
          loop s { handlers = S.insert handlerTid (handlers s) }

        Terminate reason -> do
          log Info "Terminating statistics server."
          terminateThread Nothing (listenerTid s) (killThread $ listenerTid s)
          if S.null (handlers s)
            then exit reason
            else loop s { terminateReason = Just reason }

        Exit tid reason
          | tid == listenerTid s ->
              if isNothing $ terminateReason s
                then do
                  log Warn "The statistics listener thread exited unexpectedly:\
                           \ " (show reason) "; restarting."
                  newListenerTid <- forkListener statsChan listenSock handlerQSem
                  loop s { listenerTid = newListenerTid }
                else loop s
          | tid `S.member` handlers s -> do
              when (isAbnormal reason) $
                log Warn "Bug: A statistics client handler exited abnormally: "
              let newHandlers = S.delete tid (handlers s)
              case terminateReason s of
                -- all the handlers have finished, so let's exit
                Just reason | S.null newHandlers -> exit reason
                _ -> loop s { handlers = newHandlers }
          | isAbnormal reason -> exit reason
          | otherwise -> loop s

  return $ StatsServer (writeChan statsChan) statsServerTid
  where
    maxStatsHandlers = 32
    handlerTimeout = 10 * 10^6

-- | Fork the listener thread.
forkListener :: Chan StatsMessage -> Socket -> QSem -> IO ThreadId
forkListener statsChan listenSock sem =
  forkLinkIO $ E.mask $ \restore -> forever $ do
    waitQSem sem
    (client,_) <- restore $ accept listenSock
      `E.onException` signalQSem sem
    writeChan statsChan $ NewClient client

-- | Terminate the stats server gracefully. The optional parameter specifies the
-- amount of time in microseconds to wait for the thread to terminate. If the
-- thread hasn't terminated by the timeout, an uncatchable exit signal will be
-- sent.
terminateStatsServer :: Maybe Int -> StatsServer -> IO ()
terminateStatsServer mbWait (StatsServer tellStatsServer statsServerTid) =
  terminateThread mbWait statsServerTid (tellStatsServer $ Terminate NormalExit)

-- | Render 'Stats' to text as a sequence of CRLF-terminated lines.
renderStats :: Stats -> B.ByteString
renderStats s = B.concat . map line $
  [ B.pack "BytesReceived "     ~> bytesRecv
  , B.pack "BytesSent "         ~> bytesSent
  , B.pack "DatagramsReceived " ~> dgramsRecv
  , B.pack "PositivesSent "     ~> positives
  , B.pack "NegativesSent "     ~> negatives
  , B.pack "OthersSent "        ~> others
  , B.pack "HTTPRequests "      ~> httpRequests
  , B.pack "RateLimited "       ~> rateLimited ]
  where
    line (x,f) = x `B.append` (B.pack . show $ f s) `B.append` B.pack "\r\n"
    (~>) = (,)

-- | Generate the statistics socket path from the runtime directory path.
statsSocketPath :: FilePath -> FilePath
statsSocketPath = (++ "/statistics.socket")

-- | Increment the count of bytes transferred.
incrementBytes :: Int -> Int -> IO ()
incrementBytes received sent =
  modifyMVar_ statsState $ \s -> return $!
    s { bytesRecv  = bytesRecv s + fromIntegral received
      , bytesSent  = bytesSent s + fromIntegral sent
      , dgramsRecv = dgramsRecv s + 1 }

-- | Increment the count of HTTP requests to the web interface.
incrementHTTPRequests :: IO ()
incrementHTTPRequests =
  modifyMVar_ statsState $ \s -> return $! s { httpRequests = httpRequests s + 1 }

-- | Increment the count of DNSEL responses.
incrementResponses :: ResponseType -> IO ()
incrementResponses resp =
  modifyMVar_ statsState $ \s -> return $!
    case resp of
      Negative -> s { negatives = negatives s + 1 }
      Positive -> s { positives = positives s + 1 }
      Other    -> s { others    = others    s + 1 }
      Limited  -> s { rateLimited = rateLimited s + 1 }

-- | The current statistics and network state in the Prometheus text
-- exposition format, for the web interface's @\/metrics@, given our version.
currentMetrics :: String -> IO B.ByteString
currentMetrics version = do
  s <- readMVar statsState
  start <- readIORef startTimeRef
  now <- getPOSIXTime
  ns <- readNetworkState
  return $! renderMetrics version s start now ns

-- | Render statistics and a summary of the network state as Prometheus
-- metrics, given our version, when we started and the current time.
renderMetrics
  :: String -> Stats -> POSIXTime -> POSIXTime -> NetworkState -> B.ByteString
renderMetrics version s start now ns = B.pack . unlines $ concat
  [ metric "tordnsel_build_info" "gauge" "The version of TorDNSEL, as a label."
      [("{version=\"" ++ version ++ "\"}", 1)]
  , metric "tordnsel_start_time_seconds" "gauge"
      "When TorDNSEL started, in seconds since the epoch."
      [("", floor start)]
  , counter "tordnsel_dns_received_bytes_total"
      "Bytes of DNS queries received (UDP and TCP)." (bytesRecv s)
  , counter "tordnsel_dns_sent_bytes_total"
      "Bytes of DNS responses sent (UDP and TCP)." (bytesSent s)
  , counter "tordnsel_dns_messages_received_total"
      "DNS messages received (UDP and TCP)." (dgramsRecv s)
  , metric "tordnsel_dns_responses_total" "counter"
      "Exit list queries answered, by result; rate_limited counts UDP \
      \queries truncated or dropped by DNSRateLimit."
      [ ("{result=\"positive\"}", positives s)
      , ("{result=\"negative\"}", negatives s)
      , ("{result=\"other\"}", others s)
      , ("{result=\"rate_limited\"}", rateLimited s) ]
  , counter "tordnsel_http_requests_total"
      "Requests to the web interface." (httpRequests s)
  , metric "tordnsel_relays" "gauge"
      "Relays we know of, and those we think are running."
      [ ("{state=\"known\"}", fromIntegral (M.size routers))
      , ("{state=\"running\"}", count running) ]
  , metric "tordnsel_running_exits" "gauge"
      "Running relays whose exit policy permits connections somewhere."
      [("", count runningExit)]
  , metric "tordnsel_exit_addresses" "gauge"
      "Addresses listed as exit addresses (from descriptors and exit tests)."
      [("", fromIntegral . length $ exitAddressesTo now ns anyDestination)]
  , metric "tordnsel_tested_exit_addresses" "gauge"
      "Exit addresses found by our exit tests."
      [("", sum [ fromIntegral (M.size (tstAddresses t))
                | r <- M.elems routers, Just t <- [rtrTestResults r] ])]
  ]
  where
    routers = nsRouters ns
    descs = [ d | r <- M.elems routers, Just d <- [rtrDescriptor r] ]
    running d = isRunning now d
    runningExit d = isRunning now d &&
                    policyAcceptsDestination anyDestination (descExitPolicy d)
    count p = fromIntegral . length $ filter p descs
    counter name help v = metric name "counter" help [("", v)]
    metric :: String -> String -> String -> [(String, Integer)] -> [String]
    metric name typ help samples =
      ("# HELP " ++ name ++ " " ++ help) : ("# TYPE " ++ name ++ " " ++ typ) :
      [ name ++ labels ++ " " ++ show v | (labels, v) <- samples ]
