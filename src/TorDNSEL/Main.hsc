{-# LANGUAGE ForeignFunctionInterface, CPP #-}
{-# OPTIONS_GHC -fno-warn-type-defaults -fno-warn-missing-fields
                -fno-warn-orphans #-}

-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Main
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : tup.tuple@googlemail.com
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions,
--                             pattern guards, bang patterns, FFI,
--                             GHC primitives)
--
-- Implements a DNSBL-style interface providing information about whether a
-- client for a network service is likely connecting through a Tor exit node.
--
-- See @doc/torel-design.md@ for
-- details.
--
-----------------------------------------------------------------------------

module TorDNSEL.Main (
  -- * Constants
    minFileDesc
  , maxFileDesc
  , extraFileDesc

  -- * Top level functionality
  , StaticState(..)
  , State(..)
  , MainThreadMessage(..)
  , main
  , verifyConfig
  , runMainThread
  , handleMessage
  , mkDNSServerConfig
  , mkExitTestConfig
  , initializeLogger
  , initializeNetworkStateManager
  , reconfigureOrRestartLogger
  , reconfigureListenersAndNetworkStateManager
  , reconfigureDNSListenerAndServer
  , reconfigureHTTPListenerAndServer
  , mkWebConfig
  , terminateProcess

  -- * Daemon operations
  , getIDs
  , dropPrivileges
  , changeRootDirectory
  , daemonize

  -- * Helpers
  , setMaxOpenFiles
  , checkDirectory
  , checkLogTarget
  , SysExitCode(..)
  , fromSysExitCode
  , bindErrorCode
  , exitLeft
  , exitPrint
  , liftMb
  ) where

import Prelude hiding (log)
import Control.Concurrent (rtsSupportsBoundThreads)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import qualified Control.Exception as E
import Control.Monad (when, liftM, forM, forM_)
import Control.Monad.Fix (fix)
import Control.Monad.State (StateT, runStateT, liftIO, get, put)
import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L
import Data.Char (toLower)
import Data.List (intersperse)
import qualified Data.Map as M
import Data.Map (Map)
import Data.Maybe (isJust, isNothing, fromMaybe)
import qualified Data.Set as S
import Data.Set (Set)
import System.Environment (getArgs)
import System.IO
  ( openFile, hPutStrLn, hClose, Handle, stdout, stderr
  , IOMode(WriteMode, AppendMode) )
import System.IO.Error (isPermissionError)
import Network.Socket
  (Socket, SockAddr(SockAddrInet), shutdown, ShutdownCmd(ShutdownSend))

import qualified Network.Socket.ByteString as NSB
import System.Exit (ExitCode(ExitSuccess, ExitFailure), exitWith)
import System.Directory (setCurrentDirectory, createDirectoryIfMissing)
import System.Posix.IO
  ( openFd, closeFd, stdInput, stdOutput, stdError, OpenMode(ReadWrite)
  , defaultFileFlags, dupTo )
import System.Posix.Process
  (forkProcess, createSession, exitImmediately, getProcessID)
import System.Posix.Signals
  ( installHandler, Signal, Handler(Ignore, Catch)
  , sigHUP, sigPIPE, sigINT, sigTERM )

import System.Posix.Error (throwErrnoPathIfMinus1_)
import System.Posix.Files
  (getFileStatus, fileOwner, fileMode, setFileMode, setOwnerAndGroup)
import System.Posix.Resource
  ( ResourceLimits(..), ResourceLimit(..), Resource(ResourceOpenFiles)
  , getResourceLimit, setResourceLimit )
import System.Posix.Types (UserID, GroupID)
-- unix >= 2.8 exports UserEntry/GroupEntry as pattern synonyms, so import the
-- module whole to get the field selectors with any unix version.
import System.Posix.User
import Foreign.C (CString, CInt(..), withCString)

import TorDNSEL.Config
import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.DNS
import TorDNSEL.DNS.Server
import TorDNSEL.Log
import TorDNSEL.NetworkState
import TorDNSEL.Random
import TorDNSEL.Statistics
import TorDNSEL.Util
import TorDNSEL.Web

#include <sys/types.h>
#include <unistd.h>
#include <sysexits.h>

--------------------------------------------------------------------------------
-- Constants

-- | Minimum limit on open file descriptors under which we can run.
minFileDesc :: Integer
minFileDesc = 128

-- | Maximum limit on open file descriptors we can set with 'setResourceLimit'.
-- The threaded RTS uses epoll(7)\/kqueue(2), so this no longer needs to be as
-- low as it was with the select(2)-based I\/O manager.
maxFileDesc :: Integer
maxFileDesc = 16384

-- | Number of file descriptors the process might need for everything but exit
-- tests.
extraFileDesc :: Integer
extraFileDesc = 96

--------------------------------------------------------------------------------
-- Top level functionality

-- | State that is initialized once on startup, then never changed.
data StaticState = StaticState
  { availableFileDesc :: Integer -- ^ Number of file descriptors available.
  , randomHandle      :: Handle  -- ^ Handle to a random number device.
  , statsSocket       :: Socket  -- ^ Listening statistics socket.
  , reconfigSocket    :: Socket  -- ^ Listening reconfigure socket.
  }

-- | Mutable state used by the main thread.
data State = State
  { logger              :: Maybe Logger -- ^ The logger thread, if it's running.
  , reconfigServer      :: Maybe ReconfigServer
                            -- ^ The reconfigure server thread, if it's running.
  , statsServer         :: Maybe StatsServer
                            -- ^ The statistics server thread, if it's running.
  , networkStateManager :: NetworkStateManager
                            -- ^ The network state manager thread.
  , dnsServer           :: DNSServer -- ^ The DNS server thread.
  , exitTestListeners   :: Map SockAddr (Maybe Socket)
                            -- ^ Listening exit test sockets.
  , dnsListener         :: Socket -- ^ The listening DNS socket.
  , webServer           :: Maybe WebServer
                            -- ^ The web interface thread, if enabled.
  , httpListener        :: Maybe Socket
                            -- ^ The listening HTTP socket, if enabled.
  , deadThreads         :: Set ThreadId
                            -- ^ Dead threads linked to the main thread.
  }

-- | Messages the main thread can receive.
data MainThreadMessage
  -- | Reconfigure the process given an optional config. If the config isn't
  -- given, try to reload our config file. Either way, the log file (if open)
  -- will be closed and re-opened. If the config is given, pass an error message
  -- to the given action if reconfiguring the process fails and we're about to
  -- exit.
  = Reconfigure (Maybe (Config, (Maybe String -> IO ())))
  | Terminate Signal -- ^ Terminate the process with the given Posix signal.
  | Exit ThreadId ExitReason -- ^ An exit signal sent by a linked thread.

-- | The main entry point for the server. This handles parsing config options,
-- various daemon operations, forking the network state handler, Tor controller,
-- exit test threads, and starting the DNS server.
main :: IO ()
main = do
  args <- getArgs
  case args of
    _ | args == ["-h"] || args == ["--help"] ->
          exitUsage stdout ExitSuccess
      | args == ["-v"] || args == ["--version"] ->
          putStrLn ("TorDNSEL " ++ VERSION) >> exitWith ExitSuccess
      | any (\arg -> map toLower arg == "--verify-config") args ->
          verifyConfig args
    ["--reconfigure",runtimeDir] -> do
      sock <- connectToReconfigSocket runtimeDir
        `E.catch` \(e :: E.SomeException) -> do
          hCat stderr "Connecting to reconfigure socket failed: " e '\n'
          exitWith $ fromSysExitCode Unavailable
      r <- E.handle (\(e :: E.IOException) -> do
             hCat stderr "An I/O error occurred while reconfiguring: " e '\n'
             exitWith $ fromSysExitCode IOError) $
        (`E.finally` closeSocket sock) $ do
          -- network >= 3 invalidates a socket handed to socketToHandle, so
          -- talk to the socket directly to be able to half-close it.
          L.getContents >>= NSB.sendAll sock . B.concat . L.toChunks
          shutdown sock ShutdownSend
          let readAll acc = do
                chunk <- NSB.recv sock 4096
                if B.null chunk then return (B.concat $ reverse acc)
                                else readAll (chunk : acc)
          readAll []
      B.hPut stderr r
      exitWith . fromSysExitCode $ case () of
       _| B.null r                         -> OK
        | B.pack "Parse error:" `B.isPrefixOf` r  -> DataError
        | B.pack "Config error:" `B.isPrefixOf` r -> ConfigError
        | otherwise                        -> ProtocolError
    _ -> return ()

  log Notice "Starting TorDNSEL " VERSION "."
  conf <- do
    conf <- exitLeft Usage $ parseConfigArgs args
    case B.pack "configfile" `M.lookup` conf of
      Just fp -> do
        file <- catchIO (B.readFile $ B.unpack fp)
          (exitPrint NoInput . cat "Opening config file failed: ")
        exitLeft DataError $ makeConfig . M.union conf =<< parseConfigFile file
      Nothing -> exitLeft Usage $ makeConfig conf

  availFileDesc <- setMaxOpenFiles minFileDesc maxFileDesc
  random <- exitLeft OSFile =<< openRandomDevice
  seedPRNG random
  openSystemLogger "TorDNSEL" SysLogOptions { noDelay = True, logPid = True }
                   Daemon

  euid <- getEffectiveUserID
  when (any (isJust . ($ conf)) [cfUser, cfGroup, cfChangeRootDirectory] &&
        euid /= 0) $
    exitPrint NoPermission ("You must be root to drop privileges or chroot." ++)

  ids <- catchIO
    (getIDs (cfUser conf) (cfGroup conf))
    (exitPrint OSFile . cat "Looking up uid/gid failed: ")

  catchIO
    (checkDirectory (fst ids) (cfChangeRootDirectory conf)
                    (cfStateDirectory conf))
    (exitPrint Can'tCreate . cat "Preparing state directory failed: ")

  catchIO
    (checkDirectory Nothing Nothing (cfRuntimeDirectory conf))
    (exitPrint Can'tCreate . cat "Preparing runtime directory failed: ")

  statsSock <- catchIO
    (bindStatsSocket $ cfRuntimeDirectory conf)
    (exitPrint Can'tCreate . cat "Opening statistics listener failed: ")

  reconfigSock <- catchIO
    (bindReconfigSocket (cfRuntimeDirectory conf) (fst ids))
    (exitPrint Can'tCreate . cat "Opening reconfigure listener failed: ")

  pidHandle <- catchIO
    (flip openFile WriteMode `liftMb` cfPIDFile conf)
    (exitPrint Can'tCreate . cat "Opening PID file failed: ")

  log Notice "Opening DNS listener on " (cfDNSListenAddress conf) '.'
  dnsSock <- catchIO
    (bindUDPSocket $ cfDNSListenAddress conf)
    (\e -> exitPrint (bindErrorCode e) $
             cat "Opening DNS listener on " (cfDNSListenAddress conf)
                 " failed: " e)

  httpSock <- case cfHTTPListenAddress conf of
    Nothing -> return Nothing
    Just addr -> do
      log Notice "Opening HTTP listener on " addr '.'
      fmap Just . catchIO (bindListeningTCPSocket addr) $ \e ->
        exitPrint (bindErrorCode e) $
          cat "Opening HTTP listener on " addr " failed: " e

  testListeners <- case cfTestConfig conf of
    Nothing -> return M.empty
    Just testConf ->
      fmap M.fromList . forM (snd $ tcfTestListenAddress testConf) $ \port -> do
        let sockAddr = SockAddrInet (fromIntegral port)
                                   (htonl . fst $ tcfTestListenAddress testConf)
        log Notice "Opening exit test listener on " sockAddr '.'
        sock <- catchIO
         (bindListeningTCPSocket sockAddr)
         (\e -> exitPrint (bindErrorCode e) $
                  cat "Opening exit test listener on " sockAddr " failed: " e)
        return (sockAddr, Just sock)

  -- We lose any other running threads when we 'forkProcess', so don't 'forkIO'
  -- before this point.
  (if cfRunAsDaemon conf then daemonize else id) .
    withLinksDo $ do

    whenJust pidHandle $ \handle -> do
      hPutStrLn handle . show =<< getProcessID
      hClose handle

    whenJust (cfChangeRootDirectory conf) $ \dir -> do
      changeRootDirectory dir
      setCurrentDirectory "/"

    dropPrivileges ids

    let static = StaticState availFileDesc random statsSock reconfigSock
    runMainThread static testListeners dnsSock httpSock conf

-- | Given the command line arguments, check whether config options provided on
-- the command line and in an optional config file are well-formed. If they are,
-- exit with a successful status code. Otherwise, print an error message to
-- stderr and exit with an appropriate error code.
verifyConfig :: [String] -> IO a
verifyConfig args =
  case parseConfigArgs args of
    Left e -> exitStdErr Usage e
    Right conf ->
      case B.pack "configfile" `M.lookup` conf of
        Just fp -> do
          file <- catchIO (B.readFile $ B.unpack fp) $ \e -> do
            hCat stderr "Opening config file failed: " e '\n'
            exitWith $ fromSysExitCode NoInput
          check DataError $ parseConfigFile file >>= makeConfig . M.union conf
        Nothing -> check Usage $ makeConfig conf
  where
    exitStdErr code e = hCat stderr e '\n' >> exitWith (fromSysExitCode code)
    check code = either (exitStdErr code) (const $ exitWith ExitSuccess)

-- | Install signal handlers, start children of the main thread, and enter the
-- main message-processing loop. Exit if we fail to start any threads.
runMainThread :: StaticState -> Map SockAddr (Maybe Socket) -> Socket
              -> Maybe Socket -> Config -> IO ()
runMainThread static initTestListeners initDNSListener initHTTPListener
              initConf = do
  mainChan <- newChan
  setTrapExit $ (writeChan mainChan .) . Exit

  installHandler sigPIPE Ignore Nothing
  let hupHandler = writeChan mainChan (Reconfigure Nothing)
      termHandler = writeChan mainChan . Terminate
  installHandler sigHUP (Catch hupHandler) Nothing
  installHandler sigINT (Catch $ termHandler sigINT) Nothing

  initState <-
    E.handle (\(e :: E.SomeException) -> do
      log Error "Starting failed: " e
      terminateLogger Nothing
      closeSystemLogger
      exitWith $ fromSysExitCode ConfigError) $ do

    initLogger <- initializeLogger initConf
    whenJust (cfChangeRootDirectory initConf) $ \dir ->
      log Notice "Chrooted in " (esc 256 $ B.pack dir) '.'
    when (any (isJust . ($ initConf)) [cfUser, cfGroup]) $
      log Notice "Dropped privileges to " (fromMaybe "" $ cfUser initConf) ':'
                 (fromMaybe "" $ cfGroup initConf) '.'
    initReconfig <- startReconfigServer (reconfigSocket static)
                      (((writeChan mainChan . Reconfigure) .) . curry Just)
    let cleanup = terminateReconfigServer Nothing initReconfig
    stats <- startStatsServer (statsSocket static) `E.onException` cleanup
    let cleanup' = cleanup >> terminateStatsServer Nothing stats
    netState <- initializeNetworkStateManager
                  (mkExitTestConfig static initTestListeners initConf) initConf
      `E.onException` cleanup'
    dns <- startDNSServer (mkDNSServerConfig initDNSListener initConf)
    web <- (startWebServer . mkWebConfig initConf) `liftMb` initHTTPListener
    return $ State (Just initLogger) (Just initReconfig) (Just stats) netState
                   dns initTestListeners initDNSListener web initHTTPListener
                   S.empty

  log Notice "Successfully initialized all main subsystems. If no warnings "
             "appear above, it looks like everything is working."
  installHandler sigTERM (Catch $ termHandler sigTERM) Nothing
  flip fix (initConf, initState) $ \loop (!conf,!s) ->
    readChan mainChan >>= handleMessage mainChan static conf s >>= loop

-- | Process a 'MainThreadMessage', returning a new config and state.
handleMessage :: Chan MainThreadMessage -> StaticState -> Config -> State
              -> MainThreadMessage -> IO (Config, State)
handleMessage _ static conf s (Reconfigure reconf) = flip runStateT s $ do
  (mbNewConf,respond) <- case reconf of
    Just (newConf, respond) -> do
      log Notice "Reloaded config from reconfigure socket."
      return (Just newConf, respond)
    Nothing
      | Just configFile <- cfConfigFile conf -> do
          log Notice "Caught SIGHUP. Reloading config file."
          r <- liftIO . E.try $ B.readFile configFile
          case r of
            Left (e :: E.IOException) -> do
              -- If we're chrooted, it's not suprising that we can't read our
              -- config file.
              when (isNothing $ cfChangeRootDirectory conf) $
                log Warn "Reading config file failed: " e '.'
              return (Nothing, const $ return ())
            Right file ->
              case parseConfigFile file >>= makeConfig of
                Left e -> do
                  log Warn "Parsing config file failed: " e '.'
                  return (Nothing, const $ return ())
                Right newConf -> return (Just newConf, const $ return ())
      | otherwise -> return (Nothing, const $ return ())
  let errorRespond msg = liftIO $ respond (Just msg) >> log Error msg
  case mbNewConf of
    Nothing
      | Just logger' <- logger s, ToFile _ <- logTarget (cfLogConfig conf) -> do
          -- Close and re-open the log file to allow for log rotation.
          r <- liftIO . E.tryJust syncExceptions $ reconfigureLogger id
          case r of
            Left _ -> modify' $ \s' ->
                        s' { logger = Nothing
                           , deadThreads = S.insert (threadId logger')
                                                    (deadThreads s') }
            Right _ -> return ()
          return conf
      | otherwise -> return conf
    Just newConf -> do
      let changedStatic = staticConfigOptionsChanged conf newConf
      when (not $ null changedStatic) $
        log Notice "Ignoring changed values for static config options "
                   (concat $ intersperse ", " changedStatic) '.'
      let newConf' = copyStaticConfigOptions conf newConf

      when (cfStateDirectory conf /= cfStateDirectory newConf') $
        liftIO $ checkDirectory Nothing Nothing (cfStateDirectory newConf')
          `catchIO` \e -> do
            errorRespond $ cat "Preparing new state directory failed: " e
                               "; exiting gracefully."
            terminateProcess Can'tCreate static s Nothing

      reconfigureOrRestartLogger newConf'
      reconfigureListenersAndNetworkStateManager static newConf' errorRespond
      reconfigureDNSListenerAndServer static conf newConf' errorRespond
      reconfigureHTTPListenerAndServer static conf newConf' errorRespond
      liftIO $ respond Nothing
      return newConf'

handleMessage _mainChan static _conf s (Terminate signal) = do
  log Notice "Caught signal (" signalStr "); exiting gracefully."
  terminateProcess OK static s $
    if signal == sigINT
      then Nothing
      else Just exitWaitPeriod
  where
    signalStr | signal == sigINT  = "SIGINT"
              | signal == sigTERM = "SIGTERM"
              | otherwise         = show signal
    exitWaitPeriod = 2 * 10^6

handleMessage mainChan static conf s (Exit tid reason)
  | deadThreadIs logger = do
      (r,dead) <- tryForkLinkIO $ initializeLogger conf
      mbNewLogger <- case r of
        Left _ -> return Nothing
        Right newLogger -> do
          log Warn "The logger thread exited unexpectedly: "
                   (show reason) "; restarted."
          return $ Just newLogger
      return (conf, s { logger = mbNewLogger
                      , deadThreads = S.insert dead (deadThreads s) })
  | deadThreadIs reconfigServer = do
      log Warn "The reconfigure server thread exited unexpectedly: "
               (show reason) "; restarting."
      (r,dead) <- tryForkLinkIO $ startReconfigServer (reconfigSocket static)
                           (((writeChan mainChan . Reconfigure) .) . curry Just)
      mbNewReconfigServer <- case r of
        Left e -> do
          log Warn "Restarting reconfigure server failed: "
                   (show e) "; disabling reconfigure server."
          return Nothing
        Right newReconfigServer -> return $ Just newReconfigServer
      return (conf, s { reconfigServer = mbNewReconfigServer
                      , deadThreads = S.insert dead (deadThreads s) })
  | deadThreadIs statsServer = do
      log Warn "The statistics server thread exited unexpectedly: "
               (show reason) "; restarting."
      (r,dead) <- tryForkLinkIO . startStatsServer $ statsSocket static
      mbNewStatsServer <- case r of
        Left e -> do
          log Warn "Restarting statistics server failed: " (show e)
                   "; disabling statistics server."
          return Nothing
        Right newStatsServer -> return $ Just newStatsServer
      return (conf, s { statsServer = mbNewStatsServer
                      , deadThreads = S.insert dead (deadThreads s) })
  | tid == threadId (networkStateManager s) = do
      log Warn "The network state manager thread exited unexpectedly: "
               (show reason) "; restarting."
      newManager <- initializeNetworkStateManager
                      (mkExitTestConfig static (exitTestListeners s) conf) conf
        `E.catch` \(e :: E.SomeException) -> do
          log Error "Restarting network state manager failed: " e
                    "; exiting gracefully."
          terminateProcess Internal static s Nothing
      return (conf, s { networkStateManager = newManager })
  | tid == threadId (dnsServer s) = do
      log Warn "The DNS server thread exited unexpectedly: "
               (show reason) "; restarting."
      newDNSServer <- startDNSServer $ mkDNSServerConfig (dnsListener s) conf
      return (conf, s { dnsServer = newDNSServer })
  | Just web <- webServer s, tid == threadId web
  , Just sock <- httpListener s = do
      log Warn "The web server thread exited unexpectedly: "
               (show reason) "; restarting."
      newWebServer <- startWebServer $ mkWebConfig conf sock
      return (conf, s { webServer = Just newWebServer })
  | tid `S.member` deadThreads s
  = return (conf, s { deadThreads = S.delete tid (deadThreads s) })
  | otherwise = do
      log Warn "Bug: Received unexpected exit signal: "
               (show reason)
      return (conf, s)
  where deadThreadIs thr = ((tid ==) . threadId) `fmap` thr s == Just True

-- | Return the DNS server config given a listening DNS socket and the 'Config'.
mkDNSServerConfig :: Socket -> Config -> DNSConfig
mkDNSServerConfig dnsSock conf =
  DNSConfig
    { dnsSocket = dnsSock
    , dnsAuthZone = DomainName $ reverse authLabels
    , dnsMyName = cfDomainName conf
    , dnsSOA = SOA (cfZoneOfAuthority conf) ttl (cfDomainName conf)
                   (cfSOARName conf) 0 ttl ttl ttl ttl
    , dnsNS = NS (cfZoneOfAuthority conf) ttl (cfDomainName conf)
    , dnsA = A (cfZoneOfAuthority conf) ttl `fmap` cfAddress conf
    , dnsLists = cfExitLists conf
    , dnsByteStats = incrementBytes
    , dnsRespStats = incrementResponses }
  where DomainName authLabels = cfZoneOfAuthority conf

-- | Return the web interface config given the listening HTTP socket.
mkWebConfig :: Config -> Socket -> WebConfig
mkWebConfig conf sock = WebConfig
  { webSocket = sock
  , webLists = cfExitLists conf
  , webPublicAddress = cfHTTPPublicAddress conf
  , webRequestStats = incrementHTTPRequests }

-- | Return the exit test config.
mkExitTestConfig :: StaticState -> Map SockAddr (Maybe Socket) -> Config
                 -> TestConfig -> ExitTestConfig
mkExitTestConfig static testListeners conf testConf =
  ExitTestConfig
    { etcfListeners = testListeners
    , etcfConcClientLimit = (availableFileDesc static - extraFileDesc) `div` 2
    , etcfGetRandBytes = randBytes $ randomHandle static
    , etcfTorSocksAddr = cfTorSocksAddress conf
    , etcfTestAddress = fst $ tcfTestDestinationAddress testConf
    , etcfTestPorts = snd $ tcfTestDestinationAddress testConf }

-- | Start the logger thread, resetting the log target or disabling logging if
-- necessary.
initializeLogger :: Config -> IO Logger
initializeLogger conf = do
  newLogTarget <- checkLogTarget . logTarget . cfLogConfig $ conf
  let newLogConfig = (cfLogConfig conf) { logTarget = newLogTarget }
  if cfRunAsDaemon conf && any (newLogTarget ==) [ToStdOut, ToStdErr]
    then startLogger newLogConfig { logEnabled = False }
    else startLogger newLogConfig

-- | Start the network state manager thread.
initializeNetworkStateManager
  :: (TestConfig -> ExitTestConfig) -> Config -> IO NetworkStateManager
initializeNetworkStateManager exitTestConfig conf = do
  startNetworkStateManager NetworkStateManagerConfig
    { nsmcfTorControlAddr = cfTorControlAddress conf
    , nsmcfTorControlPasswd = cfTorControlPassword conf
    , nsmcfStateDir = cfStateDirectory conf
    , nsmcfExitTestConfig = exitTestConfig `fmap` cfTestConfig conf }

-- | Reconfigure the logger if it's running, or attempt to restart it if it's
-- not running, given the new config.
reconfigureOrRestartLogger :: Config -> StateT State IO ()
reconfigureOrRestartLogger conf = do
  s <- get
  case logger s of
    Just logger' -> do
      logConf <- if cfRunAsDaemon conf &&
        any (logTarget (cfLogConfig conf) ==) [ToStdOut, ToStdErr]
        then do
          log Warn "Cannot log to " (logTarget $ cfLogConfig conf)
                   " when daemonized. Disabling logging."
          return (cfLogConfig conf) { logEnabled = False }
        else return $ cfLogConfig conf
      r <- liftIO . E.tryJust syncExceptions $ reconfigureLogger (const logConf)
      case r of
        Left _ -> put $! s { logger = Nothing
                           , deadThreads = S.insert (threadId logger')
                                                    (deadThreads s) }
        Right _ -> return ()
    Nothing -> do
      (r,dead) <- liftIO . tryForkLinkIO $ initializeLogger conf
      let mbNewLogger = either (const Nothing) Just r
      put $! s { logger = mbNewLogger
               , deadThreads = S.insert dead (deadThreads s) }

-- | Reconfigure the exit test listeners and network state manager.
reconfigureListenersAndNetworkStateManager
  :: StaticState -> Config -> (String -> StateT State IO ())
  -> StateT State IO ()
reconfigureListenersAndNetworkStateManager static conf errorRespond = do
  s <- get
  let (mbNewListeners,newListenerMap) = updateListeners s
  r <- liftIO . E.tryJust syncExceptions $
         reconfigureNetworkStateManager
           (\c -> c { nsmcfTorControlAddr = cfTorControlAddress conf
                    , nsmcfTorControlPasswd = cfTorControlPassword conf
                    , nsmcfStateDir = cfStateDirectory conf
                    , nsmcfExitTestConfig =
                        mkExitTestConfig static newListenerMap conf
                          `fmap` cfTestConfig conf })
           (networkStateManager s)
  case r of
    Left e -> do
      errorRespond $ cat "Reconfiguring network state manager failed: " e
                         "; exiting gracefully."
      get >>= liftIO . flip (terminateProcess ConfigError static) Nothing
    Right _ -> do
      put $! s { exitTestListeners = newListenerMap }
      whenJust mbNewListeners $ \newListeners ->
        forM_ (M.assocs $ exitTestListeners s `M.difference` newListeners) $
          \(addr,mbSock) -> whenJust mbSock $ \sock -> do
            log Notice "Closing exit test listener on " addr '.'
            liftIO $ closeSocket sock
  where
    updateListeners s =
      case cfTestConfig conf of
        Just testConf ->
          let addr = htonl . fst $ tcfTestListenAddress testConf
              newListeners = M.fromList $
                map (\port -> (SockAddrInet (fromIntegral port) addr, Nothing))
                    (snd $ tcfTestListenAddress testConf)
          in ( Just newListeners
             , M.intersection (exitTestListeners s) newListeners
                 `M.union` newListeners )
        Nothing -> (Nothing, exitTestListeners s)

-- | Reconfigure the DNS server, and the DNS listener if necessary.
reconfigureDNSListenerAndServer
  :: StaticState -> Config -> Config -> (String -> StateT State IO ())
  -> StateT State IO ()
reconfigureDNSListenerAndServer static oldConf newConf errorRespond = do
  when (cfDNSListenAddress oldConf /= cfDNSListenAddress newConf) $ do
    log Notice "Opening DNS listener on " (cfDNSListenAddress newConf) '.'
    r <- liftIO . E.try $ bindUDPSocket $ cfDNSListenAddress newConf
    case r of
      Left (e :: E.IOException) -> do
        errorRespond $
          cat "Opening DNS listener on " (cfDNSListenAddress newConf)
              " failed: " e "; exiting gracefully."
        s <- get
        liftIO $ terminateProcess (bindErrorCode e) static s Nothing
      Right sock -> do
        log Notice "Closing DNS listener on " (cfDNSListenAddress oldConf) '.'
        modify' $ \s -> s { dnsListener = sock }
  s <- get
  r <- liftIO . E.tryJust syncExceptions $
          reconfigureDNSServer
            (const $ mkDNSServerConfig (dnsListener s) newConf) (dnsServer s)
  case r of
    Left e -> do
      errorRespond $ cat "Reconfiguring DNS Server failed: " e
                         "; exiting gracefully."
      get >>= liftIO . flip (terminateProcess IOError static) Nothing
    Right _ -> return ()

-- | Start, stop, or reconfigure the web interface and its listener according
-- to the new config.
reconfigureHTTPListenerAndServer
  :: StaticState -> Config -> Config -> (String -> StateT State IO ())
  -> StateT State IO ()
reconfigureHTTPListenerAndServer static oldConf newConf errorRespond = do
  s <- get
  case (cfHTTPListenAddress newConf, httpListener s, webServer s) of
    -- disabled
    (Nothing, mbSock, mbWeb) -> do
      whenJust mbWeb $ \web -> do
        liftIO $ terminateWebServer Nothing web
        modify' $ \s' -> s' { deadThreads = S.insert (threadId web)
                                                     (deadThreads s') }
      whenJust mbSock $ \sock -> do
        log Notice "Closing HTTP listener."
        liftIO . ignoreIOExn $ closeSocket sock
      modify' $ \s' -> s' { webServer = Nothing, httpListener = Nothing }
    -- enabled, possibly on a new address
    (Just addr, mbSock, mbWeb) -> do
      sock <- case mbSock of
        Just sock | cfHTTPListenAddress oldConf == Just addr -> return sock
        _ -> do
          log Notice "Opening HTTP listener on " addr '.'
          r <- liftIO . E.try $ bindListeningTCPSocket addr
          case r of
            Left (e :: E.IOException) -> do
              errorRespond $ cat "Opening HTTP listener on " addr
                                 " failed: " e "; exiting gracefully."
              get >>= \s' -> liftIO $ terminateProcess (bindErrorCode e)
                                                       static s' Nothing
            Right sock -> do
              -- An old web server closes its old listener when reconfigured
              -- with the new one; without a server, close it ourselves.
              when (isNothing mbWeb) $
                whenJust mbSock $ liftIO . ignoreIOExn . closeSocket
              return sock
      case mbWeb of
        Nothing -> do
          web <- liftIO . startWebServer $ mkWebConfig newConf sock
          modify' $ \s' -> s' { webServer = Just web, httpListener = Just sock }
        Just web -> do
          r <- liftIO . E.tryJust syncExceptions $
                 reconfigureWebServer (const $ mkWebConfig newConf sock) web
          case r of
            Left e -> do
              errorRespond $ cat "Reconfiguring web server failed: " e
                                 "; exiting gracefully."
              get >>= liftIO . flip (terminateProcess IOError static) Nothing
            Right _ -> modify' $ \s' -> s' { httpListener = Just sock }
  where
    ignoreIOExn = (`catchIO` \_ -> return ())

-- | Terminate the process by first asking all our linked, child threads to
-- terminate gracefully, then releasing the resources held in 'StaticState'.
terminateProcess :: SysExitCode -> StaticState -> State -> Maybe Int -> IO a
terminateProcess status static s mbWait = do
  whenJust (reconfigServer s) (terminateReconfigServer mbWait)
  terminateNetworkStateManager mbWait $ networkStateManager s
  terminateDNSServer mbWait $ dnsServer s
  whenJust (webServer s) (terminateWebServer mbWait)
  whenJust (statsServer s) (terminateStatsServer mbWait)
  forM_ (M.assocs $ exitTestListeners s) $ \(addr,mbSock) ->
    whenJust mbSock $ \sock -> do
      log Info "Closing exit test listener on " addr '.'
      ignoreIOExn $ closeSocket sock
  log Info "Closing DNS listener."
  ignoreIOExn . closeSocket $ dnsListener s
  whenJust (httpListener s) $ \sock -> do
    log Info "Closing HTTP listener."
    ignoreIOExn $ closeSocket sock
  log Info "Closing statistics listener."
  ignoreIOExn . closeSocket $ statsSocket static
  log Info "Closing reconfigure listener."
  ignoreIOExn . closeSocket $ reconfigSocket static
  ignoreIOExn . hClose $ randomHandle static
  log Notice "All subsystems have terminated. Exiting now."
  terminateLogger mbWait
  closeSystemLogger
  exitWith $ fromSysExitCode status
  where
    ignoreIOExn = (`catchIO` \_ -> return ())

--------------------------------------------------------------------------------
-- Daemon operations

-- | Lookup the UID and GID for a pair of user and group names.
getIDs :: Maybe String -> Maybe String -> IO (Maybe UserID, Maybe GroupID)
getIDs user group = do
  userEntry <- getUserEntryForName `liftMb` user
  groupEntry <- getGroupEntryForName `liftMb` group
  return (userID `fmap` userEntry, groupID `fmap` groupEntry)

-- | Drop privileges to the given UID\/GID pair.
dropPrivileges :: (Maybe UserID, Maybe GroupID) -> IO ()
dropPrivileges (uid,gid) = do
  whenJust gid setGroupID
  whenJust uid setUserID

-- | Call chroot(2) using the given directory path. Throws an 'IOError' if the
-- call fails.
changeRootDirectory :: FilePath -> IO ()
changeRootDirectory dir =
  withCString dir $ \s ->
    throwErrnoPathIfMinus1_ "changeRootDirectory" dir (c_chroot s)

-- | Run an IO action as a daemon. This action doesn't return.
daemonize :: IO () -> IO ()
daemonize io = do
  forkProcess $ do
    createSession
    forkProcess $ do
      setCurrentDirectory "/"
      mapM_ closeFd stdFds
#if MIN_VERSION_unix(2,8,0)
      nullFd <- openFd "/dev/null" ReadWrite defaultFileFlags
#else
      nullFd <- openFd "/dev/null" ReadWrite Nothing defaultFileFlags
#endif
      mapM_ (dupTo nullFd) stdFds
      closeFd nullFd
      io
    exitImmediately ExitSuccess
  exitImmediately ExitSuccess
  where stdFds = [stdInput, stdOutput, stdError]

--------------------------------------------------------------------------------
-- Helpers

-- | Ensure that the current limit on open file descriptors is at least
-- @lowerLimit@, raising the soft limit (and the hard limit, if we're root) to
-- at most @cap@. Return the new current limit.
--
-- With the threaded RTS, GHC's I\/O manager uses epoll(7)\/kqueue(2), so the
-- old FD_SETSIZE restriction of the select(2)-based non-threaded RTS only
-- applies when we were linked without @-threaded@.
setMaxOpenFiles :: Integer -> Integer -> IO Integer
setMaxOpenFiles lowerLimit cap0 = do
  euid <- getEffectiveUserID
  limits <- getResourceLimit ResourceOpenFiles
  let fdSetSize = #{const FD_SETSIZE} :: Integer
      cap | rtsSupportsBoundThreads = cap0
          | otherwise               = cap0 `min` fdSetSize
      hard = limitValue (hardLimit limits)

  when (euid /= 0 && maybe False (< lowerLimit) hard) $
    exitPrint NoPermission $
      cat "The hard limit on file descriptors is set to "
          (showLimit $ hardLimit limits) ", but we need at least "
          lowerLimit '.'
  when (cap < lowerLimit) $
    exitPrint Internal $
      cat "FD_SETSIZE is " fdSetSize ", but we need at least " lowerLimit
          " file descriptors."

  let newLimits limit
        | euid /= 0 = limits { softLimit = ResourceLimit limit }
        | otherwise = limits { softLimit = ResourceLimit limit
                             , hardLimit = ResourceLimit limit }
      most | euid /= 0 = maybe cap (min cap) hard
           | otherwise = cap

  catchIO
    (setResourceLimit ResourceOpenFiles (newLimits most) >> return most) $ \e ->
    do
#ifdef OPEN_MAX
      -- For macOS, where the kernel refuses limits above OPEN_MAX.
      let openMax = #{const OPEN_MAX} :: Integer
      if not (isPermissionError e) && openMax < most
        then do setResourceLimit ResourceOpenFiles (newLimits openMax)
                return openMax
        else E.throwIO e
#else
      E.throwIO e
#endif
  where
    limitValue (ResourceLimit n) = Just n
    limitValue _                 = Nothing
    showLimit (ResourceLimit n)    = show n
    showLimit ResourceLimitInfinity = "infinity"
    showLimit ResourceLimitUnknown  = "unknown"

-- | Set up the state or runtime directory with proper ownership and
-- permissions.
checkDirectory :: Maybe UserID -> Maybe FilePath -> FilePath -> IO ()
checkDirectory uid newRoot path = do
  createDirectoryIfMissing True fullPath
  desiredUID <- maybe getEffectiveUserID return uid
  st <- getFileStatus fullPath
  when (fileOwner st /= desiredUID) $
    setOwnerAndGroup fullPath desiredUID (-1)
  when (fileMode st .&. 0o700 /= 0o700) $
    setFileMode fullPath (fileMode st .|. 0o700)
  where fullPath = maybe id ((++) . (++ "/")) newRoot path

-- | Check if the log target can be used. If it can, return it. Otherwise,
-- return 'ToStdOut'.
checkLogTarget :: LogTarget -> IO LogTarget
checkLogTarget target@(ToFile logPath) =
  E.bracket (openFile logPath AppendMode) hClose (\_ -> return target)
    `catchIO` (\_ -> return ToStdOut)
checkLogTarget target = return target

-- | System exit status codes from sysexits.h.
data SysExitCode
  = OK            -- ^ Successful termination
  | Usage         -- ^ Command line usage error
  | DataError     -- ^ Data format error
  | NoInput       -- ^ Cannot open input
  | NoUser        -- ^ Addressee unknown
  | NoHost        -- ^ Host name unknown
  | Unavailable   -- ^ Service unavailable
  | Internal      -- ^ Internal software error
  | OSError       -- ^ System error (e.g., can't fork)
  | OSFile        -- ^ Critical OS file missing
  | Can'tCreate   -- ^ Can't create (user) output file
  | IOError       -- ^ Input/output error
  | TempFailure   -- ^ Temp failure; user is invited to retry
  | ProtocolError -- ^ Remote error in protocol
  | NoPermission  -- ^ Permission denied
  | ConfigError   -- ^ Configuration error

-- | Convert a system exit status code to an 'ExitCode' for 'exitWith'.
fromSysExitCode :: SysExitCode -> ExitCode
fromSysExitCode status = case status of
  OK            -> ExitSuccess
  Usage         -> ExitFailure #{const EX_USAGE}
  DataError     -> ExitFailure #{const EX_DATAERR}
  NoInput       -> ExitFailure #{const EX_NOINPUT}
  NoUser        -> ExitFailure #{const EX_NOUSER}
  NoHost        -> ExitFailure #{const EX_NOHOST}
  Unavailable   -> ExitFailure #{const EX_UNAVAILABLE}
  Internal      -> ExitFailure #{const EX_SOFTWARE}
  OSError       -> ExitFailure #{const EX_OSERR}
  OSFile        -> ExitFailure #{const EX_OSFILE}
  Can'tCreate   -> ExitFailure #{const EX_CANTCREAT}
  IOError       -> ExitFailure #{const EX_IOERR}
  TempFailure   -> ExitFailure #{const EX_TEMPFAIL}
  ProtocolError -> ExitFailure #{const EX_PROTOCOL}
  NoPermission  -> ExitFailure #{const EX_NOPERM}
  ConfigError   -> ExitFailure #{const EX_CONFIG}

-- | Return the system exit code corresponding to an 'IOError' generated by the
-- failure to open a listening socket.
bindErrorCode :: IOError -> SysExitCode
bindErrorCode e | isPermissionError e = NoPermission
                | otherwise           = OSError

-- | Lift an @Either ShowS@ computation into the 'IO' monad by logging @Left e@
-- as an error message and exiting.
exitLeft :: SysExitCode -> Either ShowS a -> IO a
exitLeft status = either (exitPrint status) return

-- | Print the given string as an error message and exit with the given status.
exitPrint :: SysExitCode -> ShowS -> IO a
exitPrint status msg = do
  log Error msg
  exitUsage stderr $ fromSysExitCode status

-- | Lift a 'Maybe' into a monadic action.
liftMb :: Monad m => (a -> m b) -> Maybe a -> m (Maybe b)
liftMb f = maybe (return Nothing) (liftM Just . f)

infixr 8 `liftMb`

-- | Specialization of 'E.catch' for 'E.IOException'.
catchIO :: IO a -> (E.IOException -> IO a) -> IO a
catchIO = E.catch

foreign import ccall unsafe "unistd.h chroot"
  c_chroot :: CString -> IO CInt
