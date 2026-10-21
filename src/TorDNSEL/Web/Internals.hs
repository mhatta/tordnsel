-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Web.Internals
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : Masayuki Hatta <mhatta@mhatta.org>
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions)
--
-- /Internals/: should only be imported by the public module and tests.
--
-- The web interface. @doc/torel-design.md@ says it \"should provide the same
-- data as the dns interface\", so each DNS query type has an HTTP equivalent
-- returning JSON, and the exit list can also be fetched in bulk:
--
-- [@GET \/api\/v1\/ip-port?ip=IP1&port=PORT&dest=IP2@]
--   Query type 1: is IP1 a Tor exit that permits connections to PORT on IP2?
--
-- [@GET \/api\/v1\/list?ip=IP&list=NAME@]
--   Query type 2: is IP a Tor exit that permits connections to any member of
--   the configured list NAME? (@GET \/api\/v1\/lists@ shows the lists.)
--
-- [@GET \/api\/v1\/me?ip=IP&port=PORT@]
--   Query type 3: is IP a Tor exit that permits connections to PORT on the
--   host making this HTTP request?
--
-- [@GET \/api\/ip@]
--   Is the host making this request connecting from a Tor exit (that permits
--   connections to this web server)? The JSON has the same shape as the one
--   returned by check.torproject.org's @\/api\/ip@.
--
-- [@GET \/torbulkexitlist?ip=IP&port=PORT@]
--   The addresses of all Tor exits permitting connections to IP:PORT, one per
--   line, compatible with check.torproject.org's @\/torbulkexitlist@. Without
--   parameters, every address from which some Tor exit may exit is listed.
--
-- [@GET \/exit-addresses@]
--   The results of our active exit tests, in the @exit-addresses@ format.
--
-- The server is deliberately small: HTTP\/1.1 with one request per
-- connection, @GET@ and @HEAD@ only. Put a reverse proxy in front of it if you
-- need TLS.
--
-----------------------------------------------------------------------------

-- #not-home
module TorDNSEL.Web.Internals (
  -- * Server
    WebConfig(..)
  , WebServer(..)
  , WebMessage(..)
  , startWebServer
  , reconfigureWebServer
  , terminateWebServer

  -- * Requests and responses
  , Request(..)
  , Response(..)
  , parseRequest
  , renderResponse
  , handleRequest
  , urlDecode
  , JSON(..)
  , renderJSON
  ) where

import Prelude hiding (log)
import Control.Concurrent.QSem (QSem, newQSem, waitQSem, signalQSem)
import qualified Control.Exception as E
import Control.Monad (when, forever, unless)
import Control.Monad.Fix (fix)
import qualified Data.ByteString.Char8 as B
import Data.ByteString (ByteString)
import Data.Char (chr, digitToInt, isHexDigit, toLower, isDigit)
import qualified Data.Map as M
import Data.Maybe (isNothing, mapMaybe)
import qualified Data.Set as S
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Network.Socket
  (Socket, SockAddr(..), HostAddress, accept, getSocketName)
import Network.Socket.ByteString (recv, sendAll)
import System.Timeout (timeout)

import TorDNSEL.Control.Concurrent.Link
import TorDNSEL.Control.Concurrent.Util
import TorDNSEL.ExitList
import TorDNSEL.Log
import TorDNSEL.NetworkState
import TorDNSEL.NetworkState.Storage (mkExitAddress, renderExitAddress)
import TorDNSEL.NetworkState.Types
import TorDNSEL.Util

--------------------------------------------------------------------------------
-- Server

-- | The web interface configuration.
data WebConfig = WebConfig
  { -- | The listening HTTP socket.
    webSocket        :: !Socket
    -- | Operator-configured lists of destinations for \"list\" queries.
  , webLists         :: !NamedLists
    -- | The address and port at which clients reach us, if it differs from
    -- the address we're listening on. Used by @\/api\/ip@.
  , webPublicAddress :: !(Maybe (HostAddress, Port))
    -- | Count requests for statistics.
  , webRequestStats  :: !(IO ())
  }

instance Eq WebConfig where
  x == y = webSocket x == webSocket y && webLists x == webLists y &&
           webPublicAddress x == webPublicAddress y

-- | A handle to the web server thread.
data WebServer = WebServer (WebMessage -> IO ()) ThreadId

instance Thread WebServer where
  threadId (WebServer _ tid) = tid

-- | Messages the web server thread can receive.
data WebMessage
  = NewClient Socket SockAddr -- ^ A new client has connected.
  | Reconfigure (WebConfig -> WebConfig) (IO ()) -- ^ Reconfigure the server.
  | Terminate ExitReason -- ^ Terminate the server gracefully.
  | Exit ThreadId ExitReason -- ^ An exit signal sent to the server.

-- | The server's state.
data WebState = WebState
  { webConf         :: !WebConfig
  , listenerTid     :: !ThreadId
  , handlers        :: !(S.Set ThreadId)
    -- | Listener threads we killed ourselves, whose exit signals we ignore.
  , deadListeners   :: !(S.Set ThreadId)
  , terminateReason :: !(Maybe ExitReason) }

-- | Start the web server with an initial config, returning a handle to it.
-- Link the server thread to the calling thread.
startWebServer :: WebConfig -> IO WebServer
startWebServer initConf = do
  log Info "Starting web server."
  chan <- newMsgChan
  sem <- newQSem maxHandlers
  tid <- forkLinkIO $ do
    setTrapExit $ (writeMsgChan chan .) . Exit
    initListener <- forkListener chan sem (webSocket initConf)
    flip fix (WebState initConf initListener S.empty S.empty Nothing) $
     \loop (!s) -> do
      message <- readMsgChan chan
      case message of
        NewClient client addr -> do
          let conf = webConf s
          handler <- forkLinkIO . (`E.finally` signalQSem sem) .
                       (`E.finally` closeSocket client) $ do
            webRequestStats conf
            r <- E.try . timeout handlerTimeout $ serveClient conf client addr
            case r of
              Left (e :: E.IOException) ->
                log Debug "Error serving web client " addr ": " e
              Right Nothing -> log Debug "Web client " addr " timed out."
              Right _ -> return ()
          loop s { handlers = S.insert handler (handlers s) }

        Reconfigure reconf signal -> do
          let newConf = reconf (webConf s)
          when (newConf /= webConf s) $
            log Notice "Reconfiguring web server."
          if webSocket newConf /= webSocket (webConf s)
            then do
              terminateThread Nothing (listenerTid s)
                              (killThread $ listenerTid s)
              closeSocket . webSocket $ webConf s
              newListener <- forkListener chan sem (webSocket newConf)
              signal
              loop s { webConf = newConf, listenerTid = newListener
                     , deadListeners = S.insert (listenerTid s)
                                                (deadListeners s) }
            else signal >> loop s { webConf = newConf }

        Terminate reason -> do
          log Info "Terminating web server."
          terminateThread Nothing (listenerTid s) (killThread $ listenerTid s)
          pending <- drainMsgChan chan
          sequence_ [closeSocket c | NewClient c _ <- pending]
          if S.null (handlers s)
            then exit reason
            else loop s { terminateReason = Just reason }

        Exit t reason
          | t == listenerTid s ->
              if isNothing (terminateReason s)
                then do
                  log Warn "The web listener thread exited unexpectedly: "
                           (show reason) "; restarting."
                  newListener <- forkListener chan sem (webSocket $ webConf s)
                  loop s { listenerTid = newListener }
                else loop s
          | t `S.member` deadListeners s ->
              loop s { deadListeners = S.delete t (deadListeners s) }
          | t `S.member` handlers s -> do
              let remaining = S.delete t (handlers s)
              case terminateReason s of
                Just r | S.null remaining -> exit r
                _ -> loop s { handlers = remaining }
          | isAbnormal reason -> exit reason
          | otherwise -> loop s

  return $ WebServer (writeMsgChan chan) tid
  where
    maxHandlers = 64
    handlerTimeout = 10 * 10^(6 :: Int)

-- | Fork the thread accepting connections on the listening socket.
forkListener :: MsgChan WebMessage -> QSem -> Socket -> IO ThreadId
forkListener chan sem sock =
  forkLinkIO $ E.mask $ \restore -> forever $ do
    waitQSem sem
    (client,addr) <- restore (accept sock) `E.onException` signalQSem sem
    writeMsgChan chan $ NewClient client addr

-- | Reconfigure the web server synchronously with the given function. If the
-- server exits abnormally before reconfiguring itself, throw its exit signal
-- in the calling thread.
reconfigureWebServer :: (WebConfig -> WebConfig) -> WebServer -> IO ()
reconfigureWebServer reconf (WebServer send tid) =
  sendSyncMessage (send . Reconfigure reconf) tid

-- | Terminate the web server gracefully. The optional parameter specifies the
-- amount of time in microseconds to wait for the thread to terminate. If the
-- thread hasn't terminated by the timeout, an uncatchable exit signal will be
-- sent.
terminateWebServer :: Maybe Int -> WebServer -> IO ()
terminateWebServer mbWait (WebServer send tid) =
  terminateThread mbWait tid (send $ Terminate NormalExit)

-- | Read a request from a client, answer it, and close the connection.
serveClient :: WebConfig -> Socket -> SockAddr -> IO ()
serveClient conf client clientAddr = do
  raw <- readRequestHead client
  response <- case raw >>= parseRequest of
    Nothing -> return $ errorResponse 400 "Bad Request" "malformed request"
    Just req -> do
      localAddr <- getSocketName client
      now <- getPOSIXTime
      ns <- readNetworkState
      return $ handleRequest conf now ns clientAddr localAddr req
  sendAll client $ renderResponse response

-- | Read the request line and headers, up to a limit.
readRequestHead :: Socket -> IO (Maybe ByteString)
readRequestHead sock = go B.empty
  where
    go acc
      | B.length acc > maxHeadLen = return Nothing
      | (front,rest) <- B.breakSubstring (B.pack "\r\n\r\n") acc
      , not (B.null rest) = return (Just front)
      | otherwise = do
          chunk <- recv sock 4096
          if B.null chunk
            then return Nothing
            else go (acc `B.append` chunk)
    maxHeadLen = 8192

--------------------------------------------------------------------------------
-- Requests and responses

-- | An HTTP request.
data Request = Request
  { reqMethod :: !ByteString               -- ^ The method, e.g. @GET@.
  , reqPath   :: !ByteString               -- ^ The decoded path.
  , reqQuery  :: ![(ByteString, ByteString)] -- ^ Decoded query parameters.
  } deriving (Eq, Show)

-- | An HTTP response.
data Response = Response
  { respStatus  :: !Int
  , respReason  :: !ByteString
  , respHeaders :: ![(ByteString, ByteString)]
  , respBody    :: !ByteString
  , respHead    :: !Bool -- ^ Omit the body (a response to @HEAD@).
  } deriving (Eq, Show)

-- | Parse the request line of an HTTP request. Headers are ignored.
parseRequest :: ByteString -> Maybe Request
parseRequest raw = case B.words requestLine of
  [method, target, version]
    | B.pack "HTTP/1." `B.isPrefixOf` version
    , B.pack "/" `B.isPrefixOf` target -> do
        let (path,query) = B.break (== '?') target
        path' <- urlDecode False path
        params <- mapM param . filter (not . B.null) . B.split '&' $
                    B.drop 1 query
        return $ Request method path' params
  _ -> Nothing
  where
    requestLine = B.takeWhile (\c -> c /= '\r' && c /= '\n') raw
    param p = do
      let (k,v) = B.break (== '=') p
      k' <- urlDecode True k
      v' <- urlDecode True (B.drop 1 v)
      return (k', v')

-- | Decode percent-encoded octets; with the flag set, also decode @+@ as a
-- space (as in query strings).
urlDecode :: Bool -> ByteString -> Maybe ByteString
urlDecode plusIsSpace = fmap B.pack . go . B.unpack
  where
    go ('%':a:b:rest)
      | isHexDigit a && isHexDigit b =
          (chr (digitToInt a * 16 + digitToInt b) :) `fmap` go rest
    go ('%':_) = Nothing
    go ('+':rest) | plusIsSpace = (' ' :) `fmap` go rest
    go (c:rest) = (c :) `fmap` go rest
    go [] = Just []

-- | Serialise a response, closing the connection afterwards.
renderResponse :: Response -> ByteString
renderResponse r = B.concat $
  [ B.pack "HTTP/1.1 ", B.pack (show $ respStatus r), B.pack " "
  , respReason r, crlf ] ++
  concat [ [k, B.pack ": ", v, crlf] | (k,v) <- headers ] ++
  [ crlf ] ++
  [ respBody r | not (respHead r) ]
  where
    crlf = B.pack "\r\n"
    headers = respHeaders r ++
      [ (B.pack "Content-Length", B.pack . show . B.length $ respBody r)
      , (B.pack "Connection", B.pack "close")
      , (B.pack "Server", B.pack "TorDNSEL") ]

-- | A minimal JSON value.
data JSON
  = JString ByteString
  | JNumber Integer
  | JBool Bool
  | JNull
  | JArray [JSON]
  | JObject [(ByteString, JSON)]
  deriving (Eq, Show)

-- | Render a JSON value.
renderJSON :: JSON -> ByteString
renderJSON = B.concat . go
  where
    go (JString s) = [quote s]
    go (JNumber n) = [B.pack $ show n]
    go (JBool b)   = [B.pack $ if b then "true" else "false"]
    go JNull       = [B.pack "null"]
    go (JArray xs) = [B.pack "["] ++ commaSep (map go xs) ++ [B.pack "]"]
    go (JObject kvs) =
      [B.pack "{"] ++
      commaSep [quote k : B.pack ":" : go v | (k,v) <- kvs] ++
      [B.pack "}"]
    commaSep = concat . sepBy [B.pack ","]
    sepBy _ []     = []
    sepBy _ [x]    = [x]
    sepBy s (x:xs) = x : s : sepBy s xs
    quote s = B.concat [B.pack "\"", B.concatMap escapeChar s, B.pack "\""]
    escapeChar c
      | c == '"'  = B.pack "\\\""
      | c == '\\' = B.pack "\\\\"
      | c < ' ' || c == '\DEL' =
          B.pack $ "\\u00" ++ [hexDigit (fromEnum c `div` 16),
                               hexDigit (fromEnum c `mod` 16)]
      | otherwise = B.singleton c
    hexDigit n = "0123456789abcdef" !! n

-- | Answer a request given the current time and network state, the address
-- of the client and the local address of the connection.
handleRequest :: WebConfig -> POSIXTime -> NetworkState -> SockAddr -> SockAddr
              -> Request -> Response
handleRequest conf now ns clientAddr localAddr req
  | method `notElem` [B.pack "GET", B.pack "HEAD"] =
      (errorResponse 405 "Method Not Allowed" "only GET and HEAD are supported")
        { respHeaders = [ (B.pack "Allow", B.pack "GET, HEAD")
                        , contentType "application/json" ] }
  | otherwise = (route $ B.unpack path) { respHead = method == B.pack "HEAD" }
  where
    method = reqMethod req
    path = reqPath req
    params = reqQuery req
    lists = webLists conf

    route "/" = textResponse 200 cacheLong helpText
    route "/api/v1/ip-port" = either badRequest id $ do
      qAddr <- addrParam "ip"
      dAddr <- addrParam "dest"
      port <- portParam "port"
      return . jsonResponse cacheLong $ JObject
        [ (B.pack "query", JString $ B.pack "ip-port")
        , (B.pack "ip", showAddr qAddr)
        , (B.pack "dest", showAddr dAddr)
        , (B.pack "port", JNumber $ toInteger port)
        , (B.pack "listed", JBool $ listed qAddr (DestAddrPort dAddr port)) ]
    route "/api/v1/list" = either badRequest id $ do
      qAddr <- addrParam "ip"
      name <- B.map toLower `fmap` textParam "list"
      case M.lookup name lists of
        Nothing -> Left (404, B.pack "Not Found", B.pack "no such list")
        Just pats -> return . jsonResponse cacheLong $ JObject
          [ (B.pack "query", JString $ B.pack "list")
          , (B.pack "ip", showAddr qAddr)
          , (B.pack "list", JString name)
          , (B.pack "listed", JBool $ listed qAddr (DestAnyOf pats)) ]
    route "/api/v1/lists" = jsonResponse cacheLong $ JObject
      [ (name, JArray [JString . B.pack $ showAddrPortPattern p | p <- pats])
      | (name,pats) <- M.toAscList lists ]
    route "/api/v1/me" = either badRequest id $ do
      qAddr <- addrParam "ip"
      port <- portParam "port"
      let isListed = maybe False (\a -> listed qAddr (DestAddrPort a port))
                           (ipv4Of clientAddr)
      return . jsonResponse noCache $ JObject
        [ (B.pack "query", JString $ B.pack "me")
        , (B.pack "ip", showAddr qAddr)
        , (B.pack "dest", maybe JNull showAddr (ipv4Of clientAddr))
        , (B.pack "port", JNumber $ toInteger port)
        , (B.pack "listed", JBool isListed) ]
    route "/api/ip" =
      let isTor = case (ipv4Of clientAddr, publicAddr) of
            (Just c, Just (a,p)) -> listed' c (DestAddrPort a p)
            _                    -> False
      in jsonResponse noCache $ JObject
           [ (B.pack "IsTor", JBool isTor)
           , (B.pack "IP", JString . B.pack $ showSockAddrHost clientAddr) ]
    route "/torbulkexitlist" = either badRequest id $ do
      dest <- case lookup (B.pack "ip") params of
        Nothing -> return anyDestination
        Just _ -> do
          dAddr <- addrParam "ip"
          port <- case lookup (B.pack "port") params of
            Nothing -> return 80
            Just _  -> portParam "port"
          return $ DestAddrPort dAddr port
      return . textResponse 200 cacheLong . B.unlines .
        map (B.pack . inet_htoa) $ exitAddressesTo now ns dest
    route "/exit-addresses" =
      textResponse 200 cacheLong . B.concat . map renderExitAddress .
        mapMaybe mkExitAddress . M.toList $ nsRouters ns
    route _ = errorResponse 404 "Not Found" "no such resource"

    listed a dest = a == 0x7f000002 || listed' a dest
    listed' a = isExitTo now ns a

    publicAddr = case webPublicAddress conf of
      Just ap -> Just ap
      Nothing -> case localAddr of
        SockAddrInet p a -> Just (ntohl a, fromIntegral p)
        _                -> Nothing

    textParam k = case lookup (B.pack k) params of
      Just v | not (B.null v) -> Right v
      _ -> Left (400, B.pack "Bad Request",
                 B.pack $ "missing parameter \"" ++ k ++ "\"")
    addrParam k = do
      v <- textParam k
      either (const $ Left (400, B.pack "Bad Request",
                            B.pack $ "parameter \"" ++ k ++ "\" must be an \
                                     \IPv4 address"))
             Right (inet_atoh v)
    portParam k = do
      v <- textParam k
      unless (B.all isDigit v && B.length v <= 5) $ portError k
      either (const $ portError k) Right (parsePort v)
    portError k = Left (400, B.pack "Bad Request",
                        B.pack $ "parameter \"" ++ k ++ "\" must be a port")

    badRequest (code,reason,msg) = errorResponse code (B.unpack reason)
                                                 (B.unpack msg)

    showAddr = JString . B.pack . inet_htoa

    cacheLong = B.pack "public, max-age=1800"
    noCache   = B.pack "no-store"

    helpText = B.unlines $ map B.pack
      [ "TorDNSEL: a Tor DNS-based exit list."
      , ""
      , "This server answers, over DNS and HTTP, the question \"which Tor exit"
      , "nodes will connect to me?\" (see doc/torel-design.md)."
      , ""
      , "  GET /api/v1/ip-port?ip=IP1&port=PORT&dest=IP2"
      , "      Is IP1 a Tor exit permitting connections to IP2:PORT?"
      , "  GET /api/v1/list?ip=IP&list=NAME"
      , "      Is IP a Tor exit permitting connections to a member of list NAME?"
      , "  GET /api/v1/lists"
      , "      The configured lists."
      , "  GET /api/v1/me?ip=IP&port=PORT"
      , "      Is IP a Tor exit permitting connections to PORT on your host?"
      , "  GET /api/ip"
      , "      Are you connecting from a Tor exit?"
      , "  GET /torbulkexitlist[?ip=IP[&port=PORT]]"
      , "      All Tor exit addresses (permitting connections to IP:PORT)."
      , "  GET /exit-addresses"
      , "      Results of active exit tests." ]

-- | The IPv4 address of a socket address, if it has one.
ipv4Of :: SockAddr -> Maybe HostAddress
ipv4Of (SockAddrInet _ a)                     = Just (ntohl a)
ipv4Of (SockAddrInet6 _ _ (0, 0, 0xffff, a) _) = Just a
ipv4Of _                                      = Nothing

-- | The host part of a socket address as text.
showSockAddrHost :: SockAddr -> String
showSockAddrHost addr = case ipv4Of addr of
  Just a  -> inet_htoa a
  Nothing -> case show addr of
    '[':rest -> takeWhile (/= ']') rest
    other    -> other

-- | A response with a content type, a cache policy and a body.
contentType :: String -> (ByteString, ByteString)
contentType t = (B.pack "Content-Type", B.pack t)

textResponse :: Int -> ByteString -> ByteString -> Response
textResponse code cache body = Response code (B.pack "OK")
  [ contentType "text/plain; charset=utf-8"
  , (B.pack "Cache-Control", cache) ] body False

jsonResponse :: ByteString -> JSON -> Response
jsonResponse cache json = Response 200 (B.pack "OK")
  [ contentType "application/json"
  , (B.pack "Cache-Control", cache)
  , (B.pack "Access-Control-Allow-Origin", B.pack "*") ]
  (renderJSON json `B.append` B.pack "\n") False

errorResponse :: Int -> String -> String -> Response
errorResponse code reason msg = Response code (B.pack reason)
  [ contentType "application/json"
  , (B.pack "Cache-Control", B.pack "no-store") ]
  (renderJSON (JObject [(B.pack "error", JString $ B.pack msg)])
     `B.append` B.pack "\n") False
