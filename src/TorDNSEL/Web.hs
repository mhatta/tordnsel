-----------------------------------------------------------------------------
-- |
-- Module      : TorDNSEL.Web
-- License     : Public domain (see LICENSE)
--
-- Maintainer  : Masayuki Hatta <mhatta@mhatta.org>
-- Stability   : alpha
-- Portability : non-portable (concurrency, extended exceptions)
--
-- The web interface, providing the same data as the DNS interface over HTTP.
--
-----------------------------------------------------------------------------

module TorDNSEL.Web (
    WebConfig(..)
  , WebServer
  , startWebServer
  , reconfigureWebServer
  , terminateWebServer
  ) where

import TorDNSEL.Web.Internals
