# tordnsel wishlist

## Done in 0.2.0

See [ChangeLog](ChangeLog).

- [x] builds with current GHC (9.4 and newer) and libraries
- [x] works with current Tor (0.4.8/0.4.9): NEWCONSENSUS, controller-mapped
  `.exit` exit tests, current descriptor and policy syntax
- [x] query types 2 ("list") and 3 ("me") from
  [torel-design.md](doc/torel-design.md)
- [x] a web interface providing the same data as the DNS interface, including
  a check.torproject.org-style `/api/ip` and `/torbulkexitlist`
- [x] EDNS(0), TXT records, QNAME-minimisation-friendly empty non-terminals
- [x] more input validation on DNS queries
- [x] an end-to-end test against a chutney network

## Done in 0.2.2

- [x] SAFECOOKIE authentication to the control port
- [x] DNS over TCP (RFC 7766) and a per-client response rate limit for UDP
- [x] property tests for the parsers of untrusted input

## Done in 0.3.0

- [x] the Tor Project's form of query, `{IP}.{zone}` with fingerprints in TXT
- [x] honour X-Forwarded-For from a configured reverse proxy in the web
  interface
- [x] EDNS Client Subnet for "me" queries arriving through public resolvers
- [x] Prometheus-style metrics
- [x] fixes for the problems found in an audit of 0.2.2 (control port,
  exit test cookies, connection limits, file handling)

## Done in 0.4.0

- [x] Tor's control and SOCKS ports over Unix sockets (as Debian's tor
  offers them) and IPv6
- [x] fixes for the problems found in an audit of 0.3.0 (privilege dropping,
  exit test listener limits, DNS amplification, stored test results,
  statistics socket)

## Still to do

- [ ] IPv6
  - [ ] list exits' IPv6 exit addresses (descriptors' `or-address` lines and
    `ipv6-policy` summaries; IPv6 exit tests need an IPv6 test listener)
  - [ ] accept nibble-format IPv6 addresses in queries (RFC 5782)
  - [ ] "me" queries and `/api/ip` from IPv6 hosts
- [ ] persist the network state (not only exit test results) across restarts,
  so that answers are available before Tor has delivered all descriptors
- [ ] Debian packaging (ITP filed; packaging on Salsa, debian/tordnsel)
- [ ] don't trust the local running environment to be sane or safe
