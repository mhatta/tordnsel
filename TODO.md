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

## Still to do

- [ ] IPv6
  - [ ] list exits' IPv6 exit addresses (descriptors' `or-address` lines and
    `ipv6-policy` summaries; IPv6 exit tests need an IPv6 test listener)
  - [ ] accept nibble-format IPv6 addresses in queries (RFC 5782)
  - [ ] "me" queries and `/api/ip` from IPv6 hosts
- [ ] DNS over TCP (RFC 7766), and perhaps a per-client response rate limit
- [ ] SAFECOOKIE authentication to the control port
- [ ] honour X-Forwarded-For from a configured reverse proxy in the web
  interface
- [ ] EDNS Client Subnet for "me" queries arriving through public resolvers
- [ ] Prometheus-style metrics next to the statistics socket
- [ ] persist the network state (not only exit test results) across restarts,
  so that answers are available before Tor has delivered all descriptors
- [ ] Debian packaging
- [ ] don't trust the local running environment to be sane or safe
