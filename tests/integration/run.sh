#!/usr/bin/env bash
# End-to-end test of TorDNSEL against a private Tor network built with
# chutney: start the network, run TorDNSEL with active exit testing, and check
# the answers of the DNS and HTTP interfaces.
#
# usage: tests/integration/run.sh CHUTNEY_DIR TORDNSEL_BINARY
#
# Needs tor and tor-gencert, python3 (with the pyasyncore and pyasynchat
# backports on Python >= 3.12), dig, curl and iproute2. The addresses
# 10.200.0.{1,11,12,13,99} are added to the loopback interface, which needs
# root; set SUDO=sudo to run just that step with sudo. Set KEEP=1 to keep the
# working directory (logs, Tor data) afterwards.

set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 CHUTNEY_DIR TORDNSEL_BINARY" >&2
  exit 64
fi

here=$(cd "$(dirname "$0")" && pwd)
chutney_src=$(cd "$1" && pwd)
tordnsel=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
work=$(mktemp -d "${TMPDIR:-/tmp}/tordnsel-it.XXXXXX")
dns_port=${DNS_PORT:-15353}
http_port=${HTTP_PORT:-18080}
zone=exitlist.example.com
td_pid=
failures=0

log() { printf '%s\n' "$*" >&2; }

cleanup() {
  [ -n "$td_pid" ] && kill "$td_pid" 2>/dev/null || true
  if [ -d "$work/chutney" ]; then
    (cd "$work/chutney" && ./chutney stop networks/tordnsel >/dev/null 2>&1) || true
  fi
  if [ "${KEEP:-0}" = 1 ]; then
    log "Kept $work"
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

# wait_for DESCRIPTION SECONDS COMMAND...
wait_for() {
  local what=$1 secs=$2
  shift 2
  for _ in $(seq "$secs"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  log "Timed out waiting for $what."
  return 1
}

# check DESCRIPTION EXPECTED ACTUAL
check() {
  if [ "$2" = "$3" ]; then
    printf 'ok    %s\n' "$1"
  else
    printf 'FAIL  %s\n      expected: %s\n      got:      %s\n' "$1" "$2" "$3"
    failures=$((failures + 1))
  fi
}

dns() { # dns NAME [TYPE] -> "STATUS answers..."
  dig +norec +time=2 +tries=2 -p "$dns_port" @127.0.0.1 "$1" "${2:-A}" |
    awk '/status:/ { s = $6; sub(",", "", s) }
         /^[^;].*IN[ \t]+(A|TXT)[ \t]/ { a = a " " $NF }
         END { print s a }'
}

http() { curl -s --noproxy '*' "http://127.0.0.1:$http_port$1"; }

python3 -c 'import asyncore, asynchat' 2>/dev/null || {
  log "chutney needs asyncore and asynchat: pip install pyasyncore pyasynchat"
  exit 69
}

log "Adding test addresses to the loopback interface."
for a in 1 11 12 13 99; do
  ip -4 addr show dev lo | grep -q "inet 10\.200\.0\.$a/" ||
    ${SUDO:-} ip addr add "10.200.0.$a/32" dev lo
done

log "Preparing chutney in $work."
cp -r "$chutney_src" "$work/chutney"
cp -r "$here/chutney/." "$work/chutney/"
cd "$work/chutney"
rm -rf net/nodes*
# Python 3.13 removed cgitb, which chutney only uses for nicer tracebacks.
sed -i 's/^import cgitb$/try:\n    import cgitb\nexcept ImportError:\n    cgitb = None/;
        s/^cgitb.enable(format="plain")$/if cgitb: cgitb.enable(format="plain")/' \
  lib/chutney/TorNet.py lib/chutney/Debug.py
# Don't require IPv6 on the test host.
sed -i 's/^OrPort \$orport$/OrPort $orport IPv4Only/' \
  torrc_templates/relay-non-dir.tmpl
sed -i 's/^DirPort \$dirport$/DirPort $dirport IPv4Only/' \
  torrc_templates/relay-non-exit.tmpl

export CHUTNEY_TOR=${CHUTNEY_TOR:-$(command -v tor)}
export CHUTNEY_TOR_GENCERT=${CHUTNEY_TOR_GENCERT:-$(command -v tor-gencert)}

log "Starting the Tor network."
./chutney configure networks/tordnsel >/dev/null
./chutney start networks/tordnsel >/dev/null
nodes=$(readlink -f net/nodes)
client=$nodes/007c
wait_for "the client to bootstrap" 300 grep -q "Bootstrapped 100%" "$client/notice.log"

log "Starting TorDNSEL."
mkdir -p "$work/state" "$work/run"
cat > "$work/tordnsel.conf" <<EOF
ZoneOfAuthority $zone
DomainName ns.$zone
SOARName hostmaster.example.com
StateDirectory $work/state
RuntimeDirectory $work/run
DNSListenAddress 127.0.0.1:$dns_port
TorControlAddress 127.0.0.1:8007
TorSocksAddress 127.0.0.1:9007
Log info file $work/tordnsel.log
EnableActiveTesting True
TestListenAddress 10.200.0.1:6667,10080
TestDestinationAddress 10.200.0.1:6667,10080
ExitList ircnet 10.200.0.0/24:6667 192.0.2.10:6697
ExitList web 198.51.100.7:443
HTTPListenAddress 127.0.0.1:$http_port
EOF
"$tordnsel" -f "$work/tordnsel.conf" --verify-config
"$tordnsel" -f "$work/tordnsel.conf" > "$work/tordnsel.out" 2>&1 &
td_pid=$!

tested() {
  [ "$(grep -o 'Exit test through router [0-9a-f]*' "$work/tordnsel.log" 2>/dev/null |
       sort -u | wc -l)" -ge 3 ]
}
wait_for "exit tests through all three exits" 600 tested
grep 'Exit test through router' "$work/tordnsel.log" | awk '!seen[$8]++ { print "      " $0 }' >&2

z=$zone
echo "DNS, query type 1 (ip-port)"
check "exit A, port 80"                     "NOERROR 127.0.0.2" "$(dns 11.0.200.10.80.7.100.51.198.ip-port.$z)"
check "exit B by its tested exit address"   "NOERROR 127.0.0.2" "$(dns 99.0.200.10.80.7.100.51.198.ip-port.$z)"
check "exit C, port 80 rejected"            "NXDOMAIN"          "$(dns 13.0.200.10.80.7.100.51.198.ip-port.$z)"
check "exit C, port 443"                    "NOERROR 127.0.0.2" "$(dns 13.0.200.10.443.7.100.51.198.ip-port.$z)"
check "exit C, 10.200.0.1:6667"             "NOERROR 127.0.0.2" "$(dns 13.0.200.10.6667.1.0.200.10.ip-port.$z)"
check "an authority (not an exit)"          "NXDOMAIN"          "$(dns 1.0.0.127.80.7.100.51.198.ip-port.$z)"
check "the RFC 5782 test address"           "NOERROR 127.0.0.2" "$(dns 2.0.0.127.80.7.100.51.198.ip-port.$z)"
check "empty non-terminal"                  "NOERROR"           "$(dns 7.100.51.198.ip-port.$z)"
check "TXT explanation" \
  'NOERROR 198.51.100.7:80"' "$(dns 11.0.200.10.80.7.100.51.198.ip-port.$z TXT)"

echo "DNS, query type 2 (list)"
check "exit C, ircnet"                      "NOERROR 127.0.0.2" "$(dns 13.0.200.10.ircnet.list.$z)"
check "exit C, web"                         "NOERROR 127.0.0.2" "$(dns 13.0.200.10.web.list.$z)"
check "unknown list"                        "NXDOMAIN"          "$(dns 13.0.200.10.nosuch.list.$z)"

echo "DNS, query type 3 (me; the asker is 127.0.0.1)"
check "exit A, port 6667"                   "NOERROR 127.0.0.2" "$(dns 11.0.200.10.6667.me.$z)"
check "exit C, port 6667"                   "NXDOMAIN"          "$(dns 13.0.200.10.6667.me.$z)"
check "TTL 0" "0" \
  "$(dig +noall +answer -p "$dns_port" @127.0.0.1 11.0.200.10.6667.me.$z | awk '{print $2}')"

echo "DNS, misc"
check "outside our zone"                    "REFUSED"           "$(dns example.org)"
check "EDNS(0) is echoed" "udp: 1232" \
  "$(dig +norec -p "$dns_port" @127.0.0.1 $z SOA | grep -o 'udp: [0-9]*')"

echo "HTTP"
check "/api/v1/ip-port" \
  '{"query":"ip-port","ip":"10.200.0.99","dest":"198.51.100.7","port":80,"listed":true}' \
  "$(http '/api/v1/ip-port?ip=10.200.0.99&port=80&dest=198.51.100.7')"
check "/api/v1/list" \
  '{"query":"list","ip":"10.200.0.13","list":"ircnet","listed":true}' \
  "$(http '/api/v1/list?ip=10.200.0.13&list=ircnet')"
check "/torbulkexitlist" "10.200.0.11 10.200.0.12 10.200.0.99" \
  "$(http '/torbulkexitlist?ip=198.51.100.7&port=80' | tr '\n' ' ' | sed 's/ $//')"
check "/exit-addresses lists three exits" "3" \
  "$(http /exit-addresses | grep -c '^ExitNode')"
check "/api/ip, direct" '{"IsTor":false,"IP":"127.0.0.1"}' "$(http /api/ip)"

echo
if [ "$failures" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$failures check(s) failed. Logs: $work (rerun with KEEP=1 to keep them)."
  exit 1
fi
