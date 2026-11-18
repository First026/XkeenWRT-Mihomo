#!/bin/sh
# C2: the whole LAN through the gateway started from the LAN, routed by the
# profile's rules. The lab site www.gstatic.com matches DOMAIN-SUFFIX and goes
# through the proxy; the plain site 1.2.3.5 falls to MATCH,DIRECT. With the
# proxy down only the proxied site disappears, which shows each connection
# took its own rule.
set -u
. /usr/share/xk-lab/lib.sh
fail() { start_peer_proxy >/dev/null 2>&1; echo "XK_LAB_C2=FAIL $*"; exit 1; }
apk info -v | grep -qx xkeenwrt-core-0.1.26.4-r0 || fail "not 0.1.26.4"
use_lan; wait_api || fail "LAN listener"
[ "$(lan_fetch)" = 000 ] || fail "proxied site reachable before the gateway"
start_gateway || fail start
[ "$(field "$(api GET /api/network/status)" '@.network.state')" = active ] || fail "not active"
via_proxy=$(lan_fetch); direct=$(lan_fetch_direct)
[ "$via_proxy" != 000 ] || fail "rule DOMAIN-SUFFIX did not reach the site through the proxy"
[ "$direct" != 000 ] || fail "MATCH,DIRECT site unreachable"
echo "XK_LAB_C2_RULES=PASS proxied=HTTP_$via_proxy direct=HTTP_$direct"
stop_peer_proxy
[ "$(lan_fetch)" = 000 ] || fail "proxied site still reachable with the proxy down"
[ "$(lan_fetch_direct)" != 000 ] || fail "direct site depended on the proxy"
echo XK_LAB_C2_SPLIT=PASS
start_peer_proxy >/dev/null || fail "restore proxy"
stop_gateway || fail stop
own_table_absent || fail "own nft table left"
[ "$(lan_fetch)" = 000 ] || fail "site reachable after Stop"
no_recovery_crash || fail "recovery stopped"
echo "XK_LAB_C2=PASS proxied=HTTP_$via_proxy direct=HTTP_$direct"
