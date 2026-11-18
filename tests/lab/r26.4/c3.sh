#!/bin/sh
# C3: Start over Tailscale. The router proves gateway DNS and egress itself,
# the generation records the Tailscale channel, and the LAN client follows the
# profile's rules: the proxied site through the proxy, the plain site DIRECT.
set -u
. /usr/share/xk-lab/lib.sh
fail() { echo "XK_LAB_C3=FAIL $*"; exit 1; }
apk info -v | grep -qx xkeenwrt-core-0.1.26.4-r0 || fail "not 0.1.26.4"
use_ts; wait_api || fail "tailscale listener"
[ "$(field "$(api GET /api/app-info)" '@.management_scope')" = tailscale_admin ] || fail "not the Tailscale listener"
comp=$(api GET /api/network/compatibility)
echo "$comp" | grep -q NETWORK_MANAGEMENT && fail "management blocker over Tailscale: $comp"
echo XK_LAB_C3_COMPATIBILITY=PASS
[ "$(lan_fetch)" = 000 ] || fail "site reachable before the gateway"
LAST_CONFIRM=
start_gateway || fail start
c=$LAST_CONFIRM
[ "$(field "$c" '@.network.remote_check.dns')" = true ] || fail "dns probe $c"
[ "$(field "$c" '@.network.remote_check.egress.state')" = ok ] || fail "egress probe $c"
[ "$(field "$c" '@.network.remote_check.egress.node')" = lab-ss ] || fail "egress node $c"
st=$(api GET /api/network/status)
[ "$(field "$st" '@.network.management_channel')" = tailscale ] || fail "status channel $st"
[ "$(field "$st" '@.network.remote_check.egress.state')" = ok ] || fail "status report $st"
grep -q '"management_channel":"tailscale"' $ROOT/recovery.json || fail "journal has no channel"
via_proxy=$(lan_fetch); direct=$(lan_fetch_direct)
[ "$via_proxy" != 000 ] || fail "LAN client did not reach the proxied site"
[ "$direct" != 000 ] || fail "LAN client did not reach the direct site"
echo "XK_LAB_C3_LAN_RULES=PASS proxied=HTTP_$via_proxy direct=HTTP_$direct"
use_lan; wait_api || fail "LAN panel while captured"; use_ts
stop_gateway || fail stop
own_table_absent || fail "own nft table left"
[ "$(lan_fetch)" = 000 ] || fail "site reachable after Stop"
no_recovery_crash || fail "recovery stopped"
echo "XK_LAB_C3=PASS node=$(field "$c" '@.network.remote_check.egress.node') delay_ms=$(field "$c" '@.network.remote_check.egress.delay_ms') lan_clients=$(field "$c" '@.network.remote_check.lan_clients')"
