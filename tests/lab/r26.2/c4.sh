#!/bin/sh
# C4: over Tailscale the panel stays as in r26: it opens and can Stop, but it
# cannot start the gateway or restart it; those stay main-LAN actions.
set -u
. /usr/share/xk-lab/lib.sh
fail() { use_lan; stop_gateway >/dev/null 2>&1; echo "XK_LAB_C4=FAIL $*"; exit 1; }
use_ts; wait_api || fail "tailscale listener"
[ "$(field "$(api GET /api/app-info)" '@.management_scope')" = tailscale_admin ] || fail "not the Tailscale listener"
echo "$(api GET /api/network/compatibility)" | grep -q NETWORK_MANAGEMENT || fail "no management blocker over Tailscale"
s=$(api POST /api/control '{"action":"start"}')
[ "$(code)" != 200 ] && [ "$(field "$s" '@.code')" = NETWORK_MANAGEMENT ] || fail "start over Tailscale: code=$(code) $s"
own_table_absent || fail "refused start left capture"
echo XK_LAB_C4_START_REFUSED=PASS
use_lan; start_gateway || fail "LAN start"
use_ts
r=$(api POST /api/control '{"action":"restart"}')
[ "$(code)" != 200 ] && [ "$(field "$r" '@.code')" = UNSUPPORTED ] || fail "restart over Tailscale: code=$(code) $r"
[ "$(field "$(api GET /api/network/status)" '@.network.state')" = active ] || fail "refused restart touched the gateway"
echo XK_LAB_C4_RESTART_REFUSED=PASS
stop_gateway || fail "stop over Tailscale"
own_table_absent || fail "own nft table left"
no_recovery_crash || fail "recovery stopped"
echo XK_LAB_C4=PASS
