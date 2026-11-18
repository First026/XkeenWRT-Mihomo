#!/bin/sh
# C4: the lab proxy is down. Confirm over Tailscale is refused with
# NETWORK_REMOTE_EGRESS; withdrawing capture leaves no own objects and Direct.
set -u
. /usr/share/xk-lab/lib.sh
fail() { start_peer_proxy >/dev/null 2>&1; echo "XK_LAB_C4=FAIL $*"; exit 1; }
use_ts; wait_api || fail "tailscale listener"
stop_peer_proxy
start_refused NETWORK_REMOTE_EGRESS || fail refusal
[ "$(field "$REFUSAL" '@.network.remote_check.dns')" = true ] || fail "dns should pass $REFUSAL"
[ "$(field "$REFUSAL" '@.network.remote_check.egress.state')" = failed ] || fail "egress report $REFUSAL"
disable_gateway || fail "withdraw"
own_table_absent || fail "own nft table left"
ip netns exec xk-mgmt nslookup www.gstatic.com 192.168.5.1 2>/dev/null | grep -q 1.2.3.4 || fail "LAN DNS after withdrawal"
[ "$(lan_fetch_direct)" != 000 ] || fail "direct site after withdrawal"
stop_gateway || fail "stop core"
start_peer_proxy || fail "restore proxy"
no_recovery_crash || fail "recovery stopped"
echo "XK_LAB_C4=PASS tested=$(field "$REFUSAL" '@.network.remote_check.egress.tested')"
