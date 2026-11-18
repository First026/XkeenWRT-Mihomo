#!/bin/sh
# C5: the upstream DNS is down. Confirm over Tailscale is refused with
# NETWORK_REMOTE_DNS; withdrawing capture returns the LAN to Direct.
set -u
. /usr/share/xk-lab/lib.sh
fail() { start_peer_dns; echo "XK_LAB_C5=FAIL $*"; exit 1; }
use_ts; wait_api || fail "tailscale listener"
stop_peer_dns
# Flush the router's DNS cache so the probe sees the outage, not a cached answer.
/etc/init.d/dnsmasq restart; sleep 2
start_refused NETWORK_REMOTE_DNS || fail refusal
[ "$(field "$REFUSAL" '@.network.remote_check.dns')" = false ] || fail "dns report $REFUSAL"
disable_gateway || fail "withdraw"
own_table_absent || fail "own nft table left"
stop_gateway || fail "stop core"
start_peer_dns
ip netns exec xk-mgmt nslookup www.gstatic.com 192.168.5.1 2>/dev/null | grep -q 1.2.3.4 || fail "LAN DNS after restore"
no_recovery_crash || fail "recovery stopped"
echo XK_LAB_C5=PASS
