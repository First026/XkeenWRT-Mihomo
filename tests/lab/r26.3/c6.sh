#!/bin/sh
# C6: everything else over Tailscale. Apply replaces the running gateway,
# Restart restarts it, HTTP/SOCKS and the pilot plan stay LAN-only, Stop works.
set -u
. /usr/share/xk-lab/lib.sh
fail() { echo "XK_LAB_C6=FAIL $*"; exit 1; }
use_ts; wait_api || fail "tailscale listener"
start_gateway || fail start
gen1=$(field "$(api GET /api/network/status)" '@.network.active_generation')
rev=$(save_profile home "$PROFILE
# changed over Tailscale $(key)")
[ -n "$rev" ] || fail "save over Tailscale"
apply_profile home "$rev" > /tmp/xk-c6-apply.out 2>&1; cat /tmp/xk-c6-apply.out
grep -q XK_LAB_APPLY=PASS /tmp/xk-c6-apply.out || fail apply
grep -q XK_LAB_APPLY_REPLACED_CONFIRMED /tmp/xk-c6-apply.out || fail "apply did not replace the running gateway"
st=$(api GET /api/network/status); gen2=$(field "$st" '@.network.active_generation')
[ "$gen2" -gt "$gen1" ] 2>/dev/null || fail "generation $gen1 -> $gen2"
[ "$(field "$st" '@.network.management_channel')" = tailscale ] || fail "channel after apply $st"
[ "$(lan_fetch)" != 000 ] || fail "LAN client after apply"
restart_gateway || fail restart
[ "$(lan_fetch)" != 000 ] || fail "LAN client after restart"
[ "$(field "$(api GET /api/network/status)" '@.network.management_channel')" = tailscale ] || fail "channel after restart"
e=$(api POST /api/inputs/explicit '{"enabled":true,"binding":{"interface":"br-lan","address":"192.168.5.1"}}')
[ "$(code)" != 200 ] && [ "$(field "$e" '@.code')" = NETWORK_MANAGEMENT ] || fail "HTTP/SOCKS over Tailscale: code=$(code) $e"
echo XK_LAB_C6_EXPLICIT_REFUSED=PASS
p=$(api POST /api/network/plan '{"profile_id":"home","expected_revision":"r","candidate_id":"c","lan_interface":"br-lan","selected_ipv4":"100.64.20.2","management_ipv4":"100.64.20.2","selected_ipv6":[],"management_ipv6":[],"ipv6_policy":"block_external","failure_policy":"block_selected_on_failure"}')
[ "$(code)" = 403 ] && echo "$p" | grep -q NETWORK_MANAGEMENT || fail "pilot plan over Tailscale: code=$(code) $p"
echo XK_LAB_C6_PLAN_REFUSED=PASS
stop_gateway || fail stop
own_table_absent || fail "own nft table left"
references_intact || fail dangling
no_recovery_crash || fail "recovery stopped"
echo "XK_LAB_C6=PASS generation=$gen1->$gen2"
