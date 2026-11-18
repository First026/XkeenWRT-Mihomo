#!/bin/sh
# C7: the LAN path is unchanged. Start from the LAN after Tailscale
# generations, Apply a new revision on the running gateway (it replaces the
# generation), Restart and Stop; the journal carries no channel again.
set -u
. /usr/share/xk-lab/lib.sh
fail() { echo "XK_LAB_C7=FAIL $*"; exit 1; }
use_lan; wait_api || fail "LAN listener"
start_gateway || fail start
gen1=$(field "$(api GET /api/network/status)" '@.network.active_generation')
grep -q management_channel $ROOT/recovery.json && fail "LAN start recorded a channel"
rev=$(save_profile home "$PROFILE
# changed while running $(key)")
[ -n "$rev" ] || fail "save while running"
apply_profile home "$rev" > /tmp/xk-c7-apply.out 2>&1; cat /tmp/xk-c7-apply.out
grep -q XK_LAB_APPLY=PASS /tmp/xk-c7-apply.out || fail apply
grep -q XK_LAB_APPLY_REPLACED_CONFIRMED /tmp/xk-c7-apply.out || fail "apply did not replace the running gateway"
gen2=$(field "$(api GET /api/network/status)" '@.network.active_generation')
[ "$gen2" -gt "$gen1" ] 2>/dev/null || fail "generation $gen1 -> $gen2"
[ "$(lan_fetch)" != 000 ] || fail "LAN client after apply"
restart_gateway || fail restart
[ "$(lan_fetch)" != 000 ] || fail "LAN client after restart"
grep -q management_channel $ROOT/recovery.json && fail "LAN generation recorded a channel"
stop_gateway || fail stop
own_table_absent || fail "own nft table left"
references_intact || fail dangling
no_recovery_crash || fail "recovery stopped"
echo "XK_LAB_C7=PASS generation=$gen1->$gen2"
