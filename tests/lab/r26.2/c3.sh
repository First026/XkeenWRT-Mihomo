#!/bin/sh
# C3: from the LAN, Apply a new revision on the running gateway (it replaces
# the generation; r26 refused this with PROFILE_REQUIRED), then Restart and Stop.
set -u
. /usr/share/xk-lab/lib.sh
fail() { echo "XK_LAB_C3=FAIL $*"; exit 1; }
use_lan; wait_api || fail "LAN listener"
start_gateway || fail start
gen1=$(field "$(api GET /api/network/status)" '@.network.active_generation')
rev=$(save_profile home "$PROFILE
# changed while running $(key)")
[ -n "$rev" ] || fail "save while running"
apply_profile home "$rev" > /tmp/xk-c3-apply.out 2>&1; cat /tmp/xk-c3-apply.out
grep -q XK_LAB_APPLY=PASS /tmp/xk-c3-apply.out || fail apply
grep -q XK_LAB_APPLY_REPLACED_CONFIRMED /tmp/xk-c3-apply.out || fail "apply did not replace the running gateway"
gen2=$(field "$(api GET /api/network/status)" '@.network.active_generation')
[ "$gen2" -gt "$gen1" ] 2>/dev/null || fail "generation $gen1 -> $gen2"
[ "$(lan_fetch)" != 000 ] || fail "LAN client after apply"
restart_gateway || fail restart
[ "$(lan_fetch)" != 000 ] || fail "LAN client after restart"
grep -q management_channel $ROOT/recovery.json && fail "journal has a field r26 cannot read"
stop_gateway || fail stop
own_table_absent || fail "own nft table left"
references_intact || fail dangling
no_recovery_crash || fail "recovery stopped"
echo "XK_LAB_C3=PASS generation=$gen1->$gen2"
