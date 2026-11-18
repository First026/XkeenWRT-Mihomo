#!/bin/sh
# C8 (decision 025): a one-off failure while restoring the baseline core must
# not wedge Stop. On a running gateway the core home is made group-writable,
# so core::restore refuses it (private_dir) after nft and routes are gone,
# exactly where the 0.1.26.3 lab run 3 failed. A watcher restores the mode as
# soon as the event records RECOVERY; recovery must then finish the Disable by
# itself, Stop must complete, and logread must name the failed step.
set -u
. /usr/share/xk-lab/lib.sh
home=/tmp/xkeenwrt/runtime/active
event=/etc/xkeenwrt/active-reconcile.json
fail() { chmod 0700 "$home" 2>/dev/null; kill "$watcher" 2>/dev/null; echo "XK_LAB_C8=FAIL $*"; exit 1; }
watcher=
use_lan; wait_api || fail "LAN listener"
start_gateway || fail start
[ -d "$home" ] || fail "no core home"
rm -f /tmp/xk-c8-fixed
( while :; do
    if grep -q '"error_code":"RECOVERY"' "$event" 2>/dev/null; then
      chmod 0700 "$home"; echo fixed > /tmp/xk-c8-fixed; exit 0
    fi
  done ) &
watcher=$!
chmod 0770 "$home"
api POST /api/control '{"action":"stop"}' > /dev/null
n=0; until [ -s /tmp/xk-c8-fixed ] || [ "$n" -ge 60 ]; do sleep 1; n=$((n + 1)); done
[ -s /tmp/xk-c8-fixed ] || fail "the injected failure never reached the event"
echo XK_LAB_C8_INJECTED=PASS
wait_state inactive 60 || fail "Disable did not finish after the failure"
record=$event; [ -f "$record" ] || record=$(ls -t /etc/xkeenwrt/active-event-history/*.json | head -1)
echo "XK_LAB_C8_RETRY=PASS kind=$(jsonfilter -i "$record" -e @.kind) phase=$(jsonfilter -i "$record" -e @.phase) retries=$(grep -o '"retry_failures":\[[^]]*\]' "$record" | grep -o RECOVERY | wc -l)"
logread | grep -q 'recovery step failed: step=restore_baseline' || fail "no log line naming the failed step"
echo "XK_LAB_C8_LOG=PASS $(logread | grep 'recovery step failed' | tail -1 | sed 's/.*recovery step failed: //')"
stop_gateway || fail "Stop after the retried Disable"
own_table_absent || fail "own nft table left"
[ "$(stat -c %a "$home" 2>/dev/null || echo 700)" = 700 ] || fail "core home mode not restored"
no_recovery_crash || fail "recovery stopped"
echo XK_LAB_C8=PASS
