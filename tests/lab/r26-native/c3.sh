#!/bin/sh
# C3: delete the rollback snapshot of a pending Start, let the deadline expire:
# recovery must end Direct without a crash loop, and Start must work again.
set -u
. /usr/share/xk-lab/lib.sh
fail() { echo "XK_LAB_C3=FAIL $*"; exit 1; }
rev=$(save_profile home "mode: rule
proxies: []
rules:
  - MATCH,DIRECT
# c3")
apply_profile home "$rev" || fail apply
s=$(api POST /api/control '{"action":"start"}')
[ "$(field "$s" '@.network.state')" = pending ] || fail "start not pending: $s"
tx=$(field "$s" '@.network.transaction_id')
victim=$(jsonfilter -i $ROOT/recovery.json -e '@.previous_core.snapshot_id')
[ -d "$ROOT/history/$victim" ] || fail "rollback snapshot $victim not found"
rm -rf "$ROOT/history/$victim"
echo "XK_LAB_C3_DELETED tx=$tx snapshot=$victim"
rescue_pid=$(pidof xkeenwrt-recovery)
stops=$(logread | grep -c 'recovery stopped')
n=0
while [ "$n" -lt 100 ]; do
  state=$(jsonfilter -i $ROOT/recovery.json -e '@.state' 2>/dev/null)
  [ "$state" = disabled ] || [ "$state" = rolled_back ] && break
  sleep 3; n=$((n + 1))
done
kind=$(jsonfilter -i $ROOT/recovery.json -e '@.completion.kind' 2>/dev/null)
echo "XK_LAB_C3_JOURNAL state=$state completion=$kind"
[ "$state" = disabled ] && [ "$kind" = rollback_direct ] || fail "journal $state/$kind"
sleep 10
[ "$(logread | grep -c 'recovery stopped')" = "$stops" ] || { logread | grep 'recovery stopped' | tail -3; fail "recovery stopped"; }
[ "$(logread | grep -c 'xkeenwrt-recovery.*crash loop')" = 0 ] || fail "procd crash loop"
logread | grep 'SNAPSHOT_MISSING' | tail -2
grep -q '"SNAPSHOT_MISSING"' /var/run/xkeenwrt/recovery-notice.json || fail "no notice"
nft list table inet xkeenwrt >/dev/null 2>&1 && fail "capture table still present"
st=$(api GET /api/network/status)
[ "$(field "$st" '@.network.recovery_notice')" = SNAPSHOT_MISSING ] || fail "status notice: $st"
[ "$(field "$st" '@.network.state')" = inactive ] || fail "state not inactive: $st"
echo "XK_LAB_C3_DIRECT=PASS rescue_pid_before=$rescue_pid rescue_pid_after=$(pidof xkeenwrt-recovery)"
start_gateway || fail "start after direct"
stop_gateway || fail "stop after direct"
references_intact || fail dangling
echo XK_LAB_C3=PASS
