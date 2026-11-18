#!/bin/sh
# C2: upgrade r25 -> r26 in place, keeping /etc/xkeenwrt, after a real r25 cycle.
set -u
. /usr/share/xk-lab/lib.sh
fail() { echo "XK_LAB_C2=FAIL $*"; exit 1; }
apk info -v | grep -qx xkeenwrt-core-0.1-r25 || fail "r25 is not installed"
before_rev=$(field "$(api GET /api/profiles/home)" '@.profile.revision')
[ -n "$before_rev" ] || fail "no r25 profile state"
before_history=$(history_entries)
before_owner=$(cat $ROOT/owner-id)
echo "XK_LAB_C2_BEFORE profile=$before_rev history=$before_history"
sh /usr/share/xk-lab/install.sh r26 > /tmp/xk-install-r26.out 2>&1 || { cat /tmp/xk-install-r26.out; fail "upgrade"; }
grep XK_LAB /tmp/xk-install-r26.out
[ "$(cat $ROOT/owner-id)" = "$before_owner" ] || fail "owner changed"
[ "$(field "$(api GET /api/profiles/home)" '@.profile.revision')" = "$before_rev" ] || fail "profile lost"
references_intact || fail "dangling snapshot after upgrade"
rev=$(save_profile home "mode: rule
proxies: []
rules:
  - MATCH,DIRECT
# after upgrade")
apply_profile home "$rev" || fail apply
start_gateway || fail start
stop_gateway || fail stop
references_intact || fail "dangling snapshot after cycle"
[ "$(logread | grep -c 'recovery stopped')" = 0 ] || fail "recovery stopped in log"
echo "XK_LAB_C2=PASS history_before=$before_history history_after=$(history_entries)"
