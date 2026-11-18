#!/bin/sh
# C1: ten "YAML -> Apply -> Start -> Confirm -> Stop" cycles with history
# prefilled to 480 entries; after each: refs intact, <= 512, no recovery stop.
set -u
. /usr/share/xk-lab/lib.sh
fail() { echo "XK_LAB_C1=FAIL $*"; exit 1; }
mkdir -p $ROOT/history && chmod 700 $ROOT/history
# Unattached synthetic snapshots (12 entries each), older than any product write.
while [ "$(history_entries)" -lt 468 ]; do
  id=$(cat /proc/sys/kernel/random/uuid); d=$ROOT/history/$id
  mkdir -p $d/assets/providers/rules; chmod 700 $d $d/assets $d/assets/providers $d/assets/providers/rules
  printf 'mode: rule\n' > $d/config.yaml; chmod 600 $d/config.yaml
  for k in 0 1 2 3 4 5 6; do printf 'payload: []\n' > $d/assets/providers/rules/$k.yaml; chmod 600 $d/assets/providers/rules/$k.yaml; done
  touch -d '2026-01-01 00:00:00' $d
done
echo "XK_LAB_C1_PREFILL entries=$(history_entries)"
[ "$(history_entries)" -ge 468 ] || fail prefill
stops=$(logread | grep -c 'recovery stopped')
i=1
while [ "$i" -le 10 ]; do
  rev=$(save_profile home "mode: rule
proxies: []
rules:
  - MATCH,DIRECT
# cycle $i")
  [ -n "$rev" ] || fail "save $i"
  apply_profile home "$rev" >/tmp/xk-c1.log 2>&1 || { cat /tmp/xk-c1.log; fail "apply $i"; }
  start_gateway >>/tmp/xk-c1.log 2>&1 || { cat /tmp/xk-c1.log; fail "start $i"; }
  stop_gateway >>/tmp/xk-c1.log 2>&1 || { cat /tmp/xk-c1.log; fail "stop $i"; }
  n=$(history_entries)
  references_intact || fail "dangling after cycle $i"
  [ "$n" -le 512 ] || fail "history $n > 512 after cycle $i"
  [ "$(logread | grep -c 'recovery stopped')" = "$stops" ] || fail "recovery stopped during cycle $i"
  echo "XK_LAB_C1_CYCLE=$i entries=$n PASS"
  i=$((i + 1))
done
echo XK_LAB_C1=PASS
