#!/bin/sh
set -eu
stage=start
trap 'printf "CLONE_FAIL=%s\n" "$stage"' EXIT
[ "$(id -u)" = 0 ]
[ "$(cat /etc/xkeenwrt-isolation-lab)" = xkeenwrt-validator-lab-v1 ]
grep -qw xkeenwrt.isolation_lab=1 /proc/cmdline
[ "$(uname -r)" = 6.12.112 ]
[ "$(ls /sys/class/net)" = lo ]
[ ! -e /sys/fs/cgroup/xkeenwrt-lab ]
mkdir -p /var/run
: > /var/run/xkeenwrt-lab-clone.lock
mkdir /sys/fs/cgroup/xkeenwrt-lab
mkdir /sys/fs/cgroup/xkeenwrt-lab/clone3
cg=/sys/fs/cgroup/xkeenwrt-lab/clone3
for mode in preclose postexec; do
  rm -f /tmp/xkeenwrt-lab-clone-executed /tmp/xkeen-clone-parent.log
  stage="${mode}-start"
  /usr/libexec/xkeenwrt/lab-clone-parent "$mode" >/tmp/xkeen-clone-parent.log 2>&1 &
  parent=$!
  child=
  n=0
  seen=no
  stopped=no
  ready_seen=no
  cg_seen=no
  kids_seen=no
  while [ "$n" -lt 20 ]; do
    n=$((n + 1))
    if [ "$mode" = postexec ] && [ "$n" = 3 ]; then
      printf 'CLONE_SAMPLE_PARENT_STATE='; awk '/^State:/ {print $2}' "/proc/$parent/status" 2>/dev/null || :
      printf 'CLONE_SAMPLE_WCHAN='; cat "/proc/$parent/wchan" 2>/dev/null || :; echo
      printf 'CLONE_SAMPLE_CHILDREN='; cat "/proc/$parent/task/$parent/children" 2>/dev/null || :; echo
      printf 'CLONE_SAMPLE_CGPROCS='; tr '\n' ',' < "$cg/cgroup.procs"; echo
      printf 'CLONE_SAMPLE_POP='; awk '/^populated / {print $2}' "$cg/cgroup.events"
    fi
    if grep -q '^PARENT_READY$' /tmp/xkeen-clone-parent.log; then
      ready_seen=yes
      child=
      read -r child < "$cg/cgroup.procs" || :
      [ -z "$child" ] || cg_seen=yes
      if [ -z "$child" ] && [ -r "/proc/$parent/task/$parent/children" ]; then
        read -r child < "/proc/$parent/task/$parent/children" || :
        [ -z "$child" ] || kids_seen=yes
      fi
      case "$child" in *[!0-9]*) exit 1;; '') sleep 1; continue;; esac
      if [ "$seen" = no ]; then seen=yes; printf 'CLONE_FIRST_STATE='; awk '/^State:/ {print $2}' "/proc/$child/status"; printf 'CLONE_PARENT_STATE='; awk '/^State:/ {print $2}' "/proc/$parent/status"; printf 'CLONE_FIRST_CG='; grep -qx "$child" "$cg/cgroup.procs" && echo yes || echo no; printf 'CLONE_FIRST_EXE='; readlink "/proc/$child/exe" 2>/dev/null | grep -q '^/usr/libexec/xkeenwrt/lab-clone-probe$' && echo probe || echo other; [ ! -e /tmp/xkeenwrt-lab-clone-executed ] || echo CLONE_EXECUTED=yes; fi
      if grep -q '^State:[[:space:]]*T' "/proc/$child/status"; then stopped=yes; break; fi
    fi
    sleep 1
  done
  printf 'CLONE_LOOPS=%s\nCLONE_READY_SEEN=%s\nCLONE_CG_SEEN=%s\nCLONE_KIDS_SEEN=%s\n' "$n" "$ready_seen" "$cg_seen" "$kids_seen"
  stage="${mode}-stopped"
  if [ "$stopped" != yes ]; then
    printf 'CLONE_END_PARENT_STATE='; awk '/^State:/ {print $2}' "/proc/$parent/status" 2>/dev/null || :
    if grep -q '^PARENT_READY$' /tmp/xkeen-clone-parent.log; then echo CLONE_READY=yes; else echo CLONE_READY=no; fi
    grep -E '^LAB_CHILD_WAIT_STATUS=[0-9]+$' /tmp/xkeen-clone-parent.log || :
    if grep -q 'panicked' /tmp/xkeen-clone-parent.log; then echo CLONE_PANIC=yes; else echo CLONE_PANIC=no; fi
    if grep -q 'Operation not permitted' /tmp/xkeen-clone-parent.log; then echo CLONE_EPERM=yes; else echo CLONE_EPERM=no; fi
    kill -9 "$parent" 2>/dev/null || :; wait "$parent" 2>/dev/null || :
    if grep -q "fault controller should terminate parent" /tmp/xkeen-clone-parent.log; then echo CLONE_PARENT=returned; else echo CLONE_PARENT=other; fi
    exit 1
  fi
  [ -n "$child" ] && kill -0 "$child" || exit 1
  kill -9 "$parent"; wait "$parent" 2>/dev/null || :
  stage="${mode}-membership"
  if [ "$mode" = preclose ]; then
    grep -qx "$child" "$cg/cgroup.procs"
    kill -0 "$child"
    stage="${mode}-lock"
    if flock -n /var/run/xkeenwrt-lab-clone.lock true; then exit 1; fi
  fi
  stage="${mode}-after-parent"
  if [ "$mode" = preclose ]; then
    kill -0 "$child"
    if flock -n /var/run/xkeenwrt-lab-clone.lock true; then exit 1; fi
  fi
  stage="${mode}-kill"
  printf 1 > "$cg/cgroup.kill"
  empty=no
  for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -qx 'populated 0' "$cg/cgroup.events"; then empty=yes; break; fi
    sleep 1
  done
  [ "$empty" = yes ]
  flock -n /var/run/xkeenwrt-lab-clone.lock true
  [ ! -e /tmp/xkeenwrt-lab-clone-executed ]
  printf 'CLONE_CASE=%s:PASS\n' "$mode"
  rmdir "$cg"
  mkdir "$cg"
done
for mode in fail_enosys fail_einval fail_eperm; do
  rm -f /tmp/xkeenwrt-lab-clone-executed
  /usr/libexec/xkeenwrt/lab-clone-parent "$mode" > /tmp/xkeen-clone-parent.log 2>&1
  grep -qx FAIL_CLOSED_OK /tmp/xkeen-clone-parent.log
  grep -qx 'populated 0' "$cg/cgroup.events"
  [ ! -e /tmp/xkeenwrt-lab-clone-executed ]
  flock -n /var/run/xkeenwrt-lab-clone.lock true
  printf 'CLONE_CASE=%s:PASS\n' "$mode"
done
rmdir "$cg" /sys/fs/cgroup/xkeenwrt-lab
[ "$(cat /proc/1/comm)" = procd ]
ubus call system board >/dev/null
[ "$(ls /sys/class/net)" = lo ]
[ "$(cat /tmp/xkeenwrt-test-sentinel)" = test-sentinel-v1 ]
trap - EXIT
echo CLONE_ALL_PASS
