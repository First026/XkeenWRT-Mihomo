#!/bin/sh
# Interrupt --prepare-remove after its durable request, remove APK payload,
# then resume the exact persistent rescue supervisor in a marked no-NIC VM.
set -eu
reboot_mode=no
if [ "${1:-}" = --reboot ] && [ "$#" -eq 1 ]; then
  reboot_mode=yes
elif [ "$#" -ne 0 ]; then
  echo 'usage: remove-payload-loss-guest.sh [--reboot]' >&2
  exit 2
fi
stage=guard
failure=
rescue_pid=
rescue_starttime=
rescue_sha256=
prepare_pid=
prepare_starttime=
helper_stopped=no
request_persisted=no
fail() { failure="$stage:$1"; exit 1; }

service_running_status() {
  service_name=$1
  service_json_file=/tmp/xk-remove-pending-service.json
  service_json_error=/tmp/xk-remove-pending-jsonfilter-error
  service_failure=invalid-response
  ubus call service list "{\"name\":\"$service_name\"}" > "$service_json_file" || {
    service_failure=transport
    return 1
  }
  service_root=$(jsonfilter -i "$service_json_file" -e '@' 2> "$service_json_error") || {
    service_failure=invalid-json
    return 1
  }
  case "$service_root" in \{*\}) ;; *) service_failure=invalid-json; return 1 ;; esac
  if service_object=$(jsonfilter -i "$service_json_file" -e "@[\"$service_name\"]" 2> "$service_json_error"); then
    :
  else
    [ ! -s "$service_json_error" ] || { service_failure=invalid-json; return 1; }
    printf 'false\n'
    return 0
  fi
  case "$service_object" in null|'') printf 'false\n'; return 0 ;; esac
  if service_instances=$(jsonfilter -i "$service_json_file" -e "@[\"$service_name\"].instances" 2> "$service_json_error"); then
    :
  else
    [ ! -s "$service_json_error" ] || { service_failure=invalid-json; return 1; }
    printf 'false\n'
    return 0
  fi
  case "$service_instances" in ''|'{}') printf 'false\n'; return 0 ;; \{*\}) ;; *) service_failure=invalid-response; return 1 ;; esac
  service_running=$(jsonfilter -i "$service_json_file" -e "@[\"$service_name\"].instances.*.running" 2> "$service_json_error") || {
    [ ! -s "$service_json_error" ] || { service_failure=invalid-json; return 1; }
    printf 'false\n'
    return 0
  }
  service_running_any=false
  while IFS= read -r service_instance_running; do
    case "$service_instance_running" in
      true) service_running_any=true ;;
      false) ;;
      *) service_failure=invalid-response; return 1 ;;
    esac
  done <<EOF
$service_running
EOF
  printf '%s\n' "$service_running_any"
}

service_is_stopped() {
  service_name=$1
  service_running_status "$service_name" > /tmp/xk-remove-pending-running || fail "service-$service_name-$service_failure"
  [ "$(cat /tmp/xk-remove-pending-running)" != true ] || fail "service-$service_name-still-running"
}

proc_state_starttime() {
  proc_pid=$1
  proc_stat=$(cat "/proc/$proc_pid/stat") || return 1
  proc_fields=${proc_stat##*) }
  set -- $proc_fields
  [ "$#" -ge 20 ] || return 1
  proc_state=$1
  shift 19
  proc_starttime=$1
  case "$proc_starttime" in ''|*[!0-9]*) return 1 ;; esac
  printf '%s %s\n' "$proc_state" "$proc_starttime"
}

capture_rescue_identity() {
  identity_file=/var/run/xkeenwrt/supervisor.json
  [ -f "$identity_file" ] || return 1
  rescue_pid=$(jsonfilter -i "$identity_file" -e '@.pid') || return 1
  rescue_starttime=$(jsonfilter -i "$identity_file" -e '@.starttime') || return 1
  rescue_sha256=$(jsonfilter -i "$identity_file" -e '@.exe_sha256') || return 1
  identity_owner=$(jsonfilter -i "$identity_file" -e '@.owner_id') || return 1
  guest_owner=$(cat /etc/xkeenwrt/owner-id) || return 1
  [ "$identity_owner" = "$guest_owner" ] || return 1
  case "$rescue_pid" in ''|*[!0-9]*) return 1 ;; esac
  case "$rescue_starttime" in ''|*[!0-9]*) return 1 ;; esac
  [ "${#rescue_sha256}" -eq 64 ] || return 1
  return 0
}

rescue_identity_matches() {
  expected_state=${1:-any}
  [ -n "$rescue_pid" ] && [ -n "$rescue_starttime" ] && [ -n "$rescue_sha256" ] || return 1
  [ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || return 1
  [ -f /var/run/xkeenwrt/supervisor.json ] || return 1
  current_pid=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.pid') || return 1
  current_start=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.starttime') || return 1
  current_hash=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.exe_sha256') || return 1
  [ "$current_pid" = "$rescue_pid" ] && [ "$current_start" = "$rescue_starttime" ] && [ "$current_hash" = "$rescue_sha256" ] || return 1
  proc_identity=$(proc_state_starttime "$rescue_pid") || return 1
  set -- $proc_identity
  process_state=$1
  process_start=$2
  [ "$process_start" = "$rescue_starttime" ] || return 1
  case "$expected_state" in
    stopped) [ "$process_state" = T ] || return 1 ;;
    running) [ "$process_state" != T ] && [ "$process_state" != t ] || return 1 ;;
  esac
  process_exe=$(readlink "/proc/$rescue_pid/exe") || return 1
  [ "$process_exe" = /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || return 1
  process_hash=$(sha256sum "/proc/$rescue_pid/exe" | awk '{print $1}') || return 1
  [ "$process_hash" = "$rescue_sha256" ] || return 1
  process_cmdline=$(tr '\000' ' ' < "/proc/$rescue_pid/cmdline") || return 1
  case "$process_cmdline" in *' supervise'*) ;; *) return 1 ;; esac
  service_running_status xkeenwrt-rescue > /tmp/xk-remove-pending-rescue-running || return 1
  [ "$(cat /tmp/xk-remove-pending-rescue-running)" = true ] || return 1
  procd_pid=$(jsonfilter -i /tmp/xk-remove-pending-service.json -e '@["xkeenwrt-rescue"].instances.*.pid') || return 1
  [ "$procd_pid" = "$rescue_pid" ] || return 1
  return 0
}

rescue_lock_held() {
  process_holds_flock "$rescue_pid" recovery.lock
}

rescue_mutation_lock_held() {
  process_holds_flock "$rescue_pid" mutation.lock
}

process_holds_flock() {
  lock_pid=$1
  lock_suffix=$2
  [ -d "/proc/$lock_pid/fd" ] || return 1
  for fd_path in /proc/"$lock_pid"/fd/*; do
    [ -e "$fd_path" ] || [ -L "$fd_path" ] || continue
    fd_target=$(readlink "$fd_path") || continue
    case "$fd_target" in */xkeenwrt/"$lock_suffix") ;; *) continue ;; esac
    fd_number=${fd_path##*/}
    if awk -v owner="$lock_pid" \
      '$1 == "lock:" && $3 == "FLOCK" && $4 == "ADVISORY" && $5 == "WRITE" && $6 == owner { found = 1; exit } END { exit !found }' \
      "/proc/$lock_pid/fdinfo/$fd_number"; then
      return 0
    fi
  done
  return 1
}

diagnose_lock_record() {
  diag_pid=$1
  diag_suffix=$2
  diag_label=$3
  diag_seen=0
  for diag_fd_path in /proc/"$diag_pid"/fd/*; do
    [ -e "$diag_fd_path" ] || [ -L "$diag_fd_path" ] || continue
    diag_target=$(readlink "$diag_fd_path") || continue
    case "$diag_target" in */xkeenwrt/"$diag_suffix") ;; *) continue ;; esac
    diag_seen=$((diag_seen + 1))
    [ "$diag_seen" -le 4 ] || break
    diag_fd_number=${diag_fd_path##*/}
    diag_record=$(awk -v owner="$diag_pid" '
      $1 == "lock:" {
        if ($3 == "FLOCK" && $4 == "ADVISORY" && $5 == "WRITE" && $6 == owner) print "flock-write-owner-match"
        else if ($3 == "FLOCK" && $4 == "ADVISORY" && $5 == "READ") print "flock-read"
        else print "other-lock-record"
        found = 1
      }
      END { if (!found) print "no-lock-record" }
    ' "/proc/$diag_pid/fdinfo/$diag_fd_number" | head -n 1)
    printf 'REMOVE_PENDING_DIAG_%s=%s\n' "$diag_label" "$diag_record"
  done
  if [ "$diag_seen" -eq 0 ]; then
    printf 'REMOVE_PENDING_DIAG_%s=fd-not-found\n' "$diag_label"
  elif [ "$diag_seen" -gt 4 ]; then
    printf 'REMOVE_PENDING_DIAG_%s=fd-output-limited\n' "$diag_label"
  fi
}

remove_status() {
  /etc/xkeenwrt/rescue/xkeenwrt-recovery --remove-status > /tmp/xk-remove-pending-status.json || return 1
  request_kind=$(jsonfilter -i /tmp/xk-remove-pending-status.json -e '@.kind') || return 1
  request_state=$(jsonfilter -i /tmp/xk-remove-pending-status.json -e '@.state') || return 1
  request_owner_id=$(jsonfilter -i /tmp/xk-remove-pending-status.json -e '@.owner_id') || return 1
  request_request_id=$(jsonfilter -i /tmp/xk-remove-pending-status.json -e '@.request_id') || return 1
}

prepare_waiter_matches() {
  [ -n "$prepare_pid" ] && [ -n "$prepare_starttime" ] || return 1
  waiter_identity=$(proc_state_starttime "$prepare_pid") || return 1
  set -- $waiter_identity
  [ "$2" = "$prepare_starttime" ] || return 1
  waiter_exe=$(readlink "/proc/$prepare_pid/exe") || return 1
  [ "$waiter_exe" = /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || return 1
  waiter_cmdline=$(tr '\000' ' ' < "/proc/$prepare_pid/cmdline") || return 1
  case "$waiter_cmdline" in *' --prepare-remove'*) return 0 ;; *) return 1 ;; esac
}

hash_of() { sha256sum "$1" | awk '{print $1}'; }
assert_preserved_data() {
  [ "$(hash_of /etc/xkeenwrt/profiles/home.yaml)" = "$(cat /tmp/xk-remove-pending-profile.sha256)" ] || fail profile-config-changed
  [ "$(hash_of "$(cat /tmp/xk-remove-pending-history-path)")" = "$(cat /tmp/xk-remove-pending-history.sha256)" ] || fail history-json-changed
  [ "$(hash_of /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml)" = "$(cat /tmp/xk-remove-pending-asset.sha256)" ] || fail synthetic-asset-changed
  [ "$(hash_of /etc/xkeenwrt/other/sentinel)" = "$(cat /tmp/xk-remove-pending-sentinel.sha256)" ] || fail foreign-sentinel-changed
}

wait_for_cleanup_complete() {
  cleanup_count=0
  while [ "$cleanup_count" -lt 30 ]; do
    if remove_status && [ "$request_kind" = remove ] && [ "$request_state" = cleanup_complete ]; then
      return 0
    fi
    cleanup_count=$((cleanup_count + 1))
    sleep 1
  done
  return 1
}

cleanup_injected_processes() {
  if [ -n "$prepare_pid" ] && [ -z "$prepare_starttime" ]; then
    waiter_identity=$(proc_state_starttime "$prepare_pid") || waiter_identity=
    set -- $waiter_identity
    prepare_starttime=${2:-}
  fi
  if prepare_waiter_matches; then
    kill -TERM "$prepare_pid" 2>/dev/null || :
    waiter_status=0
    wait "$prepare_pid" 2>/dev/null || waiter_status=$?
  fi
  if [ "$helper_stopped" = yes ] && rescue_identity_matches stopped; then
    if kill -CONT "$rescue_pid" 2>/dev/null; then
      helper_stopped=no
      if [ "$request_persisted" = yes ]; then wait_for_cleanup_complete || :; fi
    fi
  fi
}

diagnostics() {
  printf 'REMOVE_PENDING_DIAG_STAGE=%s\n' "$stage"
  for log in /tmp/xk-remove-pending-install.log /tmp/xk-remove-pending-apk-help.log \
    /tmp/xk-remove-pending-remove.log /tmp/xk-remove-pending-runtime.log \
    /tmp/xk-remove-pending-waiter.log; do
    if [ -f "$log" ]; then
      printf 'REMOVE_PENDING_LOG_BEGIN=%s\n' "$log"
      tail -n 80 "$log"
      printf 'REMOVE_PENDING_LOG_END=%s\n' "$log"
    fi
  done
  if [ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ]; then
    if remove_status; then
      printf 'REMOVE_PENDING_DIAG_RECEIPT=%s/%s\n' "$request_kind" "$request_state"
    else
      printf 'REMOVE_PENDING_DIAG_RECEIPT=unavailable\n'
    fi
  else
    printf 'REMOVE_PENDING_DIAG_RECEIPT=helper-absent\n'
  fi
  if [ -r /sys/fs/cgroup/xkeenwrt/core/cgroup.events ]; then
    populated=$(sed -n 's/^populated //p' /sys/fs/cgroup/xkeenwrt/core/cgroup.events)
    printf 'REMOVE_PENDING_DIAG_CORE_CGROUP=present,populated=%s\n' "${populated:-unknown}"
  else
    printf 'REMOVE_PENDING_DIAG_CORE_CGROUP=absent\n'
  fi
  if [ -n "$rescue_pid" ] && rescue_identity_matches any; then
    if rescue_lock_held; then lock=held; else lock=unverified; fi
    printf 'REMOVE_PENDING_DIAG_RESCUE=identity-match,lock-%s\n' "$lock"
    diagnose_lock_record "$rescue_pid" recovery.lock RECOVERY_LOCK
    diagnose_lock_record "$rescue_pid" mutation.lock MUTATION_LOCK
  else
    printf 'REMOVE_PENDING_DIAG_RESCUE=identity-unavailable\n'
  fi
  for service in xkeenwrt-runtime xkeenwrt-ui xkeenwrt-core xkeenwrt-rescue; do
    if service_running_status "$service" > /tmp/xk-remove-pending-diag-running; then
      printf 'REMOVE_PENDING_DIAG_PROCD_%s=%s\n' "$service" "$(cat /tmp/xk-remove-pending-diag-running)"
    else
      printf 'REMOVE_PENDING_DIAG_PROCD_%s=error-%s\n' "$service" "$service_failure"
    fi
  done
}

# The reboot-only verifier sources these already-proved, read-only helpers.
if [ "${XK_REMOVE_PENDING_LIBRARY:-}" = yes ]; then
  return 0
fi

on_exit() {
  result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then
    printf 'REMOVE_PENDING_FAIL=%s\n' "${failure:-$stage:exit-$result}"
    cleanup_injected_processes
    diagnostics
  fi
}
trap on_exit EXIT

grep -qw xkeenwrt.isolation_lab=1 /proc/cmdline || fail isolation
[ "$(cat /etc/xkeenwrt-isolation-lab)" = xkeenwrt-validator-lab-v1 ] || fail isolation-marker
[ "$(uname -m)" = x86_64 ] || fail architecture
[ "$(for i in /sys/class/net/*; do printf '%s ' "${i##*/}"; done)" = 'lo ' ] || fail network-device
if [ "$reboot_mode" = yes ]; then
  stage=preflight-persistence
  grep -qw xkeenwrt.remove_reboot_lab=1 /proc/cmdline || fail reboot-cmdline
  [ "$(cat /etc/xkeenwrt-remove-reboot-lab-v1)" = xkeenwrt-remove-reboot-lab-v1 ] || fail reboot-marker-content
  [ "$(cat /sys/block/vda/size)" = 196608 ] || fail reboot-vda-size
  etc_mount_count=$(awk '$2 == "/etc" && $3 == "ext4" { count++ } END { print count + 0 }' /proc/mounts)
  etc_mount_source=$(awk '$2 == "/etc" && $3 == "ext4" { print $1 }' /proc/mounts)
  [ "$etc_mount_count" = 1 ] && [ "$etc_mount_source" = /dev/vda ] || fail reboot-etc-not-on-vda
  printf 'REMOVE_PENDING_REBOOT_ETC_MOUNT=PASS,source=%s,count=%s\n' "$etc_mount_source" "$etc_mount_count"
fi
cd /usr/share/xkeen-lab-packages

apk_revision=0.1-r2
baseline_revision=r2
if [ "$reboot_mode" = yes ]; then apk_revision=0.1-r3; baseline_revision=r3; stage=install-r3; else stage=install-r2; fi
apk add --no-network --allow-untrusted --force-non-repository "./xkeenwrt-core-$apk_revision.apk" "./xkeenwrt-ui-$apk_revision.apk" > /tmp/xk-remove-pending-install.log 2>&1 || fail apk-install
/usr/bin/xkeenwrt-ui package-version | grep -qx "$apk_revision" || fail package-version
/usr/bin/xkeenwrt-ui package-check || fail package-check
! pidof mihomo >/dev/null 2>&1 || fail install-started-core
! pidof xkeenwrt-ui >/dev/null 2>&1 || fail install-started-ui

stage=activate-${baseline_revision}-http
./runtime-package-smoke.sh --second-apply > /tmp/xk-remove-pending-runtime.log 2>&1 || fail runtime-smoke
grep -qx 'LAB_RUNTIME_PASS=auth,save,validate,apply,control,stop,start' /tmp/xk-remove-pending-runtime.log || fail runtime-smoke-result
grep -qx LAB_HISTORY_SECOND_APPLY=PASS /tmp/xk-remove-pending-runtime.log || fail second-apply-history
grep '^LAB_HTTP_PREAUTH_' /tmp/xk-remove-pending-runtime.log || fail loopback-preauth-snapshot-missing
pidof mihomo >/dev/null 2>&1 || fail core-not-running
[ -f /etc/xkeenwrt/rescue/xkeenwrt-recovery ] && [ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail persistent-rescue-missing
[ -f /etc/init.d/xkeenwrt-rescue ] || fail persistent-rescue-init-missing
[ -L /etc/rc.d/S09xkeenwrt-rescue ] && [ -L /etc/rc.d/K91xkeenwrt-rescue ] || fail persistent-rescue-boot-links-missing
[ "$(sed -n 's/^populated //p' /sys/fs/cgroup/xkeenwrt/core/cgroup.events)" = 1 ] || fail core-cgroup-not-active

stage=seed-preservation-data
if [ "$reboot_mode" = yes ]; then
  state_dir=/etc/xkeenwrt-lab-reboot
  [ ! -e "$state_dir" ] || fail reboot-state-already-exists
  mkdir -m 700 "$state_dir" || fail reboot-state-create
  [ ! -e /etc/xkeenwrt-remove-reboot-foreign-sentinel ] || fail foreign-sentinel-already-exists
  printf 'foreign reboot sentinel\n' > /etc/xkeenwrt-remove-reboot-foreign-sentinel || fail foreign-sentinel-create
  chmod 600 /etc/xkeenwrt-remove-reboot-foreign-sentinel || fail foreign-sentinel-mode
  hash_of /etc/xkeenwrt-remove-reboot-foreign-sentinel > /tmp/xk-remove-pending-foreign-sentinel.sha256
fi
[ -f /etc/xkeenwrt/profiles/home.yaml ] || fail profile-missing
history_json_path=
for candidate in /etc/xkeenwrt/history/*.json; do
  if [ -f "$candidate" ]; then history_json_path=$candidate; break; fi
done
[ -n "$history_json_path" ] || fail history-json-missing
mkdir -p /etc/xkeenwrt/assets/lab-preservation/providers/rules /etc/xkeenwrt/other
chmod 700 /etc/xkeenwrt/assets /etc/xkeenwrt/assets/lab-preservation \
  /etc/xkeenwrt/assets/lab-preservation/providers /etc/xkeenwrt/assets/lab-preservation/providers/rules
printf 'payload: synthetic-preservation\n' > /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml
printf 'foreign sentinel\n' > /etc/xkeenwrt/other/sentinel
chmod 600 /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml /etc/xkeenwrt/other/sentinel
hash_of /etc/xkeenwrt/profiles/home.yaml > /tmp/xk-remove-pending-profile.sha256
printf '%s\n' "$history_json_path" > /tmp/xk-remove-pending-history-path
hash_of "$history_json_path" > /tmp/xk-remove-pending-history.sha256
hash_of /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml > /tmp/xk-remove-pending-asset.sha256
hash_of /etc/xkeenwrt/other/sentinel > /tmp/xk-remove-pending-sentinel.sha256
printf 'REMOVE_PENDING_BASELINE=active-%s,real-history-json\n' "$baseline_revision"

stage=ensure-persistent-rescue-procd
service_running_status xkeenwrt-rescue > /tmp/xk-remove-pending-rescue-running || fail rescue-service-status-$service_failure
if [ "$(cat /tmp/xk-remove-pending-rescue-running)" != true ]; then
  /etc/init.d/xkeenwrt-rescue start || fail rescue-start
fi
rescue_ready=no
for n in 1 2 3 4 5 6; do
  if capture_rescue_identity && rescue_identity_matches running && rescue_lock_held && ! rescue_mutation_lock_held; then rescue_ready=yes; break; fi
  sleep 1
done
[ "$rescue_ready" = yes ] || fail rescue-identity-not-proved
printf 'REMOVE_PENDING_HELPER_PID=%s\n' "$rescue_pid"
printf 'REMOVE_PENDING_HELPER_STARTTIME=%s\n' "$rescue_starttime"
printf 'REMOVE_PENDING_HELPER_EXE_SHA256=%s\n' "$rescue_sha256"
printf 'REMOVE_PENDING_PROCD_PID=%s\n' "$rescue_pid"
printf 'REMOVE_PENDING_HELPER_IDENTITY=PASS\n'
printf 'REMOVE_PENDING_LOCKS=RECOVERY_HELD_MUTATION_FREE\n'

stage=preflight-apk-scripts-option
apk_help_status=0
apk del --help > /tmp/xk-remove-pending-apk-help.log 2>&1 || apk_help_status=$?
grep -Fq -- '--scripts[=BOOL]' /tmp/xk-remove-pending-apk-help.log || fail apk-scripts-option-unavailable
printf 'REMOVE_PENDING_APK_HELP_EXIT=%s\n' "$apk_help_status"
printf 'REMOVE_PENDING_APK_SCRIPTS_OPTION=verified-by-help-content\n'

stage=stop-exact-rescue-helper
rescue_identity_matches running && rescue_lock_held && ! rescue_mutation_lock_held || fail rescue-identity-before-stop
kill -STOP "$rescue_pid" || fail rescue-sigstop
helper_stopped=yes
stopped=no
for n in 1 2; do
  if rescue_identity_matches stopped && rescue_lock_held && ! rescue_mutation_lock_held; then stopped=yes; break; fi
  sleep 1
done
[ "$stopped" = yes ] || fail rescue-not-stopped-with-lock
printf 'REMOVE_PENDING_HELPER_STOPPED=PASS\n'

stage=prepare-remove-durable-request
/etc/xkeenwrt/rescue/xkeenwrt-recovery --prepare-remove > /tmp/xk-remove-pending-waiter.log 2>&1 &
prepare_pid=$!
waiter_ready=no
for n in 1 2 3; do
  waiter_identity=$(proc_state_starttime "$prepare_pid") || waiter_identity=
  set -- $waiter_identity
  if [ -n "${2:-}" ]; then prepare_starttime=$2; fi
  if prepare_waiter_matches; then
    waiter_ready=yes
    break
  fi
  sleep 1
done
[ "$waiter_ready" = yes ] || fail prepare-waiter-not-identified
request_ready=no
for n in 1 2 3 4 5 6 7 8 9; do
  if remove_status && [ "$request_kind" = remove ] && [ "$request_state" = requested ]; then request_ready=yes; break; fi
  sleep 1
done
[ "$request_ready" = yes ] || fail durable-request-not-requested
request_persisted=yes
pending_owner_id=$request_owner_id
pending_request_id=$request_request_id
pending_receipt_sha256=$(hash_of /etc/xkeenwrt/removal.json)
[ "$pending_owner_id" = "$(cat /etc/xkeenwrt/owner-id)" ] || fail request-owner-mismatch
[ -n "$pending_request_id" ] || fail request-id-missing
rescue_identity_matches stopped && rescue_lock_held && ! rescue_mutation_lock_held || fail rescue-changed-before-payload-removal
printf 'REMOVE_PENDING_REQUESTED=PASS\n'

stage=interrupt-only-prepare-waiter
prepare_waiter_matches || fail prepare-waiter-identity-before-signal
kill -TERM "$prepare_pid" || fail prepare-waiter-term
prepare_wait_status=0
wait "$prepare_pid" 2>/dev/null || prepare_wait_status=$?
prepare_pid=
[ "$prepare_wait_status" -ne 0 ] || fail prepare-waiter-not-interrupted
remove_status && [ "$request_kind" = remove ] && [ "$request_state" = requested ] \
  && [ "$request_owner_id" = "$pending_owner_id" ] && [ "$request_request_id" = "$pending_request_id" ] \
  || fail request-changed-after-waiter-interruption
rescue_identity_matches stopped && rescue_lock_held && ! rescue_mutation_lock_held || fail helper-changed-after-waiter-interruption
printf 'REMOVE_PENDING_WAITER_INTERRUPTED=PASS\n'
printf 'REMOVE_PENDING_REQUEST_ID_STABLE=PASS\n'

stage=remove-apk-payload-without-scripts
apk --scripts=no del --no-network xkeenwrt-ui xkeenwrt-core > /tmp/xk-remove-pending-remove.log 2>&1 || fail apk-remove-payload
for path in /usr/bin/xkeenwrt-ui /usr/libexec/xkeenwrt/mihomo \
  /usr/libexec/xkeenwrt/xkeenwrt-validate /usr/libexec/xkeenwrt/xkeenwrt-recovery \
  /usr/libexec/xkeenwrt/init/xkeenwrt-runtime /usr/libexec/xkeenwrt/init/xkeenwrt-ui \
  /usr/libexec/xkeenwrt/init/xkeenwrt-core /usr/libexec/xkeenwrt/init/xkeenwrt-recovery; do
  [ ! -e "$path" ] || fail "package-payload-remains-${path##*/}"
done
[ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] && [ -f /etc/init.d/xkeenwrt-rescue ] || fail persistent-rescue-lost-with-payload
[ "$(hash_of /etc/xkeenwrt/rescue/xkeenwrt-recovery)" = "$rescue_sha256" ] || fail persistent-rescue-elf-changed
remove_status && [ "$request_kind" = remove ] && [ "$request_state" = requested ] \
  && [ "$request_owner_id" = "$pending_owner_id" ] && [ "$request_request_id" = "$pending_request_id" ] \
  || fail request-not-pending-after-payload-removal
[ "$(hash_of /etc/xkeenwrt/removal.json)" = "$pending_receipt_sha256" ] || fail pending-receipt-changed-during-apk-removal
rescue_identity_matches stopped && rescue_lock_held && ! rescue_mutation_lock_held || fail stopped-helper-identity-after-payload-removal
[ "$(sed -n 's/^populated //p' /sys/fs/cgroup/xkeenwrt/core/cgroup.events)" = 1 ] || fail core-cleaned-before-payload-absence
pidof mihomo >/dev/null 2>&1 || fail core-not-active-before-resume
assert_preserved_data
printf 'REMOVE_PENDING_PAYLOAD_ABSENT=PASS\n'
printf 'REMOVE_PENDING_RECEIPT_UNCHANGED=PASS\n'
printf 'REMOVE_PENDING_CORE_ACTIVE_BEFORE_RESUME=PASS\n'
printf 'REMOVE_PENDING_DATA_PRESERVED=PASS\n'

if [ "$reboot_mode" = yes ]; then
  stage=save-reboot-baseline
  preboot_boot_id=$(cat /proc/sys/kernel/random/boot_id) || fail preboot-boot-id
  identity_boot_id=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.boot_id') || fail preboot-supervisor-boot-id
  preboot_nonce=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.nonce') || fail preboot-supervisor-nonce
  [ "$identity_boot_id" = "$preboot_boot_id" ] || fail preboot-supervisor-boot-mismatch
  rescue_identity_matches stopped && rescue_lock_held && ! rescue_mutation_lock_held || fail preboot-helper-not-stopped
  remove_status && [ "$request_kind" = remove ] && [ "$request_state" = requested ] \
    && [ "$request_owner_id" = "$pending_owner_id" ] && [ "$request_request_id" = "$pending_request_id" ] \
    || fail preboot-request-changed
  [ "$(hash_of /etc/xkeenwrt/removal.json)" = "$pending_receipt_sha256" ] || fail preboot-receipt-changed
  cp /tmp/xk-remove-pending-profile.sha256 "$state_dir/profile.sha256" || fail baseline-profile-save
  cp /tmp/xk-remove-pending-history-path "$state_dir/history-path" || fail baseline-history-path-save
  cp /tmp/xk-remove-pending-history.sha256 "$state_dir/history.sha256" || fail baseline-history-save
  cp /tmp/xk-remove-pending-asset.sha256 "$state_dir/asset.sha256" || fail baseline-asset-save
  cp /tmp/xk-remove-pending-sentinel.sha256 "$state_dir/internal-sentinel.sha256" || fail baseline-internal-sentinel-save
  cp /tmp/xk-remove-pending-foreign-sentinel.sha256 "$state_dir/foreign-sentinel.sha256" || fail baseline-sentinel-save
  {
    printf 'boot_id=%s\n' "$preboot_boot_id"
    printf 'owner_id=%s\n' "$pending_owner_id"
    printf 'request_id=%s\n' "$pending_request_id"
    printf 'receipt_sha256=%s\n' "$pending_receipt_sha256"
    printf 'helper_pid=%s\n' "$rescue_pid"
    printf 'helper_starttime=%s\n' "$rescue_starttime"
    printf 'helper_nonce=%s\n' "$preboot_nonce"
    printf 'helper_sha256=%s\n' "$rescue_sha256"
  } > "$state_dir/expected" || fail reboot-expected-save
  chmod 600 "$state_dir"/* "$state_dir/expected" || fail reboot-state-mode
  printf 'REMOVE_PENDING_REBOOT_BASELINE_BOOT_ID=%s\n' "$preboot_boot_id"
  printf 'REMOVE_PENDING_REBOOT_BASELINE_OWNER_ID=%s\n' "$pending_owner_id"
  printf 'REMOVE_PENDING_REBOOT_BASELINE_REQUEST_ID=%s\n' "$pending_request_id"
  printf 'REMOVE_PENDING_REBOOT_BASELINE_RECEIPT_SHA256=%s\n' "$pending_receipt_sha256"
  printf 'REMOVE_PENDING_REBOOT_BASELINE_HELPER_EXE_SHA256=%s\n' "$rescue_sha256"
  printf 'REMOVE_PENDING_REBOOT_ARMED=PASS\n'
  sync
  stage=force-sysrq-b
  echo 1 > /proc/sys/kernel/sysrq || fail enable-sysrq
  printf 'REMOVE_PENDING_REBOOT_TRIGGER=SYSRQ_B\n' > /dev/console
  echo b > /proc/sysrq-trigger
  fail sysrq-trigger-returned
fi

stage=resume-same-helper
rescue_identity_matches stopped && rescue_lock_held || fail helper-identity-before-resume
kill -CONT "$rescue_pid" || fail helper-sigcont
helper_stopped=no
resumed=no
for n in 1 2; do
  if rescue_identity_matches running && rescue_lock_held; then resumed=yes; break; fi
  sleep 1
done
[ "$resumed" = yes ] || fail same-helper-not-resumed
wait_for_cleanup_complete || fail cleanup-complete-timeout
request_persisted=no

stage=verify-independent-cleanup
remove_status || fail final-remove-status-unavailable
[ "$request_kind" = remove ] && [ "$request_state" = cleanup_complete ] || fail final-remove-receipt
[ "$request_owner_id" = "$pending_owner_id" ] && [ "$request_request_id" = "$pending_request_id" ] || fail final-request-identity-changed
[ ! -e /usr/bin/xkeenwrt-ui ] && [ ! -e /usr/libexec/xkeenwrt/mihomo ] || fail package-payload-returned
[ "$(sed -n 's/^populated //p' /sys/fs/cgroup/xkeenwrt/core/cgroup.events)" = 0 ] || fail core-cgroup-not-empty
! pidof mihomo >/dev/null 2>&1 || fail mihomo-still-running
! pidof xkeenwrt-ui >/dev/null 2>&1 || fail xkeenwrt-ui-process-still-running
service_is_stopped xkeenwrt-runtime
service_is_stopped xkeenwrt-ui
service_is_stopped xkeenwrt-core
rescue_identity_matches running && rescue_lock_held || fail persistent-rescue-not-running-after-cleanup
assert_preserved_data
printf 'REMOVE_PENDING_CLEANUP_COMPLETE=PASS\n'
printf 'REMOVE_PENDING_SAME_HELPER=PASS\n'
printf 'REMOVE_PENDING_FINAL_DATA_PRESERVED=PASS\n'
printf 'REMOVE_PENDING_PASS=durable-request,payload-absent,resume-same-rescue,cleanup-complete\n'
trap - EXIT
