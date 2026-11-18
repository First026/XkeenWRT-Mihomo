#!/bin/sh
# One r1 -> r2 rescue replacement check in a marked, no-NIC OpenWrt VM.
set -eu
stage=guard
failure=
trap 'exit_status=$?; if [ "$exit_status" -ne 0 ]; then printf "UPGRADE_FAIL=%s\n" "${failure:-$stage}"; for log in /tmp/xk-upgrade-install-r1.log /tmp/xk-upgrade-install-r2.log; do if [ -f "$log" ]; then printf "UPGRADE_APK_LOG_BEGIN=%s\n" "$log"; cat "$log"; printf "UPGRADE_APK_LOG_END=%s\n" "$log"; fi; done; logread > /tmp/xk-upgrade-log 2>/dev/null || :; fi' EXIT
fail() { failure="$stage:$1"; exit 1; }
grep -qw xkeenwrt.isolation_lab=1 /proc/cmdline || fail isolation
[ "$(cat /etc/xkeenwrt-isolation-lab)" = xkeenwrt-validator-lab-v1 ] || fail marker
cd /usr/share/xkeen-lab-packages

# Return false for a missing service or a valid empty instances table. Keep
# ubus transport failures, invalid JSON and malformed non-empty instances fatal.
service_running_status() {
  service_name=$1
  service_json_file=/tmp/xk-upgrade-service-list.json
  service_json_error=/tmp/xk-upgrade-jsonfilter-error
  service_failure=invalid-response
  ubus call service list "{\"name\":\"$service_name\"}" > "$service_json_file" || {
    service_failure=transport
    return 1
  }
  service_root=$(jsonfilter -i "$service_json_file" -e '@' 2> "$service_json_error") || {
    service_failure=invalid-json
    return 1
  }
  case "$service_root" in
    \{*\}) ;;
    *) service_failure=invalid-json; return 1 ;;
  esac
  if service_object=$(jsonfilter -i "$service_json_file" -e "@[\"$service_name\"]" 2> "$service_json_error"); then
    :
  else
    [ ! -s "$service_json_error" ] || { service_failure=invalid-json; return 1; }
    printf 'false\n'
    return 0
  fi
  service_instances=$(jsonfilter -i "$service_json_file" -e "@[\"$service_name\"].instances" 2> "$service_json_error") || return 1
  case "$service_instances" in
    ''|'{}') printf 'false\n'; return 0 ;;
    \{*\}) ;;
    *) return 1 ;;
  esac
  service_running=$(jsonfilter -i "$service_json_file" -e "@[\"$service_name\"].instances.*.running" 2> "$service_json_error") || return 1
  service_running_any=false
  while IFS= read -r service_instance_running; do
    case "$service_instance_running" in
      true) service_running_any=true ;;
      false) ;;
      *) return 1 ;;
    esac
  done <<EOF
$service_running
EOF
  printf '%s\n' "$service_running_any"
}

stage=install-r1
apk add --no-network --allow-untrusted --force-non-repository ./xkeenwrt-core-0.1-r1.apk ./xkeenwrt-ui-0.1-r1.apk >/tmp/xk-upgrade-install-r1.log 2>&1 || fail apk-r1
/usr/bin/xkeenwrt-ui package-version | grep -qx '0.1-r1' || fail version-r1
/usr/bin/xkeenwrt-ui package-check || fail package-r1

stage=activate-manual-r1
./runtime-package-smoke.sh > /tmp/xk-upgrade-manual-r1.log 2>&1 || { cat /tmp/xk-upgrade-manual-r1.log; fail manual-r1; }
grep -qx 'LAB_RUNTIME_PASS=auth,save,validate,apply,control,stop,start' /tmp/xk-upgrade-manual-r1.log || fail manual-r1-result
pidof mihomo >/dev/null || fail r1-core-not-running
[ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail rescue-not-provisioned
printf 'UPGRADE_R1_ACTIVE=manual-core-running\n'

stage=upgrade-r2
apk add --no-network --allow-untrusted --force-non-repository ./xkeenwrt-core-0.1-r2.apk ./xkeenwrt-ui-0.1-r2.apk >/tmp/xk-upgrade-install-r2.log 2>&1 || fail apk-r2
/usr/bin/xkeenwrt-ui package-version | grep -qx '0.1-r2' || fail version-r2
/usr/bin/xkeenwrt-ui package-check || fail package-r2
! pidof mihomo >/dev/null 2>&1 || fail core-auto-started
service_running_status xkeenwrt-runtime > /tmp/xk-upgrade-runtime-running || fail "runtime-status-$service_failure"
service_running_status xkeenwrt-ui > /tmp/xk-upgrade-ui-running || fail "ui-status-$service_failure"
runtime_running=$(cat /tmp/xk-upgrade-runtime-running)
ui_running=$(cat /tmp/xk-upgrade-ui-running)
[ "$runtime_running" != true ] || fail runtime-auto-started
[ "$ui_running" != true ] || fail ui-auto-started
/etc/xkeenwrt/rescue/xkeenwrt-recovery --remove-status > /tmp/xk-upgrade-status.json || fail rescue-status
[ "$(jsonfilter -i /tmp/xk-upgrade-status.json -e '@.kind')" = upgrade ] || fail receipt-kind
[ "$(jsonfilter -i /tmp/xk-upgrade-status.json -e '@.state')" = cleanup_complete ] || fail receipt-state
printf 'UPGRADE_R2_STOPPED_RECEIPT=PASS\n'

stage=start-management-services
/etc/init.d/xkeenwrt-runtime start || fail runtime-start
/etc/init.d/xkeenwrt-ui start || fail ui-start
ready=no
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if [ -S /var/run/xkeenwrt/control.sock ] && wget -q -O /dev/null --timeout=2 --no-proxy http://127.0.0.1:1000/api/auth/login; then ready=yes; break; fi
  sleep 1
done
[ "$ready" = yes ] || fail management-unavailable

http() {
  method=$1
  url=$2
  length=$(wc -c < /tmp/xk-upgrade-request)
  {
    printf '%s %s HTTP/1.1\r\nHost: 127.0.0.1:1000\r\nOrigin: http://127.0.0.1:1000\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %s\r\n' "$method" "$url" "$length"
    [ -z "${cookie:-}" ] || printf 'Cookie: %s\r\n' "$cookie"
    printf '\r\n'
    cat /tmp/xk-upgrade-request
  } > /tmp/xkeenwrt-http-wire
  rm -f /tmp/xkeenwrt-response /tmp/xkeenwrt-response-clean /tmp/xkeenwrt-body
  /usr/libexec/xkeenwrt-integration/http-wire || { status=transport; return 1; }
  tr -d '\r' < /tmp/xkeenwrt-response > /tmp/xkeenwrt-response-clean || { status=invalid-response; return 1; }
  sed '1,/^$/d' /tmp/xkeenwrt-response-clean > /tmp/xkeenwrt-body || { status=invalid-response; return 1; }
  status=$(sed -n '1s/^HTTP\/[^ ]* \([0-9][0-9][0-9]\).*/\1/p' /tmp/xkeenwrt-response-clean)
}
report_http_error() {
  printf 'UPGRADE_HTTP_ERROR url=%s status=%s\n' "$url" "${status:-unavailable}"
  if [ -s /tmp/xkeenwrt-body ]; then
    printf 'UPGRADE_HTTP_ERROR_BODY_BEGIN\n'
    head -c 4096 /tmp/xkeenwrt-body
    printf '\nUPGRADE_HTTP_ERROR_BODY_END\n'
  fi
}
upgrade_failure_snapshot() {
  fence=/etc/xkeenwrt/rescue/rescue-replacement.json
  receipt=/etc/xkeenwrt/removal.json
  if [ -f "$fence" ]; then
    fence_phase=$(jsonfilter -i "$fence" -e '@.phase' 2>/dev/null) || fence_phase=unreadable
    [ -n "$fence_phase" ] || fence_phase=unreadable
  else
    fence_phase=absent
  fi
  if [ -f "$receipt" ]; then
    receipt_kind=$(jsonfilter -i "$receipt" -e '@.kind' 2>/dev/null) || receipt_kind=unreadable
    receipt_state=$(jsonfilter -i "$receipt" -e '@.state' 2>/dev/null) || receipt_state=unreadable
  else
    receipt_kind=absent
    receipt_state=absent
  fi
  printf 'UPGRADE_DIAG_STAGE=%s\n' "$stage"
  printf 'UPGRADE_DIAG_FENCE_PHASE=%s\n' "$fence_phase"
  printf 'UPGRADE_DIAG_RECEIPT=%s/%s\n' "$receipt_kind" "$receipt_state"
  for cgroup in core recovery; do
    path="/sys/fs/cgroup/xkeenwrt/$cgroup"
    if [ -d "$path" ]; then
      populated=unknown
      if [ -r "$path/cgroup.events" ]; then
        value=$(sed -n 's/^populated //p' "$path/cgroup.events")
        case "$value" in 0|1) populated=$value ;; esac
      fi
      printf 'UPGRADE_DIAG_CGROUP_%s=present,populated=%s\n' "$cgroup" "$populated"
    else
      printf 'UPGRADE_DIAG_CGROUP_%s=absent\n' "$cgroup"
    fi
  done
  regular_files=0
  child_dirs=0
  child_populated=0
  other_entries=0
  recovery_parent=/sys/fs/cgroup/xkeenwrt/recovery
  if [ -d "$recovery_parent" ]; then
    for entry in "$recovery_parent"/*; do
      [ -e "$entry" ] || [ -L "$entry" ] || continue
      if [ -L "$entry" ]; then
        other_entries=$((other_entries + 1))
      elif [ -d "$entry" ]; then
        child_dirs=$((child_dirs + 1))
        if [ -r "$entry/cgroup.events" ] && [ "$(sed -n 's/^populated //p' "$entry/cgroup.events")" = 1 ]; then
          child_populated=$((child_populated + 1))
        fi
      elif [ -f "$entry" ]; then
        regular_files=$((regular_files + 1))
      else
        other_entries=$((other_entries + 1))
      fi
    done
  fi
  printf 'UPGRADE_DIAG_RECOVERY_ENTRIES=regular_files:%s,child_dirs:%s,child_populated:%s,other:%s\n' \
    "$regular_files" "$child_dirs" "$child_populated" "$other_entries"
  for service in xkeenwrt-runtime xkeenwrt-ui xkeenwrt-core xkeenwrt-rescue; do
    if service_running_status "$service" > /tmp/xk-upgrade-diag-service; then
      service_value=$(cat /tmp/xk-upgrade-diag-service)
    else
      service_value="error-$service_failure"
    fi
    printf 'UPGRADE_DIAG_PROCD_%s=%s\n' "$service" "$service_value"
  done
}

stage=login-after-upgrade
cookie=
printf '%s' '{"password":"synthetic-password-123"}' > /tmp/xk-upgrade-request
http POST /api/auth/login || { report_http_error; fail login-transport; }
[ "$status" = 200 ] || { report_http_error; fail login; }
cookie=$(sed -n 's/^[Ss]et-[Cc]ookie: \(session_id=[^;]*\).*/\1/p' /tmp/xkeenwrt-response-clean)
[ -n "$cookie" ] || fail login-cookie

stage=explicit-http-start
printf '%s' '{"action":"start"}' > /tmp/xk-upgrade-request
http POST /api/control || { report_http_error; upgrade_failure_snapshot; fail start-transport; }
[ "$status" = 200 ] || { report_http_error; upgrade_failure_snapshot; fail start-http; }
printf 'UPGRADE_HTTP_START=PASS\n'

stage=verify-new-runtime
: > /tmp/xk-upgrade-request
http GET /api/control || { report_http_error; fail status-transport; }
[ "$status" = 200 ] || { report_http_error; fail status-http; }
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.running')" = true ] || fail core-not-running-after-start
pidof mihomo >/dev/null || fail core-process-missing
receipt_path=/etc/xkeenwrt/removal.json
intent_path=/etc/xkeenwrt/rescue/rescue-replacement.json
[ ! -e "$receipt_path" ] || fail receipt-not-consumed
[ ! -e "$intent_path" ] || fail upgrade-fence-remains
new_hash=$(jsonfilter -i /usr/share/xkeenwrt/ui-manifest.json -e '@.sha256.recovery')
stored_hash=$(sed -n 's/^sha256=//p' /etc/xkeenwrt/rescue/identity)
supervisor_hash=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.exe_sha256')
supervisor_pid=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.pid')
[ "$new_hash" = "$stored_hash" ] && [ "$new_hash" = "$supervisor_hash" ] || fail helper-version
kill -0 "$supervisor_pid" 2>/dev/null || fail helper-not-running
process_hash=$(sha256sum "/proc/$supervisor_pid/exe" | awk '{print $1}')
[ "$process_hash" = "$new_hash" ] || fail helper-executable
printf 'UPGRADE_HELPER_READY=PASS\n'
printf 'UPGRADE_CORE_RUNNING=PASS\n'
printf 'UPGRADE_PASS=active-manual-r1,upgrade-r2,cleanup-receipt,explicit-http-start,new-helper-ready,core-running\n'
trap - EXIT
