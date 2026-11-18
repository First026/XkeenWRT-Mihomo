#!/bin/sh
# Active Remove -> same-build inert Reinstall and explicit Resume in one marked, no-NIC OpenWrt VM.
set -eu
stage=guard
failure=
fail() { failure="$stage:$1"; exit 1; }

http_status_error() {
  http_label=$1
  http_error_code=$(jsonfilter -i /tmp/xkeenwrt-body -e '@.code' 2>/dev/null) || http_error_code=unavailable
  printf 'ACTIVE_REMOVE_HTTP_ERROR=%s,status-%s,code-%s\n' "$http_label" "${status:-missing}" "${http_error_code:-missing}"
  fail "$http_label-http"
}

http_expect_status() {
  [ "$status" = "$1" ] || http_status_error "$2"
}

http_expect_code() {
  expected_code=$1
  http_label=$2
  actual_code=$(jsonfilter -i /tmp/xkeenwrt-body -e '@.code' 2>/dev/null) || actual_code=unavailable
  [ "$actual_code" = "$expected_code" ] || http_status_error "$http_label-code"
}

service_running_status() {
  service_name=$1
  service_json_file=/tmp/xk-active-remove-service.json
  service_json_error=/tmp/xk-active-remove-jsonfilter-error
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
  service_running_status "$service_name" > /tmp/xk-active-remove-running || fail "service-$service_name-$service_failure"
  [ "$(cat /tmp/xk-active-remove-running)" != true ] || fail "service-$service_name-still-running"
}

core_populated() {
  [ -r /sys/fs/cgroup/xkeenwrt/core/cgroup.events ] || return 1
  value=$(sed -n 's/^populated //p' /sys/fs/cgroup/xkeenwrt/core/cgroup.events)
  case "$value" in 0|1) printf '%s\n' "$value" ;; *) return 1 ;; esac
}

assert_core_stopped() {
  value=$(core_populated) || fail core-cgroup-unreadable
  [ "$value" = 0 ] || fail core-cgroup-populated
  ! pidof mihomo >/dev/null 2>&1 || fail mihomo-still-running
  ! pidof xkeenwrt-ui >/dev/null 2>&1 || fail xkeenwrt-ui-process-still-running
  service_is_stopped xkeenwrt-runtime
  service_is_stopped xkeenwrt-ui
  service_is_stopped xkeenwrt-core
}

assert_remove_receipt() {
  [ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail rescue-helper-missing
  /etc/xkeenwrt/rescue/xkeenwrt-recovery --remove-status > /tmp/xk-active-remove-status.json || fail rescue-status
  [ "$(jsonfilter -i /tmp/xk-active-remove-status.json -e '@.kind')" = remove ] || fail receipt-kind
  [ "$(jsonfilter -i /tmp/xk-active-remove-status.json -e '@.state')" = cleanup_complete ] || fail receipt-state
  receipt_owner=$(jsonfilter -i /tmp/xk-active-remove-status.json -e '@.owner_id') || fail receipt-owner
  receipt_request=$(jsonfilter -i /tmp/xk-active-remove-status.json -e '@.request_id') || fail receipt-request
  printf '%s\n' "$receipt_owner" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || fail receipt-owner-format
  printf '%s\n' "$receipt_request" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || fail receipt-request-format
  if [ -f /tmp/xk-active-remove-owner-id ]; then
    [ "$(cat /tmp/xk-active-remove-owner-id)" = "$receipt_owner" ] || fail receipt-owner-changed
    [ "$(cat /tmp/xk-active-remove-request-id)" = "$receipt_request" ] || fail receipt-request-changed
  else
    printf '%s\n' "$receipt_owner" > /tmp/xk-active-remove-owner-id
    printf '%s\n' "$receipt_request" > /tmp/xk-active-remove-request-id
  fi
  [ -f /etc/xkeenwrt/removal.json ] || fail durable-receipt-missing
  [ ! -e /etc/xkeenwrt/rescue/rescue-replacement.json ] || fail upgrade-fence-present
}

assert_core_stopped_with_ui() {
  value=$(core_populated) || fail core-cgroup-unreadable
  [ "$value" = 0 ] || fail core-cgroup-populated
  ! pidof mihomo >/dev/null 2>&1 || fail mihomo-still-running
  service_is_stopped xkeenwrt-core
  service_running_status xkeenwrt-runtime > /tmp/xk-active-remove-runtime-running || fail runtime-status-$service_failure
  [ "$(cat /tmp/xk-active-remove-runtime-running)" = true ] || fail runtime-not-running
  service_running_status xkeenwrt-ui > /tmp/xk-active-remove-ui-running || fail ui-status-$service_failure
  [ "$(cat /tmp/xk-active-remove-ui-running)" = true ] || fail ui-not-running
}

loopback_snapshot() {
  snapshot_label=$1
  link=$(ip -o link show dev lo 2>/dev/null) || link=unavailable
  printf 'ACTIVE_REMOVE_LOOPBACK_%s_LINK=%s\n' "$snapshot_label" "$link"
  addresses=$(ip -o addr show dev lo 2>/dev/null | awk '{print $4}' | tr '\n' ',') || addresses=unavailable
  [ -n "$addresses" ] || addresses=none
  printf 'ACTIVE_REMOVE_LOOPBACK_%s_ADDR=%s\n' "$snapshot_label" "$addresses"
  if ip route show table local 2>/dev/null | grep -Eq 'local 127\.0\.0\.0/8|local 127\.0\.0\.1'; then route=yes; else route=no; fi
  printf 'ACTIVE_REMOVE_LOOPBACK_%s_LOCAL_ROUTE=%s\n' "$snapshot_label" "$route"
  if netstat -lnt 2>/dev/null | grep -Eq '(^|[[:space:]])(127\.0\.0\.1:1000|0\.0\.0\.0:1000|\*:1000|\[::\]:1000)([[:space:]]|$)'; then listener=yes; else listener=no; fi
  printf 'ACTIVE_REMOVE_LOOPBACK_%s_LISTENER_1000=%s\n' "$snapshot_label" "$listener"
}

http_transport_diagnostics() {
  printf 'ACTIVE_REMOVE_HTTP_TRANSPORT=failed\n'
  loopback_snapshot TRANSPORT_FAIL
}

http() {
  method=$1
  url=$2
  length=$(wc -c < /tmp/xkeenwrt-request)
  {
    printf '%s %s HTTP/1.1\r\nHost: 127.0.0.1:1000\r\nOrigin: http://127.0.0.1:1000\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %s\r\n' "$method" "$url" "$length"
    [ -z "${cookie:-}" ] || printf 'Cookie: %s\r\n' "$cookie"
    printf '\r\n'
    cat /tmp/xkeenwrt-request
  } > /tmp/xkeenwrt-http-wire
  rm -f /tmp/xkeenwrt-response /tmp/xkeenwrt-response-clean /tmp/xkeenwrt-body
  if ! /usr/libexec/xkeenwrt-integration/http-wire; then
    http_transport_diagnostics
    return 1
  fi
  tr -d '\r' < /tmp/xkeenwrt-response > /tmp/xkeenwrt-response-clean
  sed '1,/^$/d' /tmp/xkeenwrt-response-clean > /tmp/xkeenwrt-body
  status=$(awk 'NR == 1 { print $2 }' /tmp/xkeenwrt-response-clean)
}

hash_of() { sha256sum "$1" | awk '{print $1}'; }
assert_preserved_data() {
  [ "$(hash_of /etc/xkeenwrt/profiles/home.yaml)" = "$(cat /tmp/xk-active-remove-profile.sha256)" ] || fail profile-config-changed
  [ "$(hash_of "$(cat /tmp/xk-active-remove-history-path)")" = "$(cat /tmp/xk-active-remove-history.sha256)" ] || fail real-history-changed
  [ "$(hash_of /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml)" = "$(cat /tmp/xk-active-remove-asset.sha256)" ] || fail synthetic-asset-changed
  [ "$(hash_of /etc/xkeenwrt/other/sentinel)" = "$(cat /tmp/xk-active-remove-sentinel.sha256)" ] || fail foreign-sentinel-changed
}

diagnostics() {
  printf 'ACTIVE_REMOVE_DIAG_STAGE=%s\n' "$stage"
  if [ -f /tmp/xk-active-remove-resume-status-code ]; then
    printf 'ACTIVE_REMOVE_RESUME_STATUS_HTTP=%s\n' "$(cat /tmp/xk-active-remove-resume-status-code)"
    printf 'ACTIVE_REMOVE_RESUME_STATUS_BODY_BEGIN\n'
    head -c 512 /tmp/xk-active-remove-resume-status-body
    printf '\nACTIVE_REMOVE_RESUME_STATUS_BODY_END\n'
  fi
  for log in /tmp/xk-active-remove-install.log /tmp/xk-active-remove-remove.log /tmp/xk-active-remove-reinstall.log /tmp/xk-active-remove-runtime.log; do
    if [ -f "$log" ]; then
      printf 'ACTIVE_REMOVE_APK_LOG_BEGIN=%s\n' "$log"
      tail -n 80 "$log"
      printf 'ACTIVE_REMOVE_APK_LOG_END=%s\n' "$log"
    fi
  done
  if [ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ]; then
    if /etc/xkeenwrt/rescue/xkeenwrt-recovery --remove-status > /tmp/xk-active-remove-diag-status.json 2>/dev/null; then
      kind=$(jsonfilter -i /tmp/xk-active-remove-diag-status.json -e '@.kind' 2>/dev/null) || kind=unreadable
      state=$(jsonfilter -i /tmp/xk-active-remove-diag-status.json -e '@.state' 2>/dev/null) || state=unreadable
      [ -n "$kind" ] || kind=absent
      [ -n "$state" ] || state=absent
      printf 'ACTIVE_REMOVE_DIAG_RECEIPT=%s/%s\n' "$kind" "$state"
    else
      printf 'ACTIVE_REMOVE_DIAG_RECEIPT=unavailable\n'
    fi
  else
    printf 'ACTIVE_REMOVE_DIAG_RECEIPT=helper-absent\n'
  fi
  if [ -r /sys/fs/cgroup/xkeenwrt/core/cgroup.events ]; then
    populated=$(sed -n 's/^populated //p' /sys/fs/cgroup/xkeenwrt/core/cgroup.events)
    printf 'ACTIVE_REMOVE_DIAG_CORE_CGROUP=present,populated=%s\n' "${populated:-unknown}"
  else
    printf 'ACTIVE_REMOVE_DIAG_CORE_CGROUP=absent\n'
  fi
  for service in xkeenwrt-runtime xkeenwrt-ui xkeenwrt-core xkeenwrt-rescue; do
    if service_running_status "$service" > /tmp/xk-active-remove-diag-running; then
      printf 'ACTIVE_REMOVE_DIAG_PROCD_%s=%s\n' "$service" "$(cat /tmp/xk-active-remove-diag-running)"
    else
      printf 'ACTIVE_REMOVE_DIAG_PROCD_%s=error-%s\n' "$service" "$service_failure"
    fi
  done
  for path in /usr/bin/xkeenwrt-ui /usr/libexec/xkeenwrt/mihomo /etc/xkeenwrt/rescue/xkeenwrt-recovery /etc/init.d/xkeenwrt-rescue; do
    [ -e "$path" ] && exists=yes || exists=no
    printf 'ACTIVE_REMOVE_DIAG_PATH_%s=%s\n' "${path##*/}" "$exists"
  done
}

on_exit() {
  result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then
    printf 'ACTIVE_REMOVE_FAIL=%s\n' "${failure:-$stage:exit-$result}"
    diagnostics
  fi
}
trap on_exit EXIT

grep -qw xkeenwrt.isolation_lab=1 /proc/cmdline || fail isolation
[ "$(cat /etc/xkeenwrt-isolation-lab)" = xkeenwrt-validator-lab-v1 ] || fail isolation-marker
[ "$(uname -m)" = x86_64 ] || fail architecture
[ "$(for i in /sys/class/net/*; do printf '%s ' "${i##*/}"; done)" = 'lo ' ] || fail network-device
cd /usr/share/xkeen-lab-packages

stage=install-r3
apk add --no-network --allow-untrusted --force-non-repository ./xkeenwrt-core-0.1-r3.apk ./xkeenwrt-ui-0.1-r3.apk > /tmp/xk-active-remove-install.log 2>&1 || fail apk-install
/usr/bin/xkeenwrt-ui package-version | grep -qx 0.1-r3 || fail package-version
/usr/bin/xkeenwrt-ui package-check || fail package-check-installed
[ -L /etc/init.d/xkeenwrt-runtime ] && [ -L /etc/init.d/xkeenwrt-ui ] || fail package-init-links
! pidof mihomo >/dev/null 2>&1 || fail install-started-core
! pidof xkeenwrt-ui >/dev/null 2>&1 || fail install-started-ui
service_is_stopped xkeenwrt-runtime
service_is_stopped xkeenwrt-ui

stage=activate-r3
./runtime-package-smoke.sh --second-apply > /tmp/xk-active-remove-runtime.log 2>&1 || { tail -n 80 /tmp/xk-active-remove-runtime.log; fail runtime-smoke; }
grep -qx 'LAB_RUNTIME_PASS=auth,save,validate,apply,control,stop,start' /tmp/xk-active-remove-runtime.log || fail runtime-smoke-result
grep -qx LAB_HISTORY_SECOND_APPLY=PASS /tmp/xk-active-remove-runtime.log || fail history-second-apply
pidof mihomo >/dev/null 2>&1 || fail core-not-running
service_running_status xkeenwrt-runtime > /tmp/xk-active-remove-runtime-status || fail runtime-status-$service_failure
[ "$(cat /tmp/xk-active-remove-runtime-status)" = true ] || fail runtime-not-running
service_running_status xkeenwrt-ui > /tmp/xk-active-remove-ui-status || fail ui-status-$service_failure
[ "$(cat /tmp/xk-active-remove-ui-status)" = true ] || fail ui-not-running
[ "$(core_populated)" = 1 ] || fail core-cgroup-not-populated
[ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail rescue-not-provisioned
[ -f /etc/init.d/xkeenwrt-rescue ] || fail rescue-init-not-provisioned
[ -L /etc/rc.d/S09xkeenwrt-rescue ] && [ -L /etc/rc.d/K91xkeenwrt-rescue ] || fail rescue-boot-links

# Keep the real profile and second-apply history JSON, plus a separate synthetic
# asset and foreign sentinel. No provider integration or network mode is used.
stage=seed-preservation-data
[ -f /etc/xkeenwrt/profiles/home.yaml ] || fail profile-missing
history_json_path=
for candidate in /etc/xkeenwrt/history/*.json; do
  if [ -f "$candidate" ]; then history_json_path=$candidate; break; fi
done
[ -n "$history_json_path" ] || fail real-history-json-missing
mkdir -p /etc/xkeenwrt/assets/lab-preservation/providers/rules /etc/xkeenwrt/other
chmod 700 /etc/xkeenwrt/assets /etc/xkeenwrt/assets/lab-preservation \
  /etc/xkeenwrt/assets/lab-preservation/providers /etc/xkeenwrt/assets/lab-preservation/providers/rules
printf 'payload: synthetic-preservation\n' > /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml
printf 'foreign sentinel\n' > /etc/xkeenwrt/other/sentinel
chmod 600 /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml /etc/xkeenwrt/other/sentinel
hash_of /etc/xkeenwrt/profiles/home.yaml > /tmp/xk-active-remove-profile.sha256
printf '%s\n' "$history_json_path" > /tmp/xk-active-remove-history-path
hash_of "$history_json_path" > /tmp/xk-active-remove-history.sha256
hash_of /etc/xkeenwrt/assets/lab-preservation/providers/rules/0.yaml > /tmp/xk-active-remove-asset.sha256
hash_of /etc/xkeenwrt/other/sentinel > /tmp/xk-active-remove-sentinel.sha256
printf 'ACTIVE_REMOVE_BASELINE=active-r3\n'

stage=remove-active-r2
apk del --no-network xkeenwrt-ui xkeenwrt-core > /tmp/xk-active-remove-remove.log 2>&1 || fail apk-remove
assert_core_stopped
assert_remove_receipt
[ -f /etc/init.d/xkeenwrt-rescue ] && [ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail persistent-rescue-removed
[ -L /etc/rc.d/S09xkeenwrt-rescue ] && [ -L /etc/rc.d/K91xkeenwrt-rescue ] || fail persistent-rescue-boot-links-removed
service_running_status xkeenwrt-rescue > /tmp/xk-active-remove-rescue-status || fail rescue-service-status-$service_failure
[ "$(cat /tmp/xk-active-remove-rescue-status)" = true ] || fail rescue-service-not-running
for path in /usr/bin/xkeenwrt-ui /usr/libexec/xkeenwrt/mihomo \
  /usr/libexec/xkeenwrt/xkeenwrt-validate /usr/libexec/xkeenwrt/xkeenwrt-recovery \
  /usr/libexec/xkeenwrt/init/xkeenwrt-runtime /usr/libexec/xkeenwrt/init/xkeenwrt-ui \
  /usr/libexec/xkeenwrt/init/xkeenwrt-core /usr/libexec/xkeenwrt/init/xkeenwrt-recovery; do
  [ ! -e "$path" ] || fail "package-payload-remains-${path##*/}"
done
for service in xkeenwrt-runtime xkeenwrt-ui xkeenwrt-core xkeenwrt-recovery; do
  [ ! -L "/etc/init.d/$service" ] || fail "package-init-link-remains-$service"
done
assert_preserved_data
printf 'ACTIVE_REMOVE_REMOVED=stopped,rescue,remove-receipt,payload-absent,data-preserved\n'

stage=reinstall-same-r3
apk add --no-network --allow-untrusted --force-non-repository ./xkeenwrt-core-0.1-r3.apk ./xkeenwrt-ui-0.1-r3.apk > /tmp/xk-active-remove-reinstall.log 2>&1 || fail apk-reinstall
/usr/bin/xkeenwrt-ui package-version | grep -qx 0.1-r3 || fail reinstall-version
/usr/bin/xkeenwrt-ui package-check || fail reinstall-package-check
[ -x /usr/bin/xkeenwrt-ui ] && [ -x /usr/libexec/xkeenwrt/mihomo ] || fail reinstall-payload-missing
[ -L /etc/init.d/xkeenwrt-runtime ] && [ -L /etc/init.d/xkeenwrt-ui ] || fail reinstall-init-links
! pidof mihomo >/dev/null 2>&1 || fail reinstall-started-core
! pidof xkeenwrt-ui >/dev/null 2>&1 || fail reinstall-started-ui
service_is_stopped xkeenwrt-runtime
service_is_stopped xkeenwrt-ui
service_is_stopped xkeenwrt-core
assert_remove_receipt
[ -f /etc/init.d/xkeenwrt-rescue ] && [ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail reinstall-rescue-missing
service_running_status xkeenwrt-rescue > /tmp/xk-active-remove-rescue-status || fail reinstall-rescue-status-$service_failure
[ "$(cat /tmp/xk-active-remove-rescue-status)" = true ] || fail reinstall-rescue-not-running
assert_preserved_data
printf 'ACTIVE_REMOVE_REINSTALL=inert-r3,remove-fence-retained,data-preserved\n'

stage=resume-ui-runtime-start
/etc/init.d/xkeenwrt-runtime start || fail runtime-start-after-reinstall
/etc/init.d/xkeenwrt-ui start || fail ui-start-after-reinstall
control_ready=no
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if service_running_status xkeenwrt-runtime > /tmp/xk-active-remove-runtime-running 2>/dev/null \
    && [ "$(cat /tmp/xk-active-remove-runtime-running)" = true ] \
    && service_running_status xkeenwrt-ui > /tmp/xk-active-remove-ui-running 2>/dev/null \
    && [ "$(cat /tmp/xk-active-remove-ui-running)" = true ] \
    && netstat -lnt 2>/dev/null | grep -Eq '(^|[[:space:]])(127\.0\.0\.1:1000|0\.0\.0\.0:1000|\*:1000|\[::\]:1000)([[:space:]]|$)'; then
    control_ready=yes
    break
  fi
  sleep 1
done
[ "$control_ready" = yes ] || fail authenticated-control-not-ready
loopback_snapshot PREAUTH
stage=authenticated-control
cookie=
printf '%s' '{"password":"synthetic-password-123"}' > /tmp/xkeenwrt-request
http POST /api/auth/login || fail login-transport
http_expect_status 200 login
cookie=$(sed -n 's/^[Ss]et-[Cc]ookie: \(session_id=[^;]*\).*/\1/p' /tmp/xkeenwrt-response-clean | head -n 1)
[ -n "$cookie" ] || fail login-cookie

: > /tmp/xkeenwrt-request
http GET /api/platform || fail platform-transport
http_expect_status 200 platform
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.platform')" = openwrt ] || fail platform-name
platform_capabilities=$(jsonfilter -i /tmp/xkeenwrt-body -e '@.capabilities.*') || fail platform-capabilities
[ "$(printf '%s\n' "$platform_capabilities" | sort | tr '\n' ',')" = 'core_control,platform_inspect,' ] || fail platform-capability-scope

: > /tmp/xkeenwrt-request
http GET /api/control || fail control-status-transport
http_expect_status 200 control-status
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.success')" = true ] || fail control-status-success
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.running')" = false ] || fail control-not-stopped
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.coreControl')" = true ] || fail control-capability-missing
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.resumeRequestId')" = "$(cat /tmp/xk-active-remove-request-id)" ] || fail control-request-mismatch
assert_core_stopped_with_ui
printf 'ACTIVE_REMOVE_CONTROL=authenticated,runtime-ui-only,exact-request-id,core-stopped\n'

stage=ordinary-start-before-resume
printf '%s' '{"action":"start"}' > /tmp/xkeenwrt-request
http POST /api/control || fail ordinary-start-transport
http_expect_status 409 ordinary-start
http_expect_code CONFLICT ordinary-start
assert_remove_receipt
assert_core_stopped_with_ui
assert_preserved_data
printf 'ACTIVE_REMOVE_START_REFUSED=remove-fence-retained,core-stopped\n'

stage=wrong-request-resume
receipt_before_wrong_resume=$(hash_of /etc/xkeenwrt/removal.json)
printf '%s' '{"action":"resume_after_reinstall","request_id":"00000000-0000-4000-8000-000000000099"}' > /tmp/xkeenwrt-request
http POST /api/control || fail wrong-resume-transport
http_expect_status 409 wrong-resume
http_expect_code CONFLICT wrong-resume
[ "$(hash_of /etc/xkeenwrt/removal.json)" = "$receipt_before_wrong_resume" ] || fail wrong-resume-receipt-changed
assert_remove_receipt
assert_core_stopped_with_ui
printf 'ACTIVE_REMOVE_WRONG_REQUEST=conflict,receipt-unchanged,core-stopped\n'

stage=explicit-resume
printf '{"action":"resume_after_reinstall","request_id":"%s"}' "$(cat /tmp/xk-active-remove-request-id)" > /tmp/xkeenwrt-request
http POST /api/control || fail resume-transport
http_expect_status 200 resume
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.success')" = true ] || fail resume-not-successful
[ ! -e /etc/xkeenwrt/removal.json ] || fail resume-receipt-retained
if /etc/xkeenwrt/rescue/xkeenwrt-recovery --remove-status > /tmp/xk-active-remove-status.json; then
  [ "$(jsonfilter -i /tmp/xk-active-remove-status.json -e '@.state')" = not_requested ] || fail resume-status-not-consumed
else
  fail resume-status-unavailable
fi
[ ! -e /etc/xkeenwrt/lifecycle.json ] && [ ! -e /etc/xkeenwrt/.rescue-next ] || fail resume-upgrade-fence-present
assert_core_stopped_with_ui
assert_preserved_data
: > /tmp/xkeenwrt-request
http GET /api/control || fail resumed-status-transport
printf '%s\n' "$status" > /tmp/xk-active-remove-resume-status-code
cp /tmp/xkeenwrt-body /tmp/xk-active-remove-resume-status-body
http_expect_status 200 resumed-status
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.running')" = false ] || fail resume-started-core
jsonfilter -i /tmp/xkeenwrt-body -e '@' > /tmp/xk-active-remove-resume-status-root 2> /tmp/xk-active-remove-resume-status-json-error || fail resume-status-invalid-json
[ -s /tmp/xk-active-remove-resume-status-root ] || fail resume-status-empty-json
if jsonfilter -i /tmp/xkeenwrt-body -t '@.resumeRequestId' > /tmp/xk-active-remove-resume-request-type 2> /tmp/xk-active-remove-resume-type-error; then
  resume_request_type_status=0
else
  resume_request_type_status=$?
fi
[ "$resume_request_type_status" = 1 ] || fail resume-request-type-status
[ "$(cat /tmp/xk-active-remove-resume-request-type)" = null ] || fail resume-request-still-advertised
[ ! -s /tmp/xk-active-remove-resume-type-error ] || fail resume-request-type-error
printf 'ACTIVE_REMOVE_RESUME=exact-request-consumed,core-stopped,data-preserved\n'

stage=replay-resume-request
printf '{"action":"resume_after_reinstall","request_id":"%s"}' "$(cat /tmp/xk-active-remove-request-id)" > /tmp/xkeenwrt-request
http POST /api/control || fail replay-resume-transport
http_expect_status 409 replay-resume
http_expect_code CONFLICT replay-resume
assert_core_stopped_with_ui
assert_preserved_data
printf 'ACTIVE_REMOVE_REPLAY_REQUEST=conflict,core-stopped,data-preserved\n'

stage=ordinary-start-after-resume
printf '%s' '{"action":"start"}' > /tmp/xkeenwrt-request
http POST /api/control || fail post-resume-start-transport
http_expect_status 200 post-resume-start
pidof mihomo >/dev/null 2>&1 || fail post-resume-core-not-running
[ "$(core_populated)" = 1 ] || fail post-resume-core-cgroup-not-populated
assert_preserved_data
printf 'ACTIVE_REMOVE_START=explicit-after-resume,core-running,data-preserved\n'
printf 'ACTIVE_REMOVE_PASS=active-r3,remove,inert-reinstall,ordinary-start-refused,explicit-resume-stopped,start-running,data-preserved\n'
trap - EXIT
