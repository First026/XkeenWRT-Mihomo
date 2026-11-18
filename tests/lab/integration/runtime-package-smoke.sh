#!/bin/sh
# Выполняется только в маркированной одноразовой VM.
set -eu
second_apply=no
case "$#" in
  0) ;;
  1) [ "$1" = --second-apply ] || { echo 'usage: runtime-package-smoke.sh [--second-apply]' >&2; exit 2; }; second_apply=yes ;;
  *) echo 'usage: runtime-package-smoke.sh [--second-apply]' >&2; exit 2 ;;
esac
second_apply=no
case "$#" in
  0) ;;
  1) [ "$1" = --second-apply ] || { echo 'usage: runtime-package-smoke.sh [--second-apply]' >&2; exit 2; }; second_apply=yes ;;
  *) echo 'usage: runtime-package-smoke.sh [--second-apply]' >&2; exit 2 ;;
esac
grep -qw 'xkeenwrt.isolation_lab=1' /proc/cmdline
[ "$(cat /etc/xkeenwrt-isolation-lab)" = 'xkeenwrt-validator-lab-v1' ]
stage=package
/usr/bin/xkeenwrt-ui package-check
stage=loopback
trap 'printf "LAB_RUNTIME_FAIL=%s\n" "$stage"' EXIT
ip link set lo up
ip addr show lo | grep -q '127.0.0.1/8' || ip addr add 127.0.0.1/8 dev lo
ip -f inet6 addr show lo | grep -q '::1/128' || ip -f inet6 addr add ::1/128 dev lo
stage=setup
mkdir -p /etc/xkeenwrt
chmod 700 /etc/xkeenwrt
printf 'xkeenwrt-runtime-v1\n' > /etc/xkeenwrt/runtime-enabled
printf 'xkeenwrt-recovery-v1\n' > /etc/xkeenwrt/recovery-enabled
chmod 600 /etc/xkeenwrt/runtime-enabled /etc/xkeenwrt/recovery-enabled
printf 'xkeenwrt-validation-v1\n' > /etc/xkeenwrt-validator-enabled
chmod 600 /etc/xkeenwrt-validator-enabled
umask 077
[ ! -e /sys/fs/cgroup/xkeenwrt-validation ] && [ ! -e /sys/fs/cgroup/xkeenwrt ]
mkdir /sys/fs/cgroup/xkeenwrt-validation
mkdir -p /sys/fs/cgroup/xkeenwrt/core
[ -f /sys/fs/cgroup/xkeenwrt/core/cgroup.procs ] && [ -f /sys/fs/cgroup/xkeenwrt/core/cgroup.kill ]
printf '+memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
printf '+memory +pids' > /sys/fs/cgroup/xkeenwrt-validation/cgroup.subtree_control
printf 'runtime-sentinel-v1\n' > /tmp/xkeenwrt-runtime-sentinel
/etc/init.d/xkeenwrt-runtime start
/etc/init.d/xkeenwrt-ui start
stage=ready
ready=no
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if [ -s /etc/xkeenwrt/bootstrap-token ] && wget -q -O /dev/null --timeout=2 --no-proxy http://127.0.0.1:1000/api/auth/login; then ready=yes; break; fi
  sleep 1
done
[ "$ready" = yes ]
stage=runtime-ready
runtime_ready=no
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  running=$(ubus call service list '{"name":"xkeenwrt-runtime"}' | jsonfilter -e '@["xkeenwrt-runtime"].instances.*.running')
  if [ "$running" = true ] && [ -S /var/run/xkeenwrt/control.sock ]; then runtime_ready=yes; break; fi
  sleep 1
done
[ "$runtime_ready" = yes ]
echo LAB_RUNTIME_READY=procd-socket
cookie=
http() {
  method=$1
  url=$2
  length=$(wc -c < /tmp/xkeenwrt-request)
  {
    printf '%s %s HTTP/1.1\r\nHost: 127.0.0.1:1000\r\nOrigin: http://127.0.0.1:1000\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %s\r\n' "$method" "$url" "$length"
    [ -z "$cookie" ] || printf 'Cookie: %s\r\n' "$cookie"
    printf '\r\n'
    cat /tmp/xkeenwrt-request
  } > /tmp/xkeenwrt-http-wire
  rm -f /tmp/xkeenwrt-response /tmp/xkeenwrt-response-clean /tmp/xkeenwrt-body
  status=
  if ! /usr/libexec/xkeenwrt-integration/http-wire; then
    echo LAB_HTTP_TRANSPORT=failed
    http_transport_diagnostics TRANSPORT_FAIL
    return 1
  fi
  tr -d '\r' < /tmp/xkeenwrt-response > /tmp/xkeenwrt-response-clean
  sed '1,/^$/d' /tmp/xkeenwrt-response-clean > /tmp/xkeenwrt-body
  status=$(sed -n '1s/^HTTP\/[^ ]* \([0-9][0-9][0-9]\).*/\1/p' /tmp/xkeenwrt-response-clean)
}
http_transport_diagnostics() {
  label=$1
  link=$(ip -o link show dev lo 2>/dev/null) || link=unavailable
  printf 'LAB_HTTP_%s_LOOPBACK_LINK=%s\n' "$label" "$link"
  addresses=$(ip -o addr show dev lo 2>/dev/null | awk '{print $4}' | tr '\n' ',') || addresses=unavailable
  [ -n "$addresses" ] || addresses=none
  printf 'LAB_HTTP_%s_LOOPBACK_ADDR=%s\n' "$label" "$addresses"
  if ip route show table local 2>/dev/null | grep -Eq 'local 127\.0\.0\.0/8|local 127\.0\.0\.1'; then route=yes; else route=no; fi
  printf 'LAB_HTTP_%s_LOCAL_ROUTE=%s\n' "$label" "$route"
  if netstat -lnt 2>/dev/null | grep -Eq '(^|[[:space:]])(127\.0\.0\.1:1000|0\.0\.0\.0:1000|\*:1000|\[::\]:1000)([[:space:]]|$)'; then listener=yes; else listener=no; fi
  printf 'LAB_HTTP_%s_LISTENER_1000=%s\n' "$label" "$listener"
  if service_json=$(ubus call service list '{"name":"xkeenwrt-runtime"}' 2>/dev/null); then
    service_running=$(printf '%s' "$service_json" | jsonfilter -e '@["xkeenwrt-runtime"].instances.*.running' 2>/dev/null) || service_running=unknown
    case "$service_running" in true) service_value=running ;; false) service_value=stopped ;; *) service_value=unknown ;; esac
  else
    service_value=unavailable
  fi
  printf 'LAB_HTTP_%s_RUNTIME_SERVICE=%s\n' "$label" "$service_value"
}
if [ "$second_apply" = yes ]; then http_transport_diagnostics PREAUTH; fi
stage=auth
printf '{"token":"%s","password":"synthetic-password-123"}' "$(cat /etc/xkeenwrt/bootstrap-token)" > /tmp/xkeenwrt-request
http POST /api/auth/setup
[ "$status" = 200 ]
cookie=$(sed -n 's/^[Ss]et-[Cc]ookie: \(session_id=[^;]*\).*/\1/p' /tmp/xkeenwrt-response-clean)
[ -n "$cookie" ]
stage=save
printf '%s' '{"source":"mode: rule\n","expected_revision":null}' > /tmp/xkeenwrt-request
http PUT /api/profiles/home
[ "$status" = 200 ]
revision=$(jsonfilter -i /tmp/xkeenwrt-body -e '@.profile.revision')
[ -n "$revision" ]
umask 077
printf '%s\n' "$revision" > /tmp/xkeenwrt-synthetic-revision
stage=validate
printf '{"expected_revision":"%s"}' "$revision" > /tmp/xkeenwrt-request
http POST /api/profiles/home/validate
[ "$status" = 200 ]
candidate=$(jsonfilter -i /tmp/xkeenwrt-body -e '@.validation.candidate_id')
[ -n "$candidate" ]
stage=apply
printf '{"expected_revision":"%s","candidate_id":"%s","idempotency_key":"synthetic-smoke-1"}' "$revision" "$candidate" > /tmp/xkeenwrt-request
http POST /api/profiles/home/apply
[ "$status" = 200 ]
if [ "$second_apply" = yes ]; then
  stage=history-save
  printf '{"source":"mode: rule\\n# second synthetic revision\\n","expected_revision":"%s"}' "$revision" > /tmp/xkeenwrt-request
  http PUT /api/profiles/home
  [ "$status" = 200 ]
  revision=$(jsonfilter -i /tmp/xkeenwrt-body -e '@.profile.revision')
  [ -n "$revision" ]
  stage=history-validate
  printf '{"expected_revision":"%s"}' "$revision" > /tmp/xkeenwrt-request
  http POST /api/profiles/home/validate
  [ "$status" = 200 ]
  candidate=$(jsonfilter -i /tmp/xkeenwrt-body -e '@.validation.candidate_id')
  [ -n "$candidate" ]
  stage=history-apply
  printf '{"expected_revision":"%s","candidate_id":"%s","idempotency_key":"synthetic-smoke-history-2"}' "$revision" "$candidate" > /tmp/xkeenwrt-request
  http POST /api/profiles/home/apply
  [ "$status" = 200 ]
  echo LAB_HISTORY_SECOND_APPLY=PASS
fi
stage=rescue
[ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ]
[ -f /etc/xkeenwrt/rescue/identity ]
[ -L /etc/rc.d/S09xkeenwrt-rescue ] && [ -L /etc/rc.d/K91xkeenwrt-rescue ]
stage=control
: > /tmp/xkeenwrt-request
http GET /api/control
[ "$status" = 200 ]
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.currentCore')" = mihomo ]
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.running')" = true ]
classify_home() {
  label=$1
  for path in /tmp/xkeenwrt/runtime/active/* /tmp/xkeenwrt/runtime/active/.[!.]*; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    case "${path##*/}" in config.yaml) kind=config ;; cache.db) kind=cache ;; providers) kind=providers ;; *) kind=other ;; esac
    printf 'LAB_HOME_%s=%s\n' "$label" "$kind"
  done
}
classify_home running
stage=stop
printf '%s' '{"action":"stop"}' > /tmp/xkeenwrt-request
http POST /api/control
[ "$status" = 200 ]
classify_home stopped
stage=start
printf '%s' '{"action":"start"}' > /tmp/xkeenwrt-request
http POST /api/control
[ "$status" = 200 ]
stage=final
[ "$(cat /proc/1/comm)" = procd ]
ubus call system board >/dev/null
[ "$(for i in /sys/class/net/*; do printf '%s' "${i##*/}"; done)" = lo ]
[ "$(cat /tmp/xkeenwrt-runtime-sentinel)" = runtime-sentinel-v1 ]
printf 'LAB_RUNTIME_PASS=auth,save,validate,apply,control,stop,start\n'
trap - EXIT
