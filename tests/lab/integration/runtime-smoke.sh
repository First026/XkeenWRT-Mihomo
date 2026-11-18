#!/bin/sh
# Выполняется только в маркированной одноразовой VM.
set -eu
grep -qw 'xkeenwrt.isolation_lab=1' /proc/cmdline
[ "$(cat /etc/xkeenwrt-isolation-lab)" = 'xkeenwrt-validator-lab-v1' ]
stage=loopback
trap 'printf "LAB_RUNTIME_FAIL=%s\n" "$stage"' EXIT
ip link set lo up
ip addr show lo | grep -q '127.0.0.1/8' || ip addr add 127.0.0.1/8 dev lo
ip -f inet6 addr show lo | grep -q '::1/128' || ip -f inet6 addr add ::1/128 dev lo
stage=setup
mkdir -p /etc/xkeenwrt
chmod 700 /etc/xkeenwrt
printf 'xkeenwrt-validation-v1\n' > /etc/xkeenwrt-validator-enabled
chmod 600 /etc/xkeenwrt-validator-enabled
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
  /usr/libexec/xkeenwrt-integration/http-wire
  tr -d '\r' < /tmp/xkeenwrt-response > /tmp/xkeenwrt-response-clean
  sed '1,/^$/d' /tmp/xkeenwrt-response-clean > /tmp/xkeenwrt-body
  status=$(sed -n '1s/^HTTP\/[^ ]* \([0-9][0-9][0-9]\).*/\1/p' /tmp/xkeenwrt-response-clean)
}
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
stage=control
: > /tmp/xkeenwrt-request
http GET /api/control
[ "$status" = 200 ]
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.currentCore')" = mihomo ]
[ "$(jsonfilter -i /tmp/xkeenwrt-body -e '@.running')" = true ]
stage=stop
printf '%s' '{"action":"stop"}' > /tmp/xkeenwrt-request
http POST /api/control
[ "$status" = 200 ]
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
