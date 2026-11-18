#!/bin/sh
set -eu

XK_REMOVE_PENDING_LIBRARY=yes
. /usr/share/xkeen-lab-packages/remove-payload-loss-guest.sh
unset XK_REMOVE_PENDING_LIBRARY

stage=reboot-after-guard
failure=
fail() {
  failure="$stage:$1"
  printf 'REMOVE_REBOOT_AFTER_FAIL=%s\n' "$failure"
  exit 1
}

grep -qw xkeenwrt.remove_reboot_lab=1 /proc/cmdline || fail cmdline
[ "$(cat /etc/xkeenwrt-remove-reboot-lab-v1)" = xkeenwrt-remove-reboot-lab-v1 ] || fail marker-content
state_dir=/etc/xkeenwrt-lab-reboot
expected_file=$state_dir/expected
[ -f "$expected_file" ] || fail reboot-state-missing
state_value() { sed -n "s/^$1=//p" "$expected_file" | head -n 1; }

preboot_id=$(state_value boot_id)
expected_owner=$(state_value owner_id)
expected_request=$(state_value request_id)
expected_receipt_sha=$(state_value receipt_sha256)
expected_helper_pid=$(state_value helper_pid)
expected_helper_start=$(state_value helper_starttime)
expected_helper_nonce=$(state_value helper_nonce)
expected_helper_sha=$(state_value helper_sha256)
case "$preboot_id:$expected_owner:$expected_request:$expected_receipt_sha:$expected_helper_pid:$expected_helper_start:$expected_helper_nonce:$expected_helper_sha" in
  *[!0-9a-fA-F:-]*) fail reboot-state-invalid ;;
esac
[ "${#preboot_id}" -eq 36 ] && [ "${#expected_owner}" -eq 36 ] && [ "${#expected_request}" -eq 36 ] || fail reboot-state-uuid
[ "${#expected_receipt_sha}" -eq 64 ] && [ "${#expected_helper_sha}" -eq 64 ] || fail reboot-state-sha

stage=verify-new-boot
current_boot_id=$(cat /proc/sys/kernel/random/boot_id) || fail boot-id-unavailable
[ "$current_boot_id" != "$preboot_id" ] || fail boot-id-not-changed
printf 'REMOVE_REBOOT_AFTER_BOOT_ID=%s\n' "$current_boot_id"

stage=observe-auto-rescue
rescue_ready=no
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if capture_rescue_identity && rescue_identity_matches running && rescue_lock_held; then
    rescue_ready=yes
    break
  fi
  sleep 1
done
[ "$rescue_ready" = yes ] || fail s09-supervisor-not-running
current_identity_boot=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.boot_id') || fail supervisor-boot-id
current_identity_nonce=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.nonce') || fail supervisor-nonce
current_identity_owner=$(jsonfilter -i /var/run/xkeenwrt/supervisor.json -e '@.owner_id') || fail supervisor-owner
[ "$current_identity_boot" = "$current_boot_id" ] || fail supervisor-stale-boot-id
[ "$current_identity_nonce" != "$expected_helper_nonce" ] || fail supervisor-identity-not-fresh
[ "$current_identity_owner" = "$expected_owner" ] || fail supervisor-owner-changed
[ "$rescue_sha256" = "$expected_helper_sha" ] || fail persistent-helper-hash-changed
printf 'REMOVE_REBOOT_AFTER_SUPERVISOR=PASS\n'
printf 'REMOVE_REBOOT_AFTER_SUPERVISOR_PID=%s\n' "$rescue_pid"
printf 'REMOVE_REBOOT_AFTER_SUPERVISOR_STARTTIME=%s\n' "$rescue_starttime"
printf 'REMOVE_REBOOT_AFTER_SUPERVISOR_EXE_SHA256=%s\n' "$rescue_sha256"

stage=wait-remove-cleanup
cleanup_ready=no
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if remove_status && [ "$request_kind" = remove ] && [ "$request_state" = cleanup_complete ] \
    && [ "$request_owner_id" = "$expected_owner" ] && [ "$request_request_id" = "$expected_request" ]; then
    cleanup_ready=yes
    break
  fi
  sleep 1
done
[ "$cleanup_ready" = yes ] || fail remove-cleanup-not-complete
final_receipt_sha=$(hash_of /etc/xkeenwrt/removal.json)
[ "$final_receipt_sha" != "$expected_receipt_sha" ] || fail receipt-hash-did-not-change
printf 'REMOVE_REBOOT_AFTER_RECEIPT=remove/cleanup_complete\n'
printf 'REMOVE_REBOOT_AFTER_REQUEST_ID=%s\n' "$request_request_id"

stage=verify-payload-and-processes
for path in /usr/bin/xkeenwrt-ui /usr/libexec/xkeenwrt/mihomo \
  /usr/libexec/xkeenwrt/xkeenwrt-validate /usr/libexec/xkeenwrt/xkeenwrt-recovery \
  /usr/libexec/xkeenwrt/init/xkeenwrt-runtime /usr/libexec/xkeenwrt/init/xkeenwrt-ui \
  /usr/libexec/xkeenwrt/init/xkeenwrt-core /usr/libexec/xkeenwrt/init/xkeenwrt-recovery; do
  [ ! -e "$path" ] || fail "package-payload-present-${path##*/}"
done
! pidof mihomo >/dev/null 2>&1 || fail mihomo-running-after-boot
! pidof xkeenwrt-ui >/dev/null 2>&1 || fail ui-running-after-boot
service_is_stopped xkeenwrt-runtime
service_is_stopped xkeenwrt-ui
service_is_stopped xkeenwrt-core
if [ -r /sys/fs/cgroup/xkeenwrt/core/cgroup.events ]; then
  core_populated=$(sed -n 's/^populated //p' /sys/fs/cgroup/xkeenwrt/core/cgroup.events)
  [ "$core_populated" = 0 ] || fail core-cgroup-populated
elif [ -d /sys/fs/cgroup/xkeenwrt/core ]; then
  fail core-cgroup-events-missing
fi
printf 'REMOVE_REBOOT_AFTER_CORE_CGROUP=empty-or-absent\n'

stage=verify-preserved-data
cp "$state_dir/profile.sha256" /tmp/xk-remove-pending-profile.sha256 || fail baseline-profile-read
cp "$state_dir/history-path" /tmp/xk-remove-pending-history-path || fail baseline-history-path-read
cp "$state_dir/history.sha256" /tmp/xk-remove-pending-history.sha256 || fail baseline-history-read
cp "$state_dir/asset.sha256" /tmp/xk-remove-pending-asset.sha256 || fail baseline-asset-read
cp "$state_dir/internal-sentinel.sha256" /tmp/xk-remove-pending-sentinel.sha256 || fail baseline-internal-sentinel-read
assert_preserved_data
expected_foreign_sha=$(cat "$state_dir/foreign-sentinel.sha256") || fail baseline-sentinel-read
[ "$(hash_of /etc/xkeenwrt-remove-reboot-foreign-sentinel)" = "$expected_foreign_sha" ] || fail foreign-sentinel-changed
[ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail persistent-helper-missing
[ "$(hash_of /etc/xkeenwrt/rescue/xkeenwrt-recovery)" = "$expected_helper_sha" ] || fail persistent-helper-changed
printf 'REMOVE_REBOOT_AFTER_DATA=profile,history,asset,foreign-sentinel-PASS\n'
printf 'REMOVE_REBOOT_AFTER_PASS=boot-id-changed,auto-S09,remove-cleanup-complete,core-stopped,data-preserved\n'
