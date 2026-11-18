#!/bin/sh
set -u

grep -qw 'xkeenwrt.remove_reboot_lab=1' /proc/cmdline || exit 0

boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unavailable)
if [ -f /etc/xkeenwrt/removal.json ]; then
	receipt=/etc/xkeenwrt/removal.json
	receipt_sha=$(sha256sum "$receipt" | awk '{print $1}')
	kind=$(jsonfilter -i "$receipt" -e '@.kind' 2>/dev/null || echo invalid)
	state=$(jsonfilter -i "$receipt" -e '@.state' 2>/dev/null || echo invalid)
	owner=$(jsonfilter -i "$receipt" -e '@.owner_id' 2>/dev/null || echo invalid)
	request_id=$(jsonfilter -i "$receipt" -e '@.request_id' 2>/dev/null || echo invalid)
else
	receipt_sha=absent
	kind=absent
	state=absent
	owner=absent
	request_id=absent
fi
if [ -f /var/run/xkeenwrt/supervisor.json ]; then supervisor=present; else supervisor=absent; fi

{
	printf 'REMOVE_REBOOT_S08_BOOT_ID=%s\n' "$boot_id"
	printf 'REMOVE_REBOOT_S08_RECEIPT_SHA256=%s\n' "$receipt_sha"
	printf 'REMOVE_REBOOT_S08_KIND=%s\n' "$kind"
	printf 'REMOVE_REBOOT_S08_STATE=%s\n' "$state"
	printf 'REMOVE_REBOOT_S08_OWNER=%s\n' "$owner"
	printf 'REMOVE_REBOOT_S08_REQUEST_ID=%s\n' "$request_id"
	printf 'REMOVE_REBOOT_S08_SUPERVISOR=%s\n' "$supervisor"
} > /dev/console
