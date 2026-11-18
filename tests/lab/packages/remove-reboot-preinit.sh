#!/bin/sh

# Test-only persistence for the fixed, disposable virtio vda used by
# tests/lab/packages/run.sh --remove-reboot. This runs before rcS enumerates
# /etc/rc.d, after the mount_root preinit hook and before run_init.
xkeenwrt_remove_reboot_mount_etc() {
	grep -qw 'xkeenwrt.remove_reboot_lab=1' /proc/cmdline || return 0
	[ "$(cat /etc/xkeenwrt-remove-reboot-lab-v1 2>/dev/null)" = xkeenwrt-remove-reboot-lab-v1 ] || {
		printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-marker\n' > /dev/console
		return 1
	}
	device_ready=no
	for n in 1 2 3; do
		if [ -b /dev/vda ] && [ -r /sys/block/vda/size ]; then device_ready=yes; break; fi
		sleep 1
	done
	[ "$device_ready" = yes ] || {
		printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-vda\n' > /dev/console
		return 1
	}
	[ "$(cat /sys/block/vda/size)" = 196608 ] || {
		printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-vda-size\n' > /dev/console
		return 1
	}

	mountpoint=/tmp/xkeenwrt-remove-reboot-etc
	mkdir -p "$mountpoint" || return 1
	if mount -t ext4 -o noatime /dev/vda "$mountpoint" 2>/dev/null; then
		mode=existing
		[ -f "$mountpoint/.xkeenwrt-remove-reboot-etc-v1" ] || {
			printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-volume-marker\n' > /dev/console
			return 1
		}
	else
		magic=$(hexdump -v -s 1080 -n 2 -e '2/1 "%02x"' /dev/vda 2>/dev/null) || magic=invalid
		[ "$magic" = 0000 ] || {
			printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-not-fresh\n' > /dev/console
			return 1
		}
		mkfs.ext4 -F -L XKWRTLAB /dev/vda >/dev/null 2>&1 || {
			printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-format\n' > /dev/console
			return 1
		}
		mount -t ext4 -o noatime /dev/vda "$mountpoint" 2>/dev/null || {
			printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-mount-fresh\n' > /dev/console
			return 1
		}
		cp -a /etc/. "$mountpoint"/ || {
			printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-seed\n' > /dev/console
			return 1
		}
		printf 'xkeenwrt-remove-reboot-etc-v1\n' > "$mountpoint/.xkeenwrt-remove-reboot-etc-v1" || return 1
		sync
		mode=seeded
	fi
	mount -o bind "$mountpoint" /etc || {
		printf 'REMOVE_REBOOT_ETC_MOUNT=FAIL-bind\n' > /dev/console
		return 1
	}
	printf 'REMOVE_REBOOT_ETC_MOUNT=%s\n' "$mode" > /dev/console
}

boot_hook_add preinit_main xkeenwrt_remove_reboot_mount_etc
