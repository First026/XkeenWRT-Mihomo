# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM xkeen-openwrt-vm:25.12.6
RUN --mount=type=bind,source=packages,target=/tmp/packages,ro \
    --mount=type=bind,source=lifecycle-guest.sh,target=/tmp/lifecycle-guest.sh,ro \
    --mount=type=bind,source=manual-guest.sh,target=/tmp/manual-guest.sh,ro \
    --mount=type=bind,source=upgrade-guest.sh,target=/tmp/upgrade-guest.sh,ro \
    --mount=type=bind,source=active-remove-guest.sh,target=/tmp/active-remove-guest.sh,ro \
    --mount=type=bind,source=remove-payload-loss-guest.sh,target=/tmp/remove-payload-loss-guest.sh,ro \
    --mount=type=bind,source=remove-reboot-preinit.sh,target=/tmp/remove-reboot-preinit.sh,ro \
    --mount=type=bind,source=remove-reboot-snapshot.sh,target=/tmp/remove-reboot-snapshot.sh,ro \
    --mount=type=bind,source=remove-reboot-snapshot.init,target=/tmp/remove-reboot-snapshot.init,ro \
    --mount=type=bind,source=remove-reboot-after-guest.sh,target=/tmp/remove-reboot-after-guest.sh,ro \
    --mount=type=bind,source=runtime-package-smoke.sh,target=/tmp/runtime-package-smoke.sh,ro \
    --mount=type=bind,source=http-wire,target=/tmp/http-wire,ro \
    --mount=type=bind,source=ipc-probe,target=/tmp/ipc-probe,ro \
    --mount=type=bind,source=validator-probe,target=/tmp/validator-probe,ro \
    echo '8f70595f3a6eec3112e007450a1a600153904deffa52ab368712342583cb387c  /guest/bzImage' | sha256sum -c - && \
    mkdir /guestroot && cd /guestroot && gzip -dc /guest/rootfs.cpio.gz | cpio -id --quiet && \
    mkdir -p usr/share/xkeen-lab-packages && cp /tmp/packages/*.apk usr/share/xkeen-lab-packages/ && \
    cp /tmp/lifecycle-guest.sh usr/share/xkeen-lab-packages/lifecycle-guest.sh && chmod 755 usr/share/xkeen-lab-packages/lifecycle-guest.sh && \
    cp /tmp/manual-guest.sh usr/share/xkeen-lab-packages/manual-guest.sh && chmod 755 usr/share/xkeen-lab-packages/manual-guest.sh && \
    cp /tmp/upgrade-guest.sh usr/share/xkeen-lab-packages/upgrade-guest.sh && chmod 755 usr/share/xkeen-lab-packages/upgrade-guest.sh && \
    cp /tmp/active-remove-guest.sh usr/share/xkeen-lab-packages/active-remove-guest.sh && chmod 755 usr/share/xkeen-lab-packages/active-remove-guest.sh && \
    cp /tmp/remove-payload-loss-guest.sh usr/share/xkeen-lab-packages/remove-payload-loss-guest.sh && chmod 755 usr/share/xkeen-lab-packages/remove-payload-loss-guest.sh && \
    cp /tmp/remove-reboot-snapshot.sh usr/share/xkeen-lab-packages/remove-reboot-snapshot.sh && chmod 755 usr/share/xkeen-lab-packages/remove-reboot-snapshot.sh && \
    cp /tmp/remove-reboot-after-guest.sh usr/share/xkeen-lab-packages/remove-reboot-after-guest.sh && chmod 755 usr/share/xkeen-lab-packages/remove-reboot-after-guest.sh && \
    cp /tmp/runtime-package-smoke.sh usr/share/xkeen-lab-packages/runtime-package-smoke.sh && chmod 755 usr/share/xkeen-lab-packages/runtime-package-smoke.sh && \
    cp /tmp/remove-reboot-preinit.sh lib/preinit/85_xkeenwrt_remove_reboot_etc && chmod 644 lib/preinit/85_xkeenwrt_remove_reboot_etc && \
    cp /tmp/remove-reboot-snapshot.init etc/init.d/xkeenwrt-remove-reboot-snapshot && chmod 755 etc/init.d/xkeenwrt-remove-reboot-snapshot && \
    ln -sf ../init.d/xkeenwrt-remove-reboot-snapshot etc/rc.d/S08xkeenwrt-remove-reboot-snapshot && \
    printf 'xkeenwrt-remove-reboot-lab-v1\n' > etc/xkeenwrt-remove-reboot-lab-v1 && \
    mkdir -p usr/libexec/xkeenwrt-integration && cp /tmp/http-wire usr/libexec/xkeenwrt-integration/http-wire && cp /tmp/ipc-probe usr/libexec/xkeenwrt-integration/ipc-probe && cp /tmp/validator-probe usr/libexec/xkeenwrt-integration/validator-probe && \
    printf 'xkeenwrt-validator-lab-v1\n' > etc/xkeenwrt-isolation-lab && chmod 600 etc/xkeenwrt-isolation-lab && \
    find . -print0 | cpio --null -o -H newc | gzip -1 > /guest/rootfs.cpio.gz && rm -rf /guestroot
