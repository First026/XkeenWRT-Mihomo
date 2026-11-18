# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Derived from the cached armsr/armv8 25.12.6 VM; no lab-hooks are added to product APKs.
FROM xkeen-openwrt-vm-arm64:25.12.6
COPY input /input
RUN set -eu; \
    mkdir /guestroot; cd /guestroot; \
    cpio -id --quiet < /guest/rootfs.cpio; \
    mkdir -p /guestroot/usr/share/xkeenwrt-r6/apks /guestroot/usr/share/xkeenwrt-r6/repositories/base \
      /guestroot/usr/share/xkeenwrt-r6/repositories/core /guestroot/usr/share/xkeenwrt-r6/repositories/kmods; \
    cp /input/xkeenwrt-core.apk /guestroot/usr/share/xkeenwrt-r6/apks/core.apk; \
    cp /input/xkeenwrt-ui.apk /guestroot/usr/share/xkeenwrt-r6/apks/ui.apk; \
    cp /input/arm64/*.apk /guestroot/usr/share/xkeenwrt-r6/repositories/base/; \
    cp /input/arm64/*.apk /guestroot/usr/share/xkeenwrt-r6/repositories/core/; \
    cp /input/arm64/*.apk /guestroot/usr/share/xkeenwrt-r6/repositories/kmods/; \
    cp /input/arm64-base.adb /guestroot/usr/share/xkeenwrt-r6/repositories/base/packages.adb; \
    cp /input/arm64-core.adb /guestroot/usr/share/xkeenwrt-r6/repositories/core/packages.adb; \
    cp /input/arm64-kmods.adb /guestroot/usr/share/xkeenwrt-r6/repositories/kmods/packages.adb; \
    rm -f /guestroot/init; cp /input/native-init /guestroot/init; chmod 755 /guestroot/init; \
    mkdir -p /guestroot/usr/libexec/xkeenwrt-r6-native; \
    cp /input/native-guest.sh /guestroot/usr/libexec/xkeenwrt-r6-native/guest.sh; chmod 755 /guestroot/usr/libexec/xkeenwrt-r6-native/guest.sh; \
    cp /input/n02.sh /guestroot/usr/libexec/xkeenwrt-r6-native/n02.sh; chmod 755 /guestroot/usr/libexec/xkeenwrt-r6-native/n02.sh; \
    cp /input/http-wire /guestroot/usr/libexec/xkeenwrt-r6-native/http-wire; chmod 755 /guestroot/usr/libexec/xkeenwrt-r6-native/http-wire; \
    printf 'r6-native-v1\n' > /guestroot/etc/xkeenwrt-r6-native-lab; chmod 644 /guestroot/etc/xkeenwrt-r6-native-lab; \
    rm /guest/rootfs.cpio; \
    find . -print0 | cpio --null -o -H newc > /guest/rootfs.cpio; \
    rm -rf /guestroot /input
