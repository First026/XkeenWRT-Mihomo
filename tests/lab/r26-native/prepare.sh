#!/bin/sh
# Host side of the disposable r26 acceptance lab (OpenWrt 25.12.6 armsr/armv8,
# QEMU TCG). Needs Docker, qemu-system-aarch64, cpio, python3 and network
# access to ghcr.io and downloads.openwrt.org. Never targets a router.
# Usage: prepare.sh R26_APK_DIR   (the exact r26 pair to accept; an
#        xkeenwrt-install-r26.run in the same directory is included for C4)
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
L=${XK_LAB:-/tmp/xk-lab}
r26=$(CDPATH= cd -- "$1" && pwd)
SDK=ghcr.io/openwrt/sdk@sha256:de8a21b5ac9b434abc62dda8d3957d890f18cbd955c6c32eb91c93184fe51e9a
ROOTFS=ghcr.io/openwrt/rootfs@sha256:22f13387da208c0fb4150c41f3ec12e34cc5994a0717a49e50aa9f9ae6cb5e7b
IB=ghcr.io/openwrt/imagebuilder@sha256:08660d295cc84143c096d6a5eab257433168ee0766f26736910a909c37e4db13
B=https://downloads.openwrt.org/releases/25.12.6
KMODS=$B/targets/armsr/armv8/kmods/6.12.112-1-67e205f26d0458c4d12f1fd315216398
rm -rf "$L"; mkdir -p "$L/guest" "$L/guestroot"
cd "$L"
docker pull -q "$ROOTFS" >/dev/null; docker pull -q "$IB" >/dev/null; docker pull -q "$SDK" >/dev/null
cid=$(docker create "$ROOTFS" /bin/true); docker export "$cid" | tar -x -C guestroot; docker rm "$cid" >/dev/null
cid=$(docker create "$IB" /bin/true)
docker cp "$cid:/builder/build_dir/target-aarch64_generic_musl/linux-armsr_armv8/vmlinux" guest/Image; docker rm "$cid" >/dev/null
echo "2b9ce48df5536e993ee691339057828488e4a31be9c2bb5d3f6120f1135fcbb0  guest/Image" | sha256sum -c -
grep -qx "DISTRIB_RELEASE='25.12.6'" guestroot/etc/openwrt_release
# Signed official indexes; the guest verifies them and every package on install.
G=guestroot/usr/share/xk-lab
mkdir -p "$G/repo/core" "$G/repo/base" "$G/repo/kmods" "$G/repo/packages" "$G/apks/r25" "$G/apks/r26"
curl -fsS -o "$G/repo/core/packages.adb" "$B/targets/armsr/armv8/packages/packages.adb"
curl -fsS -o "$G/repo/base/packages.adb" "$B/packages/aarch64_generic/base/packages.adb"
curl -fsS -o "$G/repo/kmods/packages.adb" "$KMODS/packages.adb"
curl -fsS -o "$G/repo/packages/packages.adb" "$B/packages/aarch64_generic/packages/packages.adb"
# Dependency closure resolved on 17.11.2026 against the rootfs's installed set.
for p in ip-full-6.18.0-r2 libbpf1-1.6.2-r1 libelf1-0.192-r1; do curl -fsS -o "$G/repo/base/$p.apk" "$B/packages/aarch64_generic/base/$p.apk"; done
for p in kmod-nft-tproxy-6.12.112-r1 kmod-nf-tproxy-6.12.112-r1 kmod-nft-socket-6.12.112-r1 kmod-nf-socket-6.12.112-r1 \
  kmod-nf-conntrack-netlink-6.12.112-r1 kmod-veth-6.12.112-r1; do curl -fsS -o "$G/repo/kmods/$p.apk" "$KMODS/$p.apk"; done
for p in curl-8.23.0-r1 libcurl4-8.23.0-r1 libnghttp2-14-1.70.0-r1; do curl -fsS -o "$G/repo/packages/$p.apk" "$B/packages/aarch64_generic/packages/$p.apk"; done
for p in core ui; do
  curl -fsSL -o "$G/apks/r25/xkeenwrt-$p-0.1-r25.apk" "https://github.com/First026/XkeenWRT-Mihomo/releases/download/v0.1-r25/xkeenwrt-$p-0.1-r25.apk"
  cp "$r26/xkeenwrt-$p-0.1-r26.apk" "$G/apks/r26/"
done
printf '%s  %s\n' dc731d047fba66d11d526f96c9c2e6c992b551e2afea33a39567f3ade12bc8e5 "$G/apks/r25/xkeenwrt-core-0.1-r25.apk" \
  01473d98ab45b09de5f2b8a5c22d0495afa255552716ffc8af7761575193b121 "$G/apks/r25/xkeenwrt-ui-0.1-r25.apk" | sha256sum -c -
curl -fsSL https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-arm64-v1.19.34.gz | gzip -dc > "$G/mihomo"
echo "022da41e03ce70641a2f50c485b4f69ade8f1c7aeeece2cf1ec45c614a029441  $G/mihomo" | sha256sum -c -
chmod 755 "$G/mihomo"
cp "$here"/lib.sh "$here"/setup.sh "$here"/install.sh "$here"/c1.sh "$here"/c2.sh "$here"/c3.sh "$here"/c4.sh "$G/"
[ ! -f "$r26/xkeenwrt-install-r26.run" ] || cp "$r26/xkeenwrt-install-r26.run" "$G/"
rm -f guestroot/init; cp "$here/init" guestroot/init; chmod 755 guestroot/init
printf 'xk-lab-r26-v1\n' > guestroot/etc/xk-lab
(cd guestroot && find . -print0 | cpio --null -o -H newc --quiet > "$L/guest/rootfs.cpio")
truncate -s 512M "$L/persist.img"
sha256sum "$G"/apks/*/*.apk
echo "prepared $L; boot with: XK_LAB=$L $here/boot.sh"
