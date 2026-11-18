#!/bin/sh
# Host side of the disposable 0.1.26.4 acceptance lab: the r26 stand
# (OpenWrt 25.12.6 armsr/armv8, QEMU TCG) plus a Tailscale-like management
# path and a lab "internet" with a proxied and a direct site.
# Needs Docker, qemu-system-aarch64, cpio, openssl and network access to
# ghcr.io and downloads.openwrt.org. Never targets a router.
# Usage: prepare.sh R263_DIR R264_DIR MIHOMO_GZ R2641_DIR
#   R263_DIR  - xkeenwrt-{core,ui}-0.1.26.3-r0.apk from release v0.1.26.3
#   R264_DIR  - apks/xkeenwrt-{core,ui}-0.1.26.4-r0.apk and xkeenwrt-install-r26.4.run
#   MIHOMO_GZ - mihomo-linux-arm64-v1.19.34.gz (checked by SHA-256 below)
#   R2641_DIR - apks/xkeenwrt-{core,ui}-0.1.26.4.1-r0.apk: a lab-only build of the
#               same tree with version 0.1.26.4.1, the target of the C9 update
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base=$here/../r26-native
L=${XK_LAB:-/var/tmp/xk-lab-r261}
r263=$(CDPATH= cd -- "$1" && pwd)
r264=$(CDPATH= cd -- "$2" && pwd)
mihomo_gz=$3
r2641=$(CDPATH= cd -- "$4" && pwd)
ROOTFS=ghcr.io/openwrt/rootfs@sha256:22f13387da208c0fb4150c41f3ec12e34cc5994a0717a49e50aa9f9ae6cb5e7b
IB=ghcr.io/openwrt/imagebuilder@sha256:08660d295cc84143c096d6a5eab257433168ee0766f26736910a909c37e4db13
B=https://downloads.openwrt.org/releases/25.12.6
KMODS=$B/targets/armsr/armv8/kmods/6.12.112-1-67e205f26d0458c4d12f1fd315216398
rm -rf "$L"; mkdir -p "$L/guest" "$L/guestroot" "$L/tls"
cd "$L"
docker pull -q "$ROOTFS" >/dev/null; docker pull -q "$IB" >/dev/null
cid=$(docker create "$ROOTFS" /bin/true); docker export "$cid" | tar -x -p -C guestroot; docker rm "$cid" >/dev/null
cid=$(docker create "$IB" /bin/true)
docker cp "$cid:/builder/build_dir/target-aarch64_generic_musl/linux-armsr_armv8/vmlinux" guest/Image; docker rm "$cid" >/dev/null
echo "2b9ce48df5536e993ee691339057828488e4a31be9c2bb5d3f6120f1135fcbb0  guest/Image" | sha256sum -c -
grep -qx "DISTRIB_RELEASE='25.12.6'" guestroot/etc/openwrt_release
G=guestroot/usr/share/xk-lab
mkdir -p "$G/repo/core" "$G/repo/base" "$G/repo/kmods" "$G/repo/packages" "$G/apks/r26.3" "$G/apks/r26.4" "$G/tls"
curl -fsS -o "$G/repo/core/packages.adb" "$B/targets/armsr/armv8/packages/packages.adb"
curl -fsS -o "$G/repo/base/packages.adb" "$B/packages/aarch64_generic/base/packages.adb"
curl -fsS -o "$G/repo/kmods/packages.adb" "$KMODS/packages.adb"
curl -fsS -o "$G/repo/packages/packages.adb" "$B/packages/aarch64_generic/packages/packages.adb"
for p in ip-full-6.18.0-r2 libbpf1-1.6.2-r1 libelf1-0.192-r1; do curl -fsS -o "$G/repo/base/$p.apk" "$B/packages/aarch64_generic/base/$p.apk"; done
for p in kmod-nft-tproxy-6.12.112-r1 kmod-nf-tproxy-6.12.112-r1 kmod-nft-socket-6.12.112-r1 kmod-nf-socket-6.12.112-r1 \
  kmod-nf-conntrack-netlink-6.12.112-r1 kmod-veth-6.12.112-r1; do curl -fsS -o "$G/repo/kmods/$p.apk" "$KMODS/$p.apk"; done
for p in curl-8.23.0-r1 libcurl4-8.23.0-r1 libnghttp2-14-1.70.0-r1; do curl -fsS -o "$G/repo/packages/$p.apk" "$B/packages/aarch64_generic/packages/$p.apk"; done
# The 0.1.26.3 pair C1 upgrades in place, checked against its published hashes.
for p in core ui; do
  cp "$r263/xkeenwrt-$p-0.1.26.3-r0.apk" "$G/apks/r26.3/"
  cp "$r264/apks/xkeenwrt-$p-0.1.26.4-r0.apk" "$G/apks/r26.4/"
done
printf '%s  %s\n' 45f7f5f17b0f5acd811bf53ea1f371581b18de3b247d9e7d9cadc5a292e20e6d "$G/apks/r26.3/xkeenwrt-core-0.1.26.3-r0.apk" \
  64faf1b3db1d5adf525aaa32ed7bac8f15f6f9bd77d57a4ec2a202b6fe71c5f2 "$G/apks/r26.3/xkeenwrt-ui-0.1.26.3-r0.apk" | sha256sum -c -
cp "$r264/xkeenwrt-install-r26.4.run" "$G/"
gzip -dc "$mihomo_gz" > "$G/mihomo"
echo "022da41e03ce70641a2f50c485b4f69ade8f1c7aeeece2cf1ec45c614a029441  $G/mihomo" | sha256sum -c -
chmod 755 "$G/mihomo"
# Lab-only TLS: a CA trusted inside the guest and www.gstatic.com served by the
# WAN peer, so Mihomo's own probe and a LAN client can complete real HTTPS.
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=XkeenWRT lab CA' \
  -keyout tls/ca.key -out tls/ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj '/CN=www.gstatic.com' -keyout tls/server.key -out tls/server.csr 2>/dev/null
printf 'subjectAltName=DNS:www.gstatic.com\nextendedKeyUsage=serverAuth\n' > tls/ext.cnf
openssl x509 -req -in tls/server.csr -CA tls/ca.crt -CAkey tls/ca.key -CAcreateserial -days 30 \
  -extfile tls/ext.cnf -out tls/server.crt 2>/dev/null
cp tls/ca.crt tls/server.crt tls/server.key "$G/tls/"
cp "$here"/lib.sh "$here"/setup.sh "$here"/install.sh "$here"/c[1-9].sh "$G/"
sh "$here/github.sh" "$r2641/apks" "$G" tls
rm -f guestroot/init; cp "$base/init" guestroot/init; chmod 755 guestroot/init
printf 'xk-lab-r264-v1\n' > guestroot/etc/xk-lab
# The product verifies root ownership of /usr, /usr/libexec and its files: the
# archive must be root-owned like a real image even when prepared without root.
(cd guestroot && find . -print0 | cpio --null -o -H newc --quiet -R 0:0 > "$L/guest/rootfs.cpio")
truncate -s 768M "$L/persist.img"
sha256sum "$G"/apks/*/*.apk "$G/xkeenwrt-install-r26.4.run"
echo "prepared $L; boot with: XK_LAB=$L $base/boot.sh"
