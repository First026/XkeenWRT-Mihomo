# 003. Isolated Mihomo parser evidence

Date: 2026-11-12. This evidence does not authorize changes to any router; decision 002 remains in force.

## Artifact and provenance

The official [MetaCubeX v1.19.34 release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.34) provides [mihomo-linux-amd64-v1.19.34.gz](https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-linux-amd64-v1.19.34.gz). The release's [expanded asset listing](https://github.com/MetaCubeX/mihomo/releases/expanded_assets/v1.19.34) states SHA-256 `223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc`. The downloaded gzip matched; its decompressed executable SHA-256 is `0a68807c7c93963bb66d07717fe0f3ac3945b422b525f8a1e19438d278d7ae11`. The archive is stored outside Git at `/workspace/.cache/xkeenwrt/mihomo-linux-amd64-v1.19.34.gz`. The core reported `Mihomo Meta v1.19.34 linux amd64 with go1.26.11 Wed Nov 11 06:48:49 UTC 2026`, tag `with_gvisor`.

## Reproduction and observations

`tests/lab/validate-mihomo.sh ARCHIVE CONFIG` checks the archive against that digest, then runs only `-v` and `-t` in a disposable container with `--network=none`, read-only root, tmpfs inputs and home, no host mounts, no capabilities, and no published ports. The core validation has a 15-second timeout. It uses the local Docker socket explicitly and the pinned official Alpine image digest `sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab`; if absent, pull it by exact digest with `docker pull alpine@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab` using the managed local socket. Inputs are copied into a private host directory and streamed as fixed tar entries to the container; the staging directory is removed on exit. The committed fixtures are synthetic and non-secret. The core is never executed on the host.

On the local managed Docker daemon, using this archive:

- `tests/lab/minimal.yaml`: `-t` exited 0.
- `tests/lab/amnezia-v3.yaml`: `-t` exited 0. The generated configuration contains version 3 AWG options, a peer with IPv4 and IPv6 allowed addresses, and IPv4/IPv6 interface addresses.
- `tests/lab/amnezia-legacy.yaml`: `-t` exited 0. It contains version 2 options from an AWG 1.5 input, peer PSK, IPv4/IPv6 allowed addresses and interface addresses.
- Malformed YAML (`proxies: [`): `-t` exited 1. Supplying a non-matching core archive was rejected by the wrapper with exit 2 before Docker execution.

These two synthetic YAML files were generated from the importer's v3 and legacy `.conf` fixtures. Parser acceptance does not prove that unknown fields are interpreted, that IPC applies the parameters, or that an AWG handshake or TCP/UDP traffic works. It is not proof of complete version support or router compatibility.

## Outstanding lab gates

An attempt to access `https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/` returned HTTP 403 from the environment's network policy. Subsequently, the exact mediatek/filogic SDK was obtained from OpenWrt's official GHCR publication and used for the [ARM64 build](../arm64-build.md); that resolves the SDK acquisition gate, not the kernel/VM lab gate. No host firewall substitute was used. A true OpenWrt test still needs an authorized official target image, a VM-capable isolated runner with snapshots, appropriate virtual network topology and a compatible AWG peer. It must exercise procd lifecycle/recovery, fw4/nft and routing, selected versus unselected client traffic, DNS and IPv6 scope, restart/failure rollback and real AWG handshakes and TCP/UDP traffic, as specified in decision 002 and the implementation plan. Neither this parser test nor ARM64 userspace emulation establishes those results.
