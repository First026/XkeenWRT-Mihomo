#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
expected_bun=$(cat "$root_dir/.bun-version")
if [[ $(bun --version) != "$expected_bun" ]]; then
  printf 'Expected Bun %s; found %s\n' "$expected_bun" "$(bun --version)" >&2
  exit 1
fi
cd "$root_dir/frontend"
bun install --frozen-lockfile
bun run build
cd "$root_dir/backend"
cargo build --locked --release --features lab-hooks --bin xkeenwrt-ui --target x86_64-unknown-linux-gnu
printf 'Lab binary: %s\n' "${CARGO_TARGET_DIR:-$root_dir/backend/target}/x86_64-unknown-linux-gnu/release/xkeenwrt-ui"
