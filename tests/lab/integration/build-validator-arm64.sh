#!/bin/sh
set -eu
[ "$#" -eq 0 ] || exit 2
[ "$(id -u)" -ne 0 ] || exit 1
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
: "${XKEEN_LAB_VALIDATOR_SNAPSHOT:?Set frozen snapshot directory}"
source_dir=$XKEEN_LAB_VALIDATOR_SNAPSHOT
production="$repo/validator/target/aarch64-unknown-linux-musl/release/xkeenwrt-validate.guard-production"
lab="$repo/validator/target/aarch64-unknown-linux-musl/release/xkeenwrt-validate.guard-lab"
printf '%s  %s\n' 690a90d268560d879bc922aaaf5281e5d2039aa69964aab1c74cd93e1c13b33e "$production" | sha256sum -c -
printf '%s  %s\n' fb65231abf6da94f21b7f53ef3a2530488adb305ae9b5b7befb3a42c6af2a43c "$lab" | sha256sum -c -
for elf in "$production" "$lab"; do
  readelf -h "$elf" | grep -q 'AArch64'
  if readelf -l "$elf" | grep -q INTERP || readelf -d "$elf" 2>/dev/null | grep -q NEEDED; then exit 1; fi
  sha256sum "$elf"
done
id=$(docker --host=unix:///var/run/docker.sock image inspect xkeen-openwrt-vm-arm64-isolation:25.12.6 --format '{{.Id}}')
[ "$id" = sha256:6edcb0251416a6b7e28a36ee7287356a3f9f1ba746dd799f61d032739ef92a51 ] || exit 1
tmp=$(mktemp -d); trap 'rm -rf -- "$tmp"' EXIT
cp "$production" "$tmp/production"; cp "$lab" "$tmp/lab"
mkdir "$tmp/requests"
python3 - "$source_dir" "$tmp/requests" <<'PY'
import base64, json, pathlib, sys
fixtures=pathlib.Path(sys.argv[1])/'crates/profile-policy/tests/fixtures'; out=pathlib.Path(sys.argv[2])
configs={'valid':(fixtures/'effective-inline.json').read_text(),'vless':(fixtures/'effective-vless.json').read_text(),'provider':(fixtures/'effective-provider.json').read_text(),'rule-provider':(fixtures/'effective-rule-provider.json').read_text(),'invalid':'mode: [\n','missing':'mode: rule\nproxies: []\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,DIRECT\n'}
for name,config in configs.items():
    data=[]
    if name in ('provider','rule-provider'):
        sub='proxies' if name=='provider' else 'rules'; f='provider-payload.yaml' if name=='provider' else 'rule-payload.yaml'
        data=[{'path':f'providers/{sub}/0.yaml','content_base64':base64.b64encode((fixtures/f).read_bytes()).decode()}]
        (out/(name+'-missing.json')).write_text(json.dumps({'version':1,'config':config,'assets':[]}))
    (out/(name+'.json')).write_text(json.dumps({'version':1,'config':config,'assets':data}))
PY
cp "$script_dir/Dockerfile.validator-arm64" "$tmp/Dockerfile"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock build -t xkeen-openwrt-vm-validator-arm64-test:25.12.6 "$tmp"
