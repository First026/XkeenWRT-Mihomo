#!/bin/sh
# Lab GitHub for C9 (decision 026), prepared on the build host. Writes into the
# guest's /usr/share/xk-lab:
#  - github/: files at the paths the panel and the release installer request
#    from api.github.com, raw.githubusercontent.com and github.com: a release
#    list with 0.1.26.3, 0.1.26.4 and the lab-only 0.1.26.4.1, the 0.1.26.4.1
#    install.sh and its two APKs;
#  - tls/github.crt and .key for those three names, signed by the lab CA.
# The 0.1.26.4.1 install.sh is this tree's install.sh with the lab version, the
# previous version 0.1.26.4 and the SHA-256 of the lab APKs.
# Usage: github.sh <dir with the 0.1.26.4.1 apks> <guest xk-lab dir> <lab tls dir with ca.key>
set -eu
pair=$1 G=$2 tls=$3
here=$(cd "$(dirname "$0")" && pwd)
new=0.1.26.4.1 repo=First026/XkeenWRT-Mihomo
core="xkeenwrt-core-$new-r0.apk" ui="xkeenwrt-ui-$new-r0.apk"
d="$G/github"
rm -rf "$d"
mkdir -p "$d/repos/$repo" "$d/$repo/v$new" "$d/$repo/releases/download/v$new"
cp "$pair/$core" "$pair/$ui" "$d/$repo/releases/download/v$new/"
core_sha=$(sha256sum "$pair/$core" | cut -d ' ' -f1)
ui_sha=$(sha256sum "$pair/$ui" | cut -d ' ' -f1)
awk -v new="$new" -v c="$core_sha" -v u="$ui_sha" '
  /^version=/ { print "version=" new "-r0"; next }
  /^previous=/ { print "previous=0.1.26.4-r0"; next }
  /^tag=/ { print "tag=v" new; next }
  /^        [0-9a-f]+ "\$core" \\$/ { print "        " c " \"$core\" \\"; next }
  /^        [0-9a-f]+ "\$ui" \|$/ { print "        " u " \"$ui\" |"; next }
  { print }' "$here/../../../install.sh" > "$d/$repo/v$new/install.sh"
grep -qx "version=$new-r0" "$d/$repo/v$new/install.sh"
grep -q "$core_sha \"\$core\"" "$d/$repo/v$new/install.sh"
grep -q "$ui_sha \"\$ui\"" "$d/$repo/v$new/install.sh"
cat > "$d/repos/$repo/releases" <<JSON
[
  {"tag_name":"v$new","name":"XkeenWRT $new","draft":false,"prerelease":false,"published_at":"2026-11-18T18:00:00Z","body":"Lab-only release for C9."},
  {"tag_name":"v0.1.26.4","name":"XkeenWRT 0.1.26.4","draft":false,"prerelease":false,"published_at":"2026-11-18T17:00:00Z","body":"Installed release."},
  {"tag_name":"v0.1.26.3","name":"XkeenWRT 0.1.26.3","draft":false,"prerelease":false,"published_at":"2026-11-18T12:00:00Z","body":"Older release."}
]
JSON
openssl req -newkey rsa:2048 -nodes -subj '/CN=github.com' -keyout "$tls/github.key" -out "$tls/github.csr" 2>/dev/null
printf 'subjectAltName=DNS:api.github.com,DNS:github.com,DNS:raw.githubusercontent.com\nextendedKeyUsage=serverAuth\n' > "$tls/github.cnf"
openssl x509 -req -in "$tls/github.csr" -CA "$tls/ca.crt" -CAkey "$tls/ca.key" -CAcreateserial -days 30 \
  -extfile "$tls/github.cnf" -out "$tls/github.crt" 2>/dev/null
mkdir -p "$G/tls"
cp "$tls/github.crt" "$tls/github.key" "$G/tls/"
echo "XK_LAB_GITHUB_PREPARED core=$core_sha ui=$ui_sha"
