#!/bin/sh
# Only executes inside a disposable marked no-NIC OpenWrt VM.
set -eu
grep -qw xkeenwrt.isolation_lab=1 /proc/cmdline || exit 1
cd /usr/share/xkeen-lab-packages
if apk add --no-network --allow-untrusted --force-non-repository ./xkeenwrt-core-0.1-r1.apk ./xkeenwrt-ui-0.1-r1.apk >/tmp/xk-diff-apk.log 2>&1; then
  echo DIAG_PACKAGE_INSTALL=OK
else
  echo DIAG_PACKAGE_INSTALL=FAILED; exit 1
fi
if ./runtime-package-smoke.sh >/tmp/xk-diff-smoke.log 2>&1; then
  echo DIAG_SMOKE=PASS
else
  echo DIAG_SMOKE=FAILED
fi
for marker in LAB_RUNTIME_READY=procd-socket LAB_RUNTIME_FAIL=validate LAB_RUNTIME_FAIL=save LAB_HTTP_TRANSPORT=failed LAB_RUNTIME_PASS=auth,save,validate,apply,control,stop,start; do
  if grep -qx "$marker" /tmp/xk-diff-smoke.log; then printf 'DIAG_%s\n' "$marker"; fi
done
if [ ! -S /var/run/xkeenwrt/control.sock ]; then echo DIAG_RUNTIME_SOCKET=ABSENT; exit 1; fi
echo DIAG_RUNTIME_SOCKET=PRESENT
/usr/libexec/xkeenwrt-integration/validator-diff
printf 'DIAG_PROBE_EXIT=%s\n' "$?"
echo DIAG_DONE=YES
