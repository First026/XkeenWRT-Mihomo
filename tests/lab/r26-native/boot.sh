#!/bin/sh
# Boot the disposable lab guest; serial console on a unix socket, log to serial.log.
L=${XK_LAB:-/tmp/xk-lab}
rm -f $L/serial.sock
exec qemu-system-aarch64 -machine virt,accel=tcg,gic-version=3 -cpu cortex-a53 -m 1024 -smp 2 \
  -nodefaults -display none -monitor none -no-reboot \
  -chardev socket,id=con,path=$L/serial.sock,server=on,wait=off,logfile=$L/serial.log \
  -serial chardev:con -nic none \
  -kernel $L/guest/Image -initrd $L/guest/rootfs.cpio -append "console=ttyAMA0 rdinit=/init" \
  -drive if=none,file=$L/persist.img,format=raw,id=persist -device virtio-blk-device,drive=persist
