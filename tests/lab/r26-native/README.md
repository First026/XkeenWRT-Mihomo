# Стенд приёмки r26 (С1–С3)

Одноразовая VM OpenWrt 25.12.6 `armsr/armv8` под QEMU TCG на хосте, без сети гостя. Рабочие роутеры не используются.

1. `./prepare.sh <каталог с парой r26>` — закреплённые образы rootfs и ядра, подписанные индексы и пакеты OpenWrt, пара r25 из релиза, Mihomo 1.19.34, initramfs. Нужен доступ к `ghcr.io` и `downloads.openwrt.org`.
2. `./boot.sh &` — запуск VM. Последовательная консоль доступна через unix-сокет `$XK_LAB/serial.sock`.
3. `./console.py $XK_LAB/serial.sock 900 'sh /usr/share/xk-lab/setup.sh'`, затем `install.sh r25`, `c2.sh` (обновление r25 → r26), `c1.sh`, `c3.sh`. `c4.sh upgrade` (после установки r25) и `c4.sh fresh` (на чистом диске) проверяют `.run`, если он лежит рядом с парой r26.

Каждый сценарий печатает строки `XK_LAB_*`; итог — `XK_LAB_C1|C2|C3=PASS` и `XK_LAB_C4_upgrade|fresh=PASS`.

Отклонения от устройства:
- `armsr/armv8` вместо `mediatek/filogic`; у пакетов добавлена архитектура `aarch64_cortex-a53`.
- LAN и WAN — veth-пары в netns, а не порты и Wi‑Fi.
- Mihomo кладётся по закреплённому пути и выбирается через `POST /api/core/update` без загрузки, вместо каталога.
- Адаптер `init` монтирует оверлей ext4 и cgroup2 перед `chroot`.
