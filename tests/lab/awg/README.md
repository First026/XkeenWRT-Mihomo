# Синтетический AmneziaWG peer

Эксперимент предназначен исключительно для выделенной OpenWrt 25.12.6 VM с ядром 6.12.112, маркерами изоляционной лаборатории и единственным интерфейсом `lo`. Программа отказывает до открытия сокетов, если эти условия не выполнены. Ключи фиксированные, синтетические и публичные; они никогда не используются для действительного подключения. На хосте разработки и роутерах сетевые процессы не запускают.

Peer использует ту же реализацию `github.com/metacubex/amneziawg-go` (`0c1c6f40ecd7`, `device_v1`), что и закреплённый Mihomo v1.19.34 для legacy AWG. Пользовательский IP-стек построен на `golang.zx2c4.com/wireguard/tun/netstack` (`b3bc704ef0ee`) с адаптером событий совместимого `tun.Device`; системный TUN не требуется. Прямые и транзитивные зависимости закреплены в `go.mod` и `go.sum`. `import-source.conf` преобразован реальной функцией `importAmnezia` из frontend в `imported-proxies.yaml`; `config` использует именно этот результат и печатает синтетический YAML, `peer` поднимает локальный UDP peer и TCP echo в userspace-стеке, `client` соединяется с ним через SOCKS Mihomo. `AWG_HANDSHAKE_AND_DATA_PASS` выводится только после двусторонней передачи и проверки ненулевых handshake/rx/tx в IPC состояния peer; сами ключи и полный IPC в журналы не выводятся.

Пример воспроизводимой сборки без запуска полученного файла на хосте:

```sh
cd tests/lab/awg
flock /tmp/xkeenwrt-build.lock env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  /workspace/.cache/xkeenwrt/go1.25.4/bin/go build -trimpath -mod=readonly \
  -o /workspace/.cache/xkeenwrt/awg-peer-x86.final .
```

Go 1.25.4 извлечён из официального архива `go1.25.4.linux-amd64.tar.gz`, SHA-256 `9fa5ffeda4170de60f67f3aa0f824e426421ba724c21e133c1e35d6159ca1bec`. Сценарий исполняется только внутри отмеченной VM; результат и ограничения фиксируются отдельно в `docs/awg-handshake-evidence.md`. Сам факт сборки не доказывает handshake или переносимость на устройство.

В `v3/` отдельно подготовлен синтетический профиль из того же импортёра и peer на pinned `device` (ветка AWG v3) с синтетическим header-protection key. Сборка `go build -trimpath -mod=readonly -o /workspace/.cache/xkeenwrt/awg-peer-v3-x86 ./v3` выполняется с теми же Go/CGO/GOOS/GOARCH и build lock. Результат гостевого испытания и ограничения приведены в отчёте; самостоятельная сборка совместимость не доказывает.
