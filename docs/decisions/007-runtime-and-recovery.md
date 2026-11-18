# 007. Границы runtime, проверки профиля и независимого отката

Статус: согласованный контракт текущей реализации; приёмка отдельных частей фиксируется в объёме 1–6 и отчётах испытаний. Решение продолжает [002](002-router-preservation.md), [005](005-profile-preparation-preview.md) и [006](006-validator-lab-supervisor.md).

## Почему процессы разделены

HTTP обслуживает пользовательские запросы; отдельный runtime сериализует изменения и управляет фиксированным procd-сервисом Mihomo. Проверка недоверенного профиля выполняется отдельным однопоточным validator. Независимый recovery helper отменяет сетевую транзакцию даже при недоступной панели или зависшем runtime. Цена — несколько протоколов и durable состояние; выигрыш — отказ экспериментального процесса не блокирует отмену собственных сетевых изменений.

Recovery не импортирует backend и не исполняет команды из HTTP/журнала. Он принимает только ограниченную типизированную схему и использует фиксированные системные инструменты. Вместо shell выбран самостоятельный маленький Rust executable: требуются BOOTTIME, fsync, bounded flock, безопасное чтение файлов и ограниченное управление дочерними процессами, которые нельзя предполагать доступными как утилиты BusyBox.

## Кандидат и допуск

Исходный профиль и подготовленный просмотр остаются различными сущностями. Immutable candidate включает revision, точные effective config bytes, управляемые listener/DNS/controller поля и все staged asset bytes. `candidate_id` обозначает именно этот набор. Изменение профиля или assets требует нового кандидата и новой проверки.

Validator находится по фиксированному пути `/usr/libexec/xkeenwrt/xkeenwrt-validate`, Mihomo — `/usr/libexec/xkeenwrt/mihomo`. Вход — один JSON v1 с `config` и массивом `{path, content_base64}`. Config ограничен 1 MiB; assets — до 64 файлов (с r15; ранее 32) и прежние 8 MiB decoded суммарно. Общий `profile_policy::MAX_PROVIDER_FILES` используется подготовкой, staging, validator, runtime grant и recovery; проверки каталогов согласованы с ним. Пути только относительные управляемые, без traversal, symlink и специальных файлов. Выход — один ограниченный JSON `{status, code}` с `valid`, `invalid` или `unavailable` и фиксированным code; сырой вывод core не публикуется.

Успешный `mihomo -t` и общая pure policy допуска обязательны одновременно. Policy находится в `crates/profile-policy` и используется backend и validator без дублирования. Успешная проверка не означает работоспособность сервера VPN, startup или handshake. Производственная сборка не содержит лабораторных fault hooks. Неподдержанный профиль получает объяснимый отказ, а не скрыто изменённое поведение.

## Ручной режим

- `POST /api/profiles/{id}/prepare` остаётся неисполняющим просмотром.
- `POST /api/profiles/{id}/validate` с `expected_revision` возвращает candidate и статус проверки.
- `POST /api/profiles/{id}/apply` принимает `expected_revision`, `candidate_id`, `idempotency_key`; это ручное применение без перехвата LAN.
- `GET /api/control` и `POST /api/control` с `start`/`stop` обслуживаются runtime; запуск требует активной проверенной генерации.

`/etc/xkeenwrt/transaction.json` записывается атомарно с fsync файла и каталога до публикации. Previous-good в `/etc/xkeenwrt/history` — immutable snapshot всего config/assets и прежнего состояния запуска. Публикуется целый private core home, а не отдельно YAML и частично обновлённые providers. Core home — `/tmp/xkeenwrt/runtime/active`; controller — `127.0.0.1:9090`, secret хранится отдельно с mode 0600. После успешного restart/health новая генерация фиксируется; при сбое восстанавливается предыдущая. Если core был остановлен, rollback не включает его самовольно.

History pruning обязан сохранять snapshots, на которые ссылается активная или pending network transaction. Manual apply и network/recovery используют общий mutation lock и проверяют поколение; отдельные очереди не дают права перезаписывать состояние друг друга.

### Единственный источник активного состояния

Пока сеть находится в pending или действует подтверждённая сетевая генерация, authoritative состоянием является сетевой журнал. Он хранит `current_core`, `previous_core` и `baseline_core` — immutable bundles с config/assets/overlay и сведениями о профиле, а также текущий и предыдущий сетевые manifests. Baseline создаётся до первого pilot и сохраняется при последующих сетевых изменениях.

Сетевой coordinator получает новый immutable кандидат, проверенный с точным typed overlay. Он публикует этот core home временно, **не фиксируя новую версию в ручном journal**. Confirm делает текущую сетевую генерацию активной; rollback возвращает previous, disable — baseline и исходное отсутствие перехвата. Runtime при перезапуске сначала разрешает состояние сетевого журнала и лишь затем допускает ручной режим. Поэтому отменённый сетевой candidate не может быть восстановлен из ручного journal.

Ручное применение в pending/active сетевом режиме блокируется с понятной причиной; команды управления core проходят через сетевой coordinator и выбранную failure policy. После завершённого disable снова применяется ручной journal, который всё это время оставался неизменным. Неопределённое или отозванное состояние не разрешает запуск. Ссылки всех трёх bundles и previous network удерживают history от удаления; интерфейс публикации не принимает произвольные пути или байты из HTTP.

## Сетевой pilot

План содержит profile/revision/candidate, LAN interface, выбранные IPv4/IPv6 и исключённые management адреса, IPv6 policy и failure policy. Значения запроса проверяются по доверенной runtime-инвентаризации. Первый pilot выбирает ровно один IPv4 /32. Неизвестный или пересекающийся management/IPv6 scope блокирует применение.

Сеть изменяется только через собственную таблицу `inet xkeenwrt` и зарезервированные после проверки конфликтов mark/mask, routing table и rule priority. Трафик самого роутера не захватывается; автоматического TUN fallback нет. TCP/UDP DNS выбранного клиента, включая запросы к адресу роутера, направляются в отдельный Mihomo listener; локальные имена и reverse-зоны возвращаются к штатному dnsmasq. Глобальные dnsmasq/UCI upstream не заменяются.

API состоит из `/api/network/plan`, `/apply`, `/confirm`, `/status`, `/disable`. Apply возвращает pending transaction с отдельным confirm token и сроком 120 секунд. Confirm требует явного действия пользователя и положительных локальных health checks. Ответ API или закрытие вкладки не означают confirm.

`owner-id` создаётся runtime и хранится в root-owned файле. `generation` — durable монотонный номер; `plan_id` — UUID плана. Комментарий таблицы имеет строгий вид `xkeenwrt:<owner_id>:<generation>`. Совпадение комментария не доказывает семантику таблицы. Перед восстановлением/удалением проверяются собственность и полный ожидаемый набор правил; чужие объекты и неоднозначные дубликаты не удаляются.

## Независимый recovery

Фиксированный helper `/usr/libexec/xkeenwrt/xkeenwrt-recovery` работает под procd. До любых изменений он проверяет платформу, разрешённое развёртывание, UID, приватные root-owned каталоги/файлы и single-supervisor lock. Общий `/var/run/xkeenwrt/mutation.lock` берётся с ограниченным ожиданием и не удерживается всё окно подтверждения.

Порядок первого apply: запустить helper → получить idle-ready → записать durable pending manifest → получить READY для точных transaction/generation/boot-id → менять сеть. После перезапуска helper уже существующий pending сразу отменяется; его нельзя ошибочно считать новым pilot или продлевать.

`/etc/xkeenwrt/recovery.json` содержит версию, transaction, generation, boot-id, BOOTTIME начала/deadline, state, current и previous-good. Срок — 120 000 ms BOOTTIME. Перевод wall clock его не продлевает; после reboot pending отменяется до восстановления перехвата. READY публикуется атомарно; он не является доказательством успешного rollback.

Зависший runtime после ограниченного ожидания lock останавливается через фиксированный собственный init service. Helper отзывает generation и выполняет идемпотентный rollback. Вся работа с инструментами имеет ограниченные ввод, вывод, время и завершение; blocking wait/join без deadline запрещён в этом пути.

Откат снимает candidate interception/DNS и owned routes/rules, восстанавливает previous config/assets, запускает core только если он работал ранее, проверяет его здоровье и затем возвращает previous network policy. Первоначальный pilot без previous network возвращает прямое исходное поведение. Отмена pilot и выбранная политика отказа уже подтверждённого профиля — разные случаи. Восстановление перехвата к неработающему listener не считается успешным.

## Ограниченное завершение и запоздавшие процессы

Эти требования приняты для реализации; успешный unit-тест не заменяет VM-проверки остановки процесса на каждой границе.

Команды сетевой транзакции создаются в отдельном cgroup. Размещение должно быть атомарным при создании процесса: `clone3(CLONE_INTO_CGROUP)` с заранее проверенным directory FD. Обычный `fork` с последующим входом в cgroup оставляет окно, в котором остановленный child удерживает унаследованный flock, но ещё не доступен через cgroup. Такой fallback не допускается: отсутствие нужного syscall означает `unavailable` до сетевой мутации.

Аргументы, stdin/stdout/stderr и FD подготавливаются до clone; child до exec выполняет только async-signal-safe операции. Parent получает PID без ожидания exec handshake и использует ограниченный `waitpid(WNOHANG)`. По истечении срока недостаточно отправить SIGKILL: до следующей мутации требуется подтверждённое отсутствие процессов в собственном operation cgroup. Выход непосредственного child также не доказывает отсутствие потомков.

Recovery имеет отдельный cgroup для своих команд. Его identity включает boot-id, PID, starttime и уникальное поколение supervisor. После смерти прежнего supervisor новый экземпляр очищает только точно соответствующий старый cgroup, затем получает supervisor lock и публикует новую identity до запуска children. Живой либо неоднозначный владелец блокирует захват. Параллельные попытки восстановления не должны направлять stale cleanup в cgroup нового supervisor.

То же правило применяется к read-only inventory до создания pending journal. Runtime публикует identity отдельного command cgroup для своего экземпляра до любых children. При старте короткий bootstrap lock сериализует проверку прежней identity, очистку cgroup только доказанно умершего runtime, получение lifetime lock и публикацию новой identity. Bootstrap lock освобождается до запуска children. Helper при отзыве очищает весь command cgroup остановленного runtime, включая inventory, а не только команды последней транзакции.

Для Mihomo применяется отдельный core cgroup и root-private launch grant с nonce, desired-running, digest конфигурации, assets, controller secret и typed overlay. Фиксированный `core-run <nonce>` входит в core cgroup до чтения разрешения, проверяет весь home и перечитывает grant перед exec. Он не берёт mutation lock. Отзыв изменяет nonce и desired-running; запоздавший procd start со старым nonce не получает право запуститься.

При аварийном отзыве helper фиксирует точную transaction/generation/boot identity, отзывает grant, останавливает runtime, подтверждает прекращение его operation cgroup, останавливает core и подтверждает опустошение core cgroup. Затем под mutation lock фиксирует отзыв и восстанавливает previous-good. Fence имеет приоритет перед конкурентным confirm. Одной отправки команды stop или совпадения имени процесса недостаточно.

## Достоверность плана и подтверждения

Адрес управления берётся из реального HTTP TCP peer. Выбранный IPv4 /32 связывается с MAC по доверенным neighbour/DHCP данным и проверенной LAN-топологии. Перехват IPv4 и DNS требует обоих признаков. Внешний IPv6 выбранного L2-клиента блокируется по MAC, включая временные IPv6-адреса; список /128 сам по себе не ограничивает весь клиент. Неоднозначный neighbour, routed tunnel или неподтверждённая bridge-топология не допускают pilot.

После запуска core повторно проверяется inventory. Новые слушатели допускаются только при подтверждённой принадлежности socket inode точному procd PID/starttime Mihomo. Чужие prerouting hooks нельзя считать совместимыми только по одному внешне безопасному правилу: требуется доказать весь traversal. Текущие stgws/zapret2 рабочего роутер остаются отдельной неподтверждённой комбинацией.

Ожидаемые nft semantics вычисляются до мутации общим JSON AST generator для planner, executor и recovery. Применённый ruleset не может стать собственным эталоном. Normalizer удаляет только доказанно динамические поля, сохраняет порядок правил и учитывает наблюдаемые преобразования nft. Обычный manifest и failblock имеют отдельные заранее вычисленные digests.

Повтор запроса apply получает тот же confirm token: HMAC-SHA256 с отдельным persistent ключом, привязанный к однозначно кодированным transaction/generation/plan/idempotency. В журнале хранится только hash токена, из status/logs токен удаляется. Существующий журнал при утраченном ключе не разрешает создать новый ключ. Receipt успешного применения записывается после проверки semantics и здоровья; confirm требует receipt, свежую проверку и неистёкший BOOTTIME deadline.

## Подтверждённая сеть после сбоя

Confirmed не означает, что helper может навсегда прекратить наблюдение. Сбой core, firewall reload, изменение WAN и restart требуют согласования с текущей generation. Authoritative состояние и применение failure policy принадлежат независимому helper под общим lock; coordinator сообщает ограниченное типизированное событие с generation. Устаревшее событие не изменяет новое поколение.

`direct-on-failure` снимает только собственный перехват; `block-selected-on-failure` оставляет заранее проверенную блокировку выбранного клиента. Восстановление допускается только после проверки здоровья core, inventory, собственности объектов и отсутствия fence. Неизвестное изменение чужих правил не исправляется автоматически. Этот протокол ещё требует реализации и VM-матрицы; имеющийся rollback previous-good не считается поддержкой постоянной failure policy.

Удаление и неполное обновление APK определены отдельно в [решении 008](008-package-integrity-and-rescue.md).

## Providers и relay

Контроллер доступен только через фиксированный loopback адрес и allowlist методов/маршрутов; вход пользователя не выбирает socket, executable или произвольный upstream. WebSocket каналы ограничены logs/traffic/memory/connections и проходят те же auth/origin проверки. Секреты и подписочные URL маскируются без уничтожения всей полезной диагностики.

Provider refresh — отдельное действие по непрозрачному ID существующей записи профиля и expected revision. Runtime получает файл с проверкой назначения/redirect/размера/deadline, формирует целый candidate, заново проверяет его и публикует транзакционно. Generic PUT relay обновления providers не допускается. UA/HWID, filter и override сохраняются в пределах поддержанной схемы. Неполный staging не заменяет активный home.

## Проверка решения

Каждая граница требует VM evidence: реальный validator без fault features, ручной procd/HTTP, providers, журналы и previous-good, истечение 120 секунд, потеря UI/runtime/core/helper, изменение boot-id, пакеты выбранного/невыбранного/management клиентов, DNS/IPv6, обе failure policies и package lifecycle. Успешная сборка, mock или root-owned marker сами по себе не закрывают эту проверку. Рабочие роутеры остаются вне испытаний до отдельного допуска.
