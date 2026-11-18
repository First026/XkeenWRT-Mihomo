# 005. Подготовка профиля без запуска ядра

Первый шаг Task 3 — просмотр результата системных overrides для сохранённой ревизии. Он не запускает Mihomo, не создаёт staging/assets и не меняет runtime или сеть. Основание — аудит закреплённого core: даже `mihomo -t` может работать с файлами и сетью. Дальнейший изолированный валидатор и транзакционное применение остаются отдельными этапами.

## Interface

`ConfigStore::prepare(id, expected_revision) -> Result<PreparedPreview, PrepareError>` читает согласованный снимок source-профиля. Устаревшая revision даёт существующий `CONFLICT`. Source и его revision остаются прежними. Это **PreparedPreview**, не разрешённый к запуску Candidate; будущая активация обязана заново проверить revision, assets, core и план.

Authenticated `POST /api/profiles/{id}/prepare` принимает только `{expected_revision: string}`. Успех: `{success: true, preparation: {...}}`, где preparation содержит:

- `profile_id`, `revision`, `source`, `effective_yaml`;
- `mode: "manual-preview"`, `core_validation: "not_run"`, `activatable: false`;
- `changes: [{path, before: string|null, after: string|null, reason}]` — семантические изменения в YAML-представлении; controller secret в этом списке маскируется;
- `diagnostics: [{code, path, message}]` — препятствия будущему запуску, без значений credentials, URL подписок и файловых путей из значений YAML.

С r15 source-подготовка поддерживает обычные YAML-якоря, ссылки на уже завершённые узлы и merge-ключ `<<`. До загрузки дерева проверяются стоимость полного раскрытия ссылок (50 000 узлов, глубина 64 и консервативный лимит строк 8 MiB) и синтаксические ограничения. Циклические/неизвестные ссылки, произвольные теги, повторяющиеся или нестроковые ключи, некорректные merge-значения запрещены. Явные ключи перекрывают merge, в последовательности merge побеждает первая карта. Служебная верхняя карта `anchors` из шаблонов XKeen UI убирается только из effective YAML после раскрытия ссылок, с записью в changes. Source с комментариями и его ревизия сохраняются точно.

`AMBIGUOUS_YAML` также защищает от plain scalars, для которых Rust и Go YAML могут расходиться: legacy booleans (`on`/`yes`), неоднозначные числа, `Null`/`NULL` и timestamps. Узкое исключение — строковый enum `find-process-mode: off` в корне профиля Mihomo; в effective он явно заключён в кавычки. Генераторы URI/подписки пишут все строковые значения в кавычках, включая Reality short-id, пароли и параметры транспорта. Канонические десятичные целые и дробные числа сохраняются без потери точности. Ошибки ограничений имеют стабильные коды; текст парсера и значения YAML в них не включаются. Response проходит существующие auth/Host/Origin/no-store checks. Парсинг и сериализация большого ответа выполняются вне async executor; глубина, число узлов и объём результата ограничены. Одновременно выполняется не более одной HTTP-подготовки на instance сервера, остальные получают `BUSY`; закрытие запроса не освобождает занятый worker раньше окончания работы. Это не доказательство общего RAM budget всех функций HTTP-сервера.

## Manual preview overlay

Оставить proxies/groups/rules/sub-rules/hosts и значения вне managed keys семантически неизменными. Комментарии и оформление всегда сохраняются в source; effective YAML может быть нормализован в читаемую JSON-совместимую форму YAML с явно заключёнными в кавычки строками. Preview не заявляет полной поддержки вложенных параметров или безопасности полученного YAML для самостоятельного запуска.

Установить mixed-port 7890, bind-address 127.0.0.1, allow-lan false; port/socks-port/redir-port/tproxy-port 0. Очистить controller, его TLS/Unix/pipe endpoints, external-doh-server, external-ui/url/name, secret, ss-config и vmess-config. Controller в этом preview полностью выключен: runtime с отдельным секретом ещё не реализован. Установить controller routing-mark и routing-mark 0, interface-name пустой. Очистить listeners/tunnels; непустые исходные значения дополнительно дают diagnostic. Исходный выбор interface/controller mark также требует явного diagnostic. Верхний `routing-mark` (в том числе Keenetic 255 в штатных шаблонах) с r15 нормализуется в 0 и отражается в changes без блокирующего diagnostic; вложенные marks по-прежнему запрещены.

Заменить целиком managed mappings: tun `{enable: false, auto-route: false, auto-redirect: false, auto-detect-interface: false, dns-hijack: []}`, iptables `{enable: false, dns-redirect: false}`, ntp `{enable: false, write-to-system: false}`, tuic-server `{enable: false}`, dns `{enable: false, enhanced-mode: normal, listen: "", use-system-hosts: false, fallback-filter: {geoip: false}}`, profile `{store-selected: false, store-fake-ip: false}`. Geo auto-update выключить. Любая замена видна в changes; объяснение DNS сообщает, что изменяется поведение DNS профиля, но обычное разрешение адресов приложением/core этим не исключается.

## Providers и неизвестные возможности

HTTP(S) proxy/rule providers сохраняют URL, настройки и связи. Только cache path заменяется на относительный путь под `providers/proxies/` или `providers/rules/`, полученный из внутреннего индекса, а не имени/пути пользователя. Имена и ссылки на providers сохраняются. Diagnostics отмечают обязательность будущего получения и проверки payload в изолированном staging. Никаких fetch, чтения или создания файлов по этим путям сейчас нет. File providers и прочие unresolved assets сохраняются с blocking diagnostic, а не читаются и не удаляются.

Неизвестные top-level ключи, необычные типы outbounds, вложенные interface/mark/override-expr, credential-file и geodata зависимости помечаются diagnostics. Их наличие не превращает preview в разрешённый к запуску объект. Полная рекурсивная проверка схемы и разрешённых ресурсов отложена до production validator; отсутствие diagnostics тоже не снимает `activatable: false` и `core_validation: not_run`.

## UI и проверка

Кнопка «Подготовить YAML» работает только для сохранённого профиля без локальных изменений. UI показывает source/effective и список изменений, ограничения и отсутствие проверки core. Редактирование, переключение/повторная загрузка профиля и save инвалидируют прошлый preview; ошибочная или устаревшая подготовка не трогает редактор. Prepare не сохраняет автоматически и не включает ядро.

Проверки через ранее согласованные Configuration/HTTP/UI interfaces: сохранность source/revision, stale revision, managed overrides, YAML ambiguity/limits, неизменность AWG и пользовательских правил, managed provider paths и отсутствие чтения внешнего sentinel файла, auth/no-store, сохранность dirty editor и инвалидирование preview. Синтетические итоговые YAML можно отдельно передать имеющемуся network-disabled lab runner для `mihomo -t`; это не production endpoint и доказывает только parser acceptance.
