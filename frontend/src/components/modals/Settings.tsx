import { Alert, AlertDescription } from '@/components/ui/alert'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Field, FieldContent, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from '@/components/ui/input-group'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  IconAlertCircle,
  IconChevronDown,
  IconChevronUp,
  IconSettings,
  IconTrash,
} from '@tabler/icons-react'
import { Fragment, memo, useCallback, useState, type ReactNode } from 'react'
import { applyEmojiFont } from '../../lib/theme'
import { useAppContext, useModalContext } from '../../lib/store'
import type { AppSettings, EmojiFont, PingMode, ProxySortOrder, ThemeMode } from '../../lib/types'

type BooleanSettingKey = {
  [K in keyof AppSettings]: AppSettings[K] extends boolean ? K : never
}[keyof AppSettings]

type ToggleSetting = {
  id: string
  key: BooleanSettingKey
  path: string
  title: string
  description: string
}

type ToggleSettingHandler = (item: ToggleSetting, value: boolean) => void

const clashApiSettings: ToggleSetting[] = [
  {
    id: 'close-conns-on-apply',
    key: 'closeConnectionsOnApply',
    path: 'clash_api.close_connections_on_apply',
    title: 'Автозакрытие при применении',
    description: 'Закрывать все соединения после успешного применения конфига Mihomo',
  },
]

const pingModeOptions: { value: PingMode; label: string }[] = [
  { value: 'single', label: 'Одинарный' },
  { value: 'double', label: 'Двойной' },
  { value: 'double_keep_alive', label: 'Двойной+KeepAlive' },
]

const themeOptions: { value: ThemeMode; label: string }[] = [
  { value: 'auto', label: 'Авто' },
  { value: 'light', label: 'Светлая' },
  { value: 'dark', label: 'Темная' },
]

const emojiFontOptions: { value: EmojiFont; label: string }[] = [
  { value: 'twemoji', label: 'Twemoji' },
  { value: 'notocoloremoji', label: 'Noto Color Emoji' },
]

const SwitchSettingField = memo(function SwitchSettingField({
  item,
  checked,
  onToggleSetting,
}: {
  item: ToggleSetting
  checked: boolean
  onToggleSetting: ToggleSettingHandler
}) {
  const onToggle = useCallback((value: boolean) => onToggleSetting(item, value), [item, onToggleSetting])

  return (
    <Field orientation="horizontal" className="px-0 py-3">
      <FieldContent>
        <FieldLabel htmlFor={item.id}>{item.title}</FieldLabel>
        <FieldDescription className="text-[13px] whitespace-pre-line">{item.description}</FieldDescription>
      </FieldContent>
      <Switch id={item.id} checked={checked} onCheckedChange={onToggle} aria-label={item.title} />
    </Field>
  )
})

const HiddenFileRow = memo(function HiddenFileRow({
  file,
  index,
  onRemove,
}: {
  file: string
  index: number
  onRemove: (index: number) => Promise<void>
}) {
  const onRemoveClick = useCallback(() => void onRemove(index), [index, onRemove])

  return (
    <InputGroup>
      <InputGroupInput readOnly value={file} />
      <InputGroupAddon align="inline-end">
        <InputGroupButton size="icon-xs" variant="destructive" onClick={onRemoveClick} aria-label={`Показать файл ${file}`}>
          <IconTrash className="size-3.5" />
        </InputGroupButton>
      </InputGroupAddon>
    </InputGroup>
  )
})

const HiddenFilesField = memo(function HiddenFilesField({
  hiddenFiles,
  onRemoveFile,
}: {
  hiddenFiles: string[]
  onRemoveFile: (index: number) => Promise<void>
}) {
  return (
    <Field className="gap-2 py-3">
      <FieldContent>
        <FieldLabel>Скрытые файлы</FieldLabel>
        <FieldDescription className="text-[13px] text-wrap!">Файлы, скрытые из панели вкладок редактора</FieldDescription>
      </FieldContent>

      {hiddenFiles.length === 0 ? (
        <FieldDescription className="py-1 text-[13px]">Нет скрытых файлов</FieldDescription>
      ) : (
        <div className="flex flex-col gap-2">
          {hiddenFiles.map((file, index) => (
            <HiddenFileRow key={file + index} file={file} index={index} onRemove={onRemoveFile} />
          ))}
        </div>
      )}
    </Field>
  )
})

const PING_URL_PRESETS = [
  'cp.cloudflare.com/generate_204',
  'www.gstatic.com/generate_204',
  'www.google.com/generate_204',
  'www.youtube.com/generate_204',
  'redirector.googlevideo.com/generate_204',
  'connectivitycheck.gstatic.com/generate_204',
] as const

const PING_URL_CUSTOM = '__custom__'

function parsePingUrl(raw: string): { protocol: string; host: string; custom: boolean } {
  const match = raw.match(/^(https?):\/\/(.+)$/i)
  const protocol = match?.[1]?.toLowerCase() ?? 'https'
  const host = match?.[2] ?? raw
  return { protocol, host, custom: !(PING_URL_PRESETS as readonly string[]).includes(host) }
}

const PingTestSettingsField = memo(function PingTestSettingsField({
  pingUrl,
  pingTimeout,
  onSave,
  showToast,
  label = 'URL',
  urlDescription = 'Адрес для ручного теста подключений Mihomo',
  timeoutDescription = 'Порог времени теста, после которого подключение считается мертвым',
}: {
  pingUrl: string
  pingTimeout: number
  onSave: (url: string, timeout: number) => Promise<boolean>
  showToast: (msg: string, type?: 'success' | 'error') => void
  label?: string
  urlDescription?: string
  timeoutDescription?: string
}) {
  const [initial] = useState(() => parsePingUrl(pingUrl))
  const [protocol, setProtocol] = useState(initial.protocol)
  const [host, setHost] = useState(initial.host)
  const [custom, setCustom] = useState(initial.custom)
  const [timeout, setTimeout] = useState(String(pingTimeout))

  const save = useCallback(async () => {
    const tHost = host.trim()
    const tTimeout = Number(timeout)
    if (!tHost) return showToast('URL пинг-теста пустой', 'error')
    if (!(Number.isInteger(tTimeout) && tTimeout > 0)) return showToast('Таймаут должен быть целым числом больше 0', 'error')
    const tUrl = `${protocol}://${tHost}`
    if (tUrl === pingUrl && tTimeout === pingTimeout) return
    const ok = await onSave(tUrl, tTimeout)
    if (ok) {
      setHost(tHost)
      setTimeout(String(tTimeout))
    }
  }, [onSave, pingUrl, pingTimeout, showToast, timeout, host, protocol])

  const saveHost = useCallback(
    async (newHost: string, newProtocol: string) => {
      const tHost = newHost.trim()
      const tTimeout = Number(timeout)
      if (!tHost) return showToast('URL пинг-теста пустой', 'error')
      if (!(Number.isInteger(tTimeout) && tTimeout > 0)) return showToast('Таймаут должен быть целым числом больше 0', 'error')
      const tUrl = `${newProtocol}://${tHost}`
      if (tUrl === pingUrl && tTimeout === pingTimeout) return
      const ok = await onSave(tUrl, tTimeout)
      if (ok) {
        setHost(tHost)
        setProtocol(newProtocol)
        setTimeout(String(tTimeout))
      }
    },
    [onSave, pingUrl, pingTimeout, showToast, timeout]
  )

  const hostSelectValue = custom ? PING_URL_CUSTOM : host

  return (
    <FieldGroup className="gap-0!">
      <Field className="px-0 py-3">
        <FieldContent>
          <FieldLabel>{label}</FieldLabel>
          <FieldDescription className="text-[13px]">{urlDescription}</FieldDescription>
        </FieldContent>
        <div className="flex items-center gap-2">
          <Select
            value={protocol}
            items={{ http: 'http', https: 'https' }}
            onValueChange={(value) => {
              setProtocol(value)
              void saveHost(host, value)
            }}
          >
            <SelectTrigger className="w-24" aria-label="Протокол">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="http">http</SelectItem>
                <SelectItem value="https">https</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>

          <Select
            value={hostSelectValue}
            items={{
              ...Object.fromEntries(PING_URL_PRESETS.map((p) => [p, p])),
              [PING_URL_CUSTOM]: 'Свой URL...',
            }}
            onValueChange={(value) => {
              if (value === PING_URL_CUSTOM) {
                setCustom(true)
              } else {
                setHost(value)
                setCustom(false)
                void saveHost(value, protocol)
              }
            }}
          >
            <SelectTrigger className="min-w-0 flex-1" aria-label="Хост">
              {custom ? <span className="text-muted-foreground">Свой URL...</span> : <SelectValue />}
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {PING_URL_PRESETS.map((item) => (
                  <SelectItem key={item} value={item}>
                    {item}
                  </SelectItem>
                ))}
                <SelectItem value={PING_URL_CUSTOM} className="text-muted-foreground">
                  Свой URL...
                </SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>

        {custom && (
          <InputGroup>
            <InputGroupAddon align="inline-start">{protocol}://</InputGroupAddon>
            <InputGroupInput
              value={host}
              onChange={(e) => setHost(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && void save()}
              onBlur={() => void save()}
              placeholder="www.example.com/generate_204"
              aria-label="Свой URL пинга"
              className="pl-0!"
            />
          </InputGroup>
        )}
      </Field>

      <Separator className="my-0" />

      <Field className="px-0 py-3">
        <FieldContent>
          <FieldLabel htmlFor="ping-test-timeout">Таймаут</FieldLabel>
          <FieldDescription className="text-[13px]">{timeoutDescription}</FieldDescription>
        </FieldContent>
        <InputGroup className="max-w-40">
          <InputGroupInput
            id="ping-test-timeout"
            type="number"
            min={1}
            step={100}
            inputMode="numeric"
            className="[appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
            value={timeout}
            onChange={(e) => setTimeout(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void save()}
            onBlur={() => void save()}
            placeholder="5000"
          />
          <InputGroupAddon align="inline-end" className="text-muted-foreground px-2 text-xs">
            мс
          </InputGroupAddon>
        </InputGroup>
      </Field>
    </FieldGroup>
  )
})

function AuthSettingsField() {
  return (
    <Field orientation="horizontal" className="px-0 py-3">
      <FieldContent>
        <FieldLabel>Доступ к панели</FieldLabel>
        <FieldDescription className="text-[13px]">
          Парольный bootstrap отключён. Запросы принимаются только из проверенной management/LAN зоны; WAN и гостевая сеть закрыты.
        </FieldDescription>
      </FieldContent>
      <span className="text-muted-foreground text-xs">Доверенная зона</span>
    </Field>
  )
}

export function SettingsModal({ advanced, diagnostics }: { advanced: ReactNode; diagnostics: ReactNode }) {
  const { state, dispatch, showToast } = useAppContext({ includeSettings: true })
  const { modals } = useModalContext()
  const { settings } = state

  const close = useCallback(() => dispatch({ type: 'SHOW_MODAL', modal: 'showSettingsModal', show: false }), [dispatch])

  const saveSetting = useCallback(
    async (path: string, value: unknown) => {
      try {
        localStorage.setItem(`xkeenwrt.setting:${path}`, JSON.stringify(value))
        return true
      } catch {
        showToast('Настройка действует до закрытия вкладки: браузер запретил локальное сохранение.', 'warning')
        return false
      }
    },
    [showToast]
  )

  const toggleSetting = useCallback(
    async (item: ToggleSetting, value: boolean) => {
      const ok = await saveSetting(item.path, value)
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { [item.key]: value } as Partial<AppSettings> })
    },
    [dispatch, saveSetting]
  )

  const setTheme = useCallback(
    (value: string) => {
      dispatch({ type: 'SET_SETTINGS', settings: { theme: value as ThemeMode } })
    },
    [dispatch]
  )

  const setEmojiFont = useCallback(
    (value: string) => {
      applyEmojiFont(value as EmojiFont)
      dispatch({ type: 'SET_SETTINGS', settings: { emojiFont: value as EmojiFont } })
    },
    [dispatch]
  )

  const removeHiddenFile = useCallback(
    async (index: number) => {
      const next = settings.hiddenConfigFiles.filter((_, i) => i !== index)
      const ok = await saveSetting('ui', { hidden_files: next })
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { hiddenConfigFiles: next } })
    },
    [dispatch, saveSetting, settings.hiddenConfigFiles]
  )

  const setTimezone = useCallback(
    async (value: string) => {
      const offset = parseInt(value, 10)
      const ok = await saveSetting('log.timezone', offset)
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { timezone: offset } })
    },
    [dispatch, saveSetting]
  )

  const savePingTestSettings = useCallback(
    async (url: string, timeout: number) => {
      const ok = await saveSetting('clash_api', { ping_url: url, ping_timeout: timeout })
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { pingTestUrl: url, pingTestTimeout: timeout } })
      return ok
    },
    [dispatch, saveSetting]
  )

  const toggleHideUnavailable = useCallback(
    async (value: boolean) => {
      const ok = await saveSetting('clash_api', { hide_unavailable_proxies: value })
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { hideUnavailableProxies: value } })
    },
    [dispatch, saveSetting]
  )

  const setPingMode = useCallback(
    async (value: string) => {
      const ok = await saveSetting('clash_api', { ping_mode: value })
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { pingMode: value as PingMode } })
    },
    [dispatch, saveSetting]
  )

  const setProxySortOrder = useCallback(
    async (value: string) => {
      const ok = await saveSetting('clash_api', { proxy_sort_order: value })
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { proxySortOrder: value as ProxySortOrder } })
    },
    [dispatch, saveSetting]
  )

  const setHideCounter = useCallback(
    async (value: number) => {
      const v = Math.max(1, Math.min(10, value))
      if (v === settings.hideUnavailableProxiesCounter) return
      const ok = await saveSetting('clash_api', { hide_unavailable_proxies_counter: v })
      if (ok) dispatch({ type: 'SET_SETTINGS', settings: { hideUnavailableProxiesCounter: v } })
    },
    [dispatch, saveSetting, settings.hideUnavailableProxiesCounter]
  )

  const sortOrderOptions: { value: ProxySortOrder; label: string }[] = [
    { value: 'default', label: 'По-умолчанию' },
    { value: 'name', label: 'По названию' },
    { value: 'ping', label: 'По пингу' },
  ]

  return (
    <Dialog open={modals.showSettingsModal} onOpenChange={(open) => !open && close()}>
      <DialogContent className="flex h-[79dvh]! max-w-xl! flex-col overflow-hidden md:h-142!">
        <DialogHeader className="shrink-0">
          <DialogTitle className="flex items-center gap-2">
            <IconSettings size={24} className="text-chart-2" /> Настройки
          </DialogTitle>
        </DialogHeader>

        <Tabs defaultValue="general" className="flex flex-1 flex-col overflow-hidden">
          <TabsList
            variant="line"
            className="border-border h-auto! w-full shrink-0 flex-wrap justify-start gap-x-1 gap-y-1 rounded-none border-b px-0 *:h-8 *:flex-none *:px-1.5 *:text-[13px] *:after:bottom-0"
          >
            <TabsTrigger value="general">Общие</TabsTrigger>
            <TabsTrigger value="clash-api">Mihomo</TabsTrigger>
            <TabsTrigger value="updates">Обновления</TabsTrigger>
            <TabsTrigger value="advanced">Расширенные настройки</TabsTrigger>
            <TabsTrigger value="diagnostics">Диагностика</TabsTrigger>
          </TabsList>

          <ScrollArea className="min-h-0 flex-1">
            <div className="pr-2 pl-1">
              <TabsContent value="general">
                <FieldGroup className="gap-0!">
                  <p className="text-muted-foreground pt-3 pb-1 text-xs font-medium tracking-wider uppercase">Оформление</p>
                  <Field orientation="horizontal" className="px-0 py-3">
                    <FieldContent>
                      <FieldLabel htmlFor="theme">Тема приложения</FieldLabel>
                      <FieldDescription className="text-[13px]">Ручной режим или синхронизация с системой</FieldDescription>
                    </FieldContent>
                    <Select
                      value={settings.theme}
                      items={Object.fromEntries(themeOptions.map((o) => [o.value, o.label]))}
                      onValueChange={setTheme}
                    >
                      <SelectTrigger id="theme" className="w-32">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {themeOptions.map((item) => (
                            <SelectItem key={item.value} value={item.value}>
                              {item.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Separator className="my-2" />
                  <Field orientation="horizontal" className="px-0 py-3">
                    <FieldContent>
                      <FieldLabel htmlFor="emoji-font">Шрифт эмоджи</FieldLabel>
                      <FieldDescription className="text-[13px]">
                        Используется для отображения флагов и других эмоджи. Шрифты отличные от Twemoji должны быть установлены в системе.
                      </FieldDescription>
                    </FieldContent>
                    <Select
                      value={settings.emojiFont}
                      items={Object.fromEntries(emojiFontOptions.map((o) => [o.value, o.label]))}
                      onValueChange={setEmojiFont}
                    >
                      <SelectTrigger id="emoji-font" className="w-42">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {emojiFontOptions.map((item) => (
                            <SelectItem key={item.value} value={item.value}>
                              {item.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Separator className="my-2" />
                  <p className="text-muted-foreground pt-3 pb-1 text-xs font-medium tracking-wider uppercase">Редактор</p>
                  <HiddenFilesField hiddenFiles={settings.hiddenConfigFiles} onRemoveFile={removeHiddenFile} />
                  <Separator className="my-2" />
                  <p className="text-muted-foreground pt-3 pb-1 text-xs font-medium tracking-wider uppercase">Авторизация</p>
                  <AuthSettingsField />
                  <Separator className="my-2" />
                  <p className="text-muted-foreground pt-1 pb-1 text-xs font-medium tracking-wider uppercase">Журнал</p>
                  <Field orientation="horizontal" className="px-0 py-3">
                    <FieldContent>
                      <FieldLabel htmlFor="timezone">Часовой пояс</FieldLabel>
                      <FieldDescription className="text-[13px]">Сдвиг времени для записей в журнале</FieldDescription>
                    </FieldContent>
                    <Select
                      value={String(settings.timezone)}
                      items={Object.fromEntries(
                        Array.from({ length: 27 }, (_, i) => {
                          const v = String(i - 12)
                          return [v, `UTC${i - 12 >= 0 ? '+' : ''}${v}`]
                        })
                      )}
                      onValueChange={setTimezone}
                    >
                      <SelectTrigger id="timezone" className="w-30">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {Array.from({ length: 27 }, (_, i) => i - 12).map((offset) => (
                            <SelectItem key={offset} value={String(offset)}>
                              UTC{offset >= 0 ? '+' : ''}
                              {offset}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Separator className="my-2" />
                  <p className="text-muted-foreground pt-1 pb-1 text-xs font-medium tracking-wider uppercase">Тест подключений</p>
                  <PingTestSettingsField
                    key={`${settings.pingTestUrl}\x00${settings.pingTestTimeout}`}
                    pingUrl={settings.pingTestUrl}
                    pingTimeout={settings.pingTestTimeout}
                    onSave={savePingTestSettings}
                    showToast={showToast}
                  />
                  <Separator />
                  <Field orientation="horizontal" className="px-0 py-3">
                    <FieldContent>
                      <FieldLabel htmlFor="ping-mode">Режим теста</FieldLabel>
                      <FieldDescription className="text-[13px] whitespace-pre-line">
                        Двойной режим выполняет первый запрос для прогрева DNS/MUX, затем сам тест. KeepAlive повторно использует
                        первое соединение.
                      </FieldDescription>
                    </FieldContent>
                    <Select
                      value={settings.pingMode}
                      items={Object.fromEntries(pingModeOptions.map((o) => [o.value, o.label]))}
                      onValueChange={setPingMode}
                    >
                      <SelectTrigger id="ping-mode" className="w-45">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {pingModeOptions.map((item) => (
                            <SelectItem key={item.value} value={item.value}>
                              {item.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                </FieldGroup>
              </TabsContent>

              <TabsContent value="clash-api">
                <p className="text-muted-foreground pt-3 pb-1 text-xs font-medium tracking-wider uppercase">Селекторы</p>
                <FieldGroup className="gap-0!">
                  <Field orientation="horizontal" className="px-0 py-3">
                    <FieldContent>
                      <FieldLabel htmlFor="hide-unavailable">Скрывать недоступные подключения</FieldLabel>
                      <FieldDescription className="text-[13px]">
                        Скрывать подключения из селекторов при наличии нескольких таймаутов подряд в истории проверок
                      </FieldDescription>
                    </FieldContent>
                    <Switch
                      id="hide-unavailable"
                      checked={settings.hideUnavailableProxies}
                      onCheckedChange={toggleHideUnavailable}
                      aria-label="Скрывать недоступные подключения"
                    />
                  </Field>
                  <Separator className="my-0" />
                  <Field orientation="horizontal" className="px-0 py-3">
                    <FieldContent>
                      <FieldLabel htmlFor="hide-counter">Порог таймаутов</FieldLabel>
                      <FieldDescription className="text-[13px]">Порог таймаутов подряд для скрытия подключений (1–10)</FieldDescription>
                    </FieldContent>
                    <InputGroup className="w-15">
                      <InputGroupInput id="hide-counter" readOnly value={settings.hideUnavailableProxiesCounter} />
                      <InputGroupAddon align="inline-end" className="flex flex-col gap-0">
                        <InputGroupButton
                          aria-label="Увеличить"
                          className="text-muted-foreground hover:text-foreground h-[calc(50%-0.5px)]! min-h-0! px-1 text-[9px]"
                          onClick={() => void setHideCounter(settings.hideUnavailableProxiesCounter + 1)}
                        >
                          <IconChevronUp />
                        </InputGroupButton>
                        <InputGroupButton
                          aria-label="Уменьшить"
                          className="text-muted-foreground hover:text-foreground h-[calc(50%-0.5px)]! min-h-0! px-1 text-[9px]"
                          onClick={() => void setHideCounter(settings.hideUnavailableProxiesCounter - 1)}
                        >
                          <IconChevronDown />
                        </InputGroupButton>
                      </InputGroupAddon>
                    </InputGroup>
                  </Field>
                  <Separator className="my-0" />
                  <Field orientation="horizontal" className="px-0 py-3">
                    <FieldContent>
                      <FieldLabel htmlFor="proxy-sort">Сортировка</FieldLabel>
                      <FieldDescription className="text-[13px]">
                        Порядок отображения подключений в списке. Не влияет на fallback логику
                      </FieldDescription>
                    </FieldContent>
                    <Select
                      value={settings.proxySortOrder}
                      items={Object.fromEntries(sortOrderOptions.map((o) => [o.value, o.label]))}
                      onValueChange={setProxySortOrder}
                    >
                      <SelectTrigger id="proxy-sort" className="w-39">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          {sortOrderOptions.map((item) => (
                            <SelectItem key={item.value} value={item.value}>
                              {item.label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </Field>
                </FieldGroup>
                <Separator className="my-2" />
                <p className="text-muted-foreground pt-3 pb-1 text-xs font-medium tracking-wider uppercase">Соединения</p>
                <FieldGroup className="gap-0!">
                  {clashApiSettings.map((item, index) => (
                    <Fragment key={item.id}>
                      <SwitchSettingField item={item} checked={settings[item.key]} onToggleSetting={toggleSetting} />
                      {index < clashApiSettings.length - 1 && <Separator className="my-0" />}
                    </Fragment>
                  ))}
                </FieldGroup>
              </TabsContent>

              <TabsContent value="updates">
                <Alert className="my-2 border-blue-500/20 bg-blue-100 p-3 text-blue-700 dark:bg-[#101d2e] dark:text-blue-300">
                  <IconAlertCircle className="size-4.5" />
                  <AlertDescription className="text-xs leading-5">
                    Обновления Mihomo устанавливаются из встроенного каталога совместимых релизов. Версия, архив, размер, SHA-256 и ABI
                    проверяются до атомарного переключения. Управление каталогом доступно в разделе «Ядро».
                  </AlertDescription>
                </Alert>
              </TabsContent>

              <TabsContent value="advanced">{advanced}</TabsContent>
              <TabsContent value="diagnostics">{diagnostics}</TabsContent>
            </div>
          </ScrollArea>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
