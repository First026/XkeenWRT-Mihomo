import { Alert, AlertAction, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { IconAlertCircle, IconDeviceFloppy, IconInfoCircle, IconX } from '@tabler/icons-react'
import * as jsyaml from 'js-yaml'
import { isNode, isSeq, parseDocument, YAMLMap, type Document } from 'yaml'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { apiCall } from '../../../lib/api'
import { useAppContext } from '../../../lib/store'

const FAKE_IP_WARNING_STORAGE_KEY = 'dnsFakeIpFilterWarningDismissed'

function formatPortListener(listener: string): string {
  return listener
    .split(',')
    .map((name) => name.trim())
    .join(', ')
}

function DnsSettingLabel({ children, tooltip }: { children: string; tooltip: string }) {
  const formattedTooltip = tooltip.replaceAll('\\n', '\n')
  const [open, setOpen] = useState(false)

  return (
    <div className="flex items-center gap-1">
      <Label className="text-xs">{children}</Label>
      <Tooltip open={open} onOpenChange={setOpen}>
        <TooltipTrigger
          render={<span className="text-muted-foreground inline-flex cursor-help" />}
          aria-label={`Подробнее: ${children}`}
          onClick={() => setOpen((prev) => !prev)}
        >
          <IconInfoCircle size={14} />
        </TooltipTrigger>
        <TooltipContent
          side="right"
          sideOffset={8}
          className="max-w-xs whitespace-pre-line"
          onClick={() => {
            if (typeof window !== 'undefined' && window.innerWidth < 768) setOpen(false)
          }}
        >
          {formattedTooltip}
        </TooltipContent>
      </Tooltip>
    </div>
  )
}

interface DnsConfig {
  enhancedMode: string
  fakeIpFilterMode: string
  fakeIpFilter: string
  bootstrap: string
  nameserver: string
  proxyServerNameserver: string
  nameserverPolicy: string
  fallback: string
}

export const DEFAULT_DNS_CONFIG: DnsConfig = {
  enhancedMode: 'redir-host',
  fakeIpFilterMode: 'blacklist',
  fakeIpFilter: '+.local',
  bootstrap: '77.88.8.8',
  nameserver: 'https://1.1.1.1/dns-query\nhttps://8.8.8.8/dns-query',
  proxyServerNameserver: 'https://1.1.1.1/dns-query\nhttps://8.8.8.8/dns-query',
  nameserverPolicy: '',
  fallback: 'tls://77.88.8.1\ntls://77.88.8.8',
}

const DEFAULT_DNS_LISTEN = '127.0.0.1:1053'
const YAML_LINE_WIDTH = 200

function trimFlowSeqPadding(text: string): string {
  return text.replace(/\[[ \t]+/g, '[').replace(/[ \t]+\]/g, ']')
}

function parseList(text: string): string[] {
  const trimmed = text.trim()
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    return trimmed
      .slice(1, -1)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  }
  return trimmed
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
}

function parseNameserverPolicy(text: string): Record<string, string[]> {
  const trimmed = text.trim()
  if (!trimmed) return {}

  let parsed: unknown
  try {
    parsed = jsyaml.load(trimmed, { json: true })
  } catch {
    throw new Error('Ошибка валидации YAML. Проверьте корректность записи')
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Ошибка валидации YAML. Проверьте корректность записи')
  }

  const result: Record<string, string[]> = {}
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (Array.isArray(value)) {
      result[key] = value.map(String)
    } else if (value != null) {
      result[key] = [String(value)]
    }
  }
  return result
}

function getCommentBefore(doc: Document, path: string[]): string | undefined {
  const existing = doc.getIn(path, true)
  return isNode(existing) ? (existing.commentBefore ?? undefined) : undefined
}

function buildPolicyNode(doc: Document, text: string): YAMLMap {
  const policy = parseNameserverPolicy(text)
  const map = new YAMLMap()
  for (const [key, servers] of Object.entries(policy)) {
    if (servers.length === 1) {
      map.set(key, servers[0])
    } else if (servers.length > 1) {
      const seq = doc.createNode(servers)
      if (isSeq(seq)) seq.flow = true
      map.set(key, seq)
    }
  }
  return map
}

function setOrDeleteList(doc: Document, path: string[], items: string[]) {
  if (!items.length) {
    doc.deleteIn(path)
    return
  }
  const commentBefore = getCommentBefore(doc, path)
  const seq = doc.createNode(items)
  if (commentBefore !== undefined) seq.commentBefore = commentBefore
  doc.setIn(path, seq)
}

export function patchDnsConfig(content: string, config: DnsConfig): string {
  const doc = parseDocument(content)
  if (doc.errors.length) throw new Error('Исправьте YAML перед изменением DNS')

  doc.setIn(['dns', 'enable'], true)
  if (!doc.hasIn(['dns', 'listen'])) doc.setIn(['dns', 'listen'], DEFAULT_DNS_LISTEN)
  doc.setIn(['dns', 'enhanced-mode'], config.enhancedMode)

  if (config.enhancedMode === 'fake-ip') {
    doc.setIn(['dns', 'fake-ip-filter-mode'], config.fakeIpFilterMode)
    setOrDeleteList(doc, ['dns', 'fake-ip-filter'], parseList(config.fakeIpFilter))
  }

  setOrDeleteList(doc, ['dns', 'default-nameserver'], parseList(config.bootstrap))

  const policyCommentBefore = getCommentBefore(doc, ['dns', 'nameserver-policy'])
  const policyNode = buildPolicyNode(doc, config.nameserverPolicy)
  if (policyCommentBefore !== undefined) policyNode.commentBefore = policyCommentBefore
  if (policyNode.items.length) doc.setIn(['dns', 'nameserver-policy'], policyNode)
  else doc.deleteIn(['dns', 'nameserver-policy'])

  setOrDeleteList(doc, ['dns', 'nameserver'], parseList(config.nameserver))
  setOrDeleteList(doc, ['dns', 'proxy-server-nameserver'], parseList(config.proxyServerNameserver))
  setOrDeleteList(doc, ['dns', 'fallback'], parseList(config.fallback))

  if (!doc.hasIn(['dns', 'fallback-filter'])) doc.setIn(['dns', 'fallback-filter'], { geoip: false })

  return trimFlowSeqPadding(doc.toString({ lineWidth: YAML_LINE_WIDTH }))
}

export function setDnsEnabled(content: string, enabled: boolean): string {
  const doc = parseDocument(content)
  if (doc.errors.length) throw new Error('Исправьте YAML перед изменением DNS')
  doc.setIn(['dns', 'enable'], enabled)
  return trimFlowSeqPadding(doc.toString({ lineWidth: YAML_LINE_WIDTH }))
}

export function ensureDnsEnabled(content: string, config: DnsConfig): string {
  const doc = parseDocument(content)
  if (doc.errors.length) throw new Error('Исправьте YAML перед изменением DNS')
  const hasDns = doc.hasIn(['dns'])

  if (!hasDns) {
    return patchDnsConfig(content, config)
  }

  doc.setIn(['dns', 'enable'], true)
  if (!doc.hasIn(['dns', 'listen'])) doc.setIn(['dns', 'listen'], DEFAULT_DNS_LISTEN)
  return trimFlowSeqPadding(doc.toString({ lineWidth: YAML_LINE_WIDTH }))
}

interface Props { content: string; onChange: (content: string) => void; onApply?: (content: string) => Promise<void>; children?: ReactNode }
export function DnsPanel({ content, onChange, onApply, children }: Props) {
  const { showToast } = useAppContext()
  const [dnsStatus, setDnsStatus] = useState<{ portListener: string; dnsmasq: boolean; dnsMihomo: boolean } | null>(null)
  const [statusError, setStatusError] = useState('')
  const [fakeIpWarningDismissed, setFakeIpWarningDismissed] = useState(() => localStorage.getItem(FAKE_IP_WARNING_STORAGE_KEY) === 'true')
  const [config, setConfig] = useState<DnsConfig>(DEFAULT_DNS_CONFIG)
  const [isApplying, setIsApplying] = useState(false)
  const [enabled, setEnabled] = useState(false)
  const showFakeIpWarning = config.enhancedMode === 'fake-ip' && config.fakeIpFilterMode === 'blacklist' && !fakeIpWarningDismissed
  useEffect(() => {
    let live = true
    const update = async () => {
      try { const value = await apiCall<typeof dnsStatus>('GET', 'dns'); if (live) { setDnsStatus(value); setStatusError('') } }
      catch { if (live) setStatusError('Статус DNS недоступен; последние данные могут быть устаревшими') }
    }
    void update(); const timer = setInterval(update, 5000)
    return () => { live = false; clearInterval(timer) }
  }, [])
  useEffect(() => {

    let parsed: Record<string, unknown>
    try {
      parsed = jsyaml.load(content) as Record<string, unknown>
    } catch {
      return
    }

    const dns = parsed?.dns as Record<string, unknown> | undefined
    setEnabled(dns?.enable === true)
    if (!dns) { setConfig(DEFAULT_DNS_CONFIG); return }

    const toStr = (v: unknown): string => (typeof v === 'string' ? v : '')
    const toLines = (v: unknown): string => {
      if (Array.isArray(v)) return v.join('\n')
      if (typeof v === 'string') return v
      return ''
    }

    const enhancedMode = toStr(dns['enhanced-mode']) || 'redir-host'
    const fakeIpFilterMode = toStr(dns['fake-ip-filter-mode']) || 'blacklist'
    const fakeIpFilter = toLines(dns['fake-ip-filter'])
    const bootstrap = toLines(dns['default-nameserver'])
    const nameserver = toLines(dns['nameserver'])
    const proxyServerNameserver = toLines(dns['proxy-server-nameserver'])
    const fallback = toLines(dns['fallback'])

    let nameserverPolicy = ''
    const policy = dns['nameserver-policy'] as Record<string, unknown> | undefined
    if (policy) {
      const entries: string[] = []
      for (const [key, val] of Object.entries(policy)) {
        if (Array.isArray(val)) {
          if (val.length === 1) entries.push(`${key}: ${val[0]}`)
          else if (val.length > 1) entries.push(`${key}: [${val.join(', ')}]`)
        } else if (typeof val === 'string') {
          entries.push(`${key}: ${val}`)
        }
      }
      nameserverPolicy = entries.join('\n')
    }

    setConfig({
      enhancedMode,
      fakeIpFilterMode,
      fakeIpFilter,
      bootstrap,
      nameserver,
      proxyServerNameserver,
      nameserverPolicy,
      fallback,
    })
  }, [content])

  const handleApply = async () => {
    setIsApplying(true)
    try {
      const next = setDnsEnabled(patchDnsConfig(content, config), enabled)
      onChange(next)
      if (onApply) { await onApply(next); showToast('Настройки DNS сохранены в применённом профиле. Слушатель DNS включается отдельно в сетевом режиме.') }
      else showToast('DNS внесён в черновик')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Ошибка применения DNS', 'error') }
    finally { setIsApplying(false) }
  }
  const updateConfig = useCallback((patch: Partial<DnsConfig>) => {
    setConfig((prev) => ({ ...prev, ...patch }))
  }, [])

  const dismissFakeIpWarning = useCallback(() => {
    setFakeIpWarningDismissed(true)
    localStorage.setItem(FAKE_IP_WARNING_STORAGE_KEY, 'true')
  }, [])

  return (
    <TooltipProvider delayDuration={300}>
      <div className="absolute inset-4 flex scrollbar-thin flex-col gap-4 overflow-y-auto">
        <fieldset className="border-border rounded-lg border px-4 pt-1.5 pb-4">
          <legend className="px-1 text-sm font-medium">Статус DNS</legend>
          <div className="flex flex-col gap-3 pt-1">
            {statusError && <p className="text-xs text-amber-500">{statusError}</p>}
            <div className="flex items-center justify-between"><Label>DNS OpenWrt · dnsmasq</Label><Badge variant={dnsStatus?.dnsmasq ? 'emerald' : 'outline'}>{dnsStatus ? dnsStatus.dnsmasq ? 'Активно' : 'Не обнаружен на :53' : 'Неизвестно'}</Badge></div>
            <div className="flex items-center justify-between"><Label>DNS Mihomo · :1053</Label><Badge variant={dnsStatus?.dnsMihomo ? 'emerald' : 'outline'}>{dnsStatus ? dnsStatus.dnsMihomo ? 'Активно' : 'Неактивно' : 'Неизвестно'}</Badge></div>
            <div className="flex items-center justify-between"><Label>Слушатель 53 порта</Label><Badge variant="outline">{dnsStatus ? formatPortListener(dnsStatus.portListener) : 'Неизвестно'}</Badge></div>
            <Separator />
            <p className="text-muted-foreground text-xs">DNS сети обслуживает OpenWrt. В ручном режиме DNS Mihomo отключён. Слушатель и перехват DNS выбранного клиента включаются только через отдельный сетевой режим с проверкой и откатом.</p>
            {children}
          </div>
        </fieldset>
          <fieldset className="border-border rounded-lg border px-4 pt-1.5 pb-4">
            <legend className="px-1 text-sm font-medium">Mihomo DNS</legend>
            <div className="flex items-center justify-between py-2"><Label htmlFor="dns-profile-enable">Включить DNS в профиле</Label><Switch id="dns-profile-enable" checked={enabled} onCheckedChange={setEnabled} /></div>
            <div className="flex flex-col gap-4 pt-1">
              {showFakeIpWarning && (
                <Alert className="border-amber-500/20 bg-amber-100 p-2.75 text-yellow-600 dark:bg-[#2a1f0d] dark:text-amber-400">
                  <IconAlertCircle className="size-4.5" />
                  <AlertDescription className="text-xs leading-4.25 tracking-wide text-yellow-600 dark:text-amber-400">
                    Потенциально проблемная конфигурация DNS. Для режима <strong>fake-ip</strong> рекомендуется использовать режим фильтра{' '}
                    <strong>whitelist</strong> либо <strong>rule</strong>, в противном случае возникнут проблемы с трафиком, проходящим мимо
                    ядра Mihomo.{' '}
                    <a
                      href="https://wiki.metacubex.one/ru/config/dns/#fake-ip-filter-mode"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="underline underline-offset-2"
                    >
                      Подробнее...
                    </a>
                  </AlertDescription>
                  <AlertAction>
                    <button
                      type="button"
                      onClick={dismissFakeIpWarning}
                      aria-label="Скрыть предупреждение"
                      className="rounded-md p-1 opacity-70 hover:opacity-100"
                    >
                      <IconX size={18} />
                    </button>
                  </AlertAction>
                </Alert>
              )}
              <div className="grid gap-2">
                <DnsSettingLabel tooltip="Redir-host - реальные IP в ответах. Медленнее, лучше совместимость, рекомендуется \nFake-ip - поддельные IP в ответах. Быстрее, нужен перехват DNS и трафика одного и того же клиента, для продвинутых пользователей">
                  Enhanced Mode
                </DnsSettingLabel>
                <Select
                  value={config.enhancedMode}
                  items={{ 'redir-host': 'redir-host', 'fake-ip': 'fake-ip' }}
                  onValueChange={(v) => updateConfig({ enhancedMode: v })}
                >
                  <SelectTrigger popper className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent position="popper">
                    <SelectGroup>
                      <SelectItem value="redir-host">redir-host</SelectItem>
                      <SelectItem value="fake-ip">fake-ip</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>

              {config.enhancedMode === 'fake-ip' && (
                <>
                  <div className="grid gap-2">
                    <DnsSettingLabel
                      tooltip="Режим фильтрации Fake IP.
                      Whitelist - использовать fake-ip только для перечисленных доменов.
                      Blacklist - Использовать fake-ip для всего, кроме перечисленных доменов.
                      Rule - classical правила domain-suffix, domain-keyword и пр.
                      Для Whitelist и Blacklist поддерживается rule-set: и +. синтаксис"
                    >
                      Fake IP Filter Mode
                    </DnsSettingLabel>
                    <Select
                      value={config.fakeIpFilterMode}
                      items={{ blacklist: 'blacklist', whitelist: 'whitelist', rule: 'rule' }}
                      onValueChange={(v) => updateConfig({ fakeIpFilterMode: v })}
                    >
                      <SelectTrigger popper className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent position="popper">
                        <SelectGroup>
                          <SelectItem value="blacklist">blacklist</SelectItem>
                          <SelectItem value="whitelist">whitelist</SelectItem>
                          <SelectItem value="rule">rule</SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="grid gap-2">
                    <DnsSettingLabel tooltip="Список доменов для фильтрации fake-ip. По одному на строку.">Fake IP Filter</DnsSettingLabel>
                    <Textarea
                      value={config.fakeIpFilter}
                      onChange={(e) => updateConfig({ fakeIpFilter: e.target.value })}
                      placeholder={'+.local'}
                      className="min-h-15 text-sm! tracking-wide"
                    />
                  </div>
                </>
              )}

              <div className="grid gap-2">
                <DnsSettingLabel tooltip="Основные DNS-резолверы. Поддерживаются: udp:// tcp:// https:// tls:// quic://. По одному на строку.\nДля того чтобы направить запросы через определенное подключение, укажите #PROXY в конец ссылки, где 'PROXY' - название прокси/селектора. Примеры: \n tls://1.1.1.1#vless-reality\n Или:\n tls://1.1.1.1#Заблок. сервисы">
                  Nameserver
                </DnsSettingLabel>
                <Textarea
                  value={config.nameserver}
                  onChange={(e) => updateConfig({ nameserver: e.target.value })}
                  placeholder={'https://1.1.1.1/dns-query\nhttps://8.8.8.8/dns-query'}
                  className="min-h-15 text-sm! tracking-wide"
                />
              </div>

              <div className="grid gap-2">
                <DnsSettingLabel tooltip="Позволяет указать какие резолверы использовать для каких доменов. Поддерживается rule-set: и +. синтаксис. Примеры: \nexample.com: tls://1.1.1.1\n+.ru: 77.88.8.8\nrule-set:example: [1.1.1.1, 8.8.8.8]">
                  Nameserver Policy
                </DnsSettingLabel>
                <Textarea
                  value={config.nameserverPolicy}
                  onChange={(e) => updateConfig({ nameserverPolicy: e.target.value })}
                  placeholder={'rule-set:category-ru@domain: [77.88.8.8, 195.208.5.1]'}
                  className="min-h-15 text-sm! tracking-wide"
                />
              </div>

              <div className="grid gap-2">
                <DnsSettingLabel tooltip="При проксировании всех DNS из поля Nameserver, если адрес выбранного подключения является доменным именем, его нужно разрешить через отдельные резолверы. Здесь можно указать через какие.">
                  Proxy Server Nameserver
                </DnsSettingLabel>
                <Textarea
                  value={config.proxyServerNameserver}
                  onChange={(e) => updateConfig({ proxyServerNameserver: e.target.value })}
                  placeholder={'https://1.1.1.1/dns-query\nhttps://8.8.8.8/dns-query'}
                  className="min-h-15 text-sm! tracking-wide"
                />
              </div>

              <div className="grid gap-2">
                <DnsSettingLabel tooltip="Резервные DNS-резолверы. Используются, если разрешение через основные - безуспешно.">
                  Fallback
                </DnsSettingLabel>
                <Textarea
                  value={config.fallback}
                  onChange={(e) => updateConfig({ fallback: e.target.value })}
                  placeholder={'tls://1.1.1.1\ntls://8.8.8.8'}
                  className="min-h-15 text-sm! tracking-wide"
                />
              </div>

              <div className="grid gap-2">
                <DnsSettingLabel tooltip="DNS-резолверы для разрешения других резолверов, у которых в качестве адреса используется доменное имя. Допустимы только IP-адреса.">
                  Bootstrap DNS
                </DnsSettingLabel>
                <Textarea
                  value={config.bootstrap}
                  onChange={(e) => updateConfig({ bootstrap: e.target.value })}
                  placeholder={'77.88.8.8\n77.8.8.1'}
                  className="min-h-15 text-sm! tracking-wide"
                />
              </div>

              <Button className="w-full" onClick={handleApply} disabled={isApplying}>
                {isApplying ? <Spinner /> : <IconDeviceFloppy data-icon="inline-start" />}
                Применить
              </Button>
            </div>
          </fieldset>
      </div>
    </TooltipProvider>
  )
}
