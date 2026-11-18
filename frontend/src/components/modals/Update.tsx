import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { CodeBlock, CodeBlockContent } from '@/components/ui/code-block'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Progress } from '@/components/ui/progress'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Spinner } from '@/components/ui/spinner'
import { IconCancel, IconDownload, IconLogs, IconPlaylistX, IconRefresh } from '@tabler/icons-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { apiCall } from '../../lib/api'
import { useAppContext, useModalContext } from '../../lib/store'
import type { Release } from '../../lib/types'
import type { UpdateEvent, WsMessage } from '../../lib/websocket'
import { useUpdateWebSocket } from '../../lib/websocket'
import { cn } from '../../lib/utils'
import { nextPhase, rememberPendingUpdate, selfReleases, type SelfCatalog, type SelfPhase, type SelfStatus } from '../../lib/self-update'

const LEVEL_CLASSES: Record<string, string> = {
  info: 'text-foreground/80',
  warn: 'text-amber-400',
  error: 'text-red-400',
}

const mdClass = `
  text-xs text-muted-foreground leading-relaxed
  [&_h1]:text-sm [&_h1]:font-semibold [&_h1]:text-foreground [&_h1]:mb-2 [&_h1]:mt-3 [&_h1:first-child]:mt-0
  [&_h2]:text-sm [&_h2]:font-semibold [&_h2]:text-foreground [&_h2]:mb-1.5 [&_h2]:mt-3 [&_h2:first-child]:mt-0
  [&_h3]:text-xs [&_h3]:font-semibold [&_h3]:text-foreground [&_h3]:mb-1 [&_h3]:mt-2 [&_h3:first-child]:mt-0
  [&_p]:mb-2 [&_p:last-child]:mb-0 [&_p]:break-words
  [&_ul]:mb-2 [&_ul]:list-disc [&_ul]:pl-4 [&_ul:last-child]:mb-0 [&_li]:mb-0.5 [&_li]:break-words
  [&_ol]:mb-2 [&_ol]:list-decimal [&_ol]:pl-4 [&_ol:last-child]:mb-0
  [&_code]:bg-muted [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-[10px] [&_code]:font-mono [&_code]:wrap-anywhere
  [&_pre]:bg-muted [&_pre]:p-2 [&_pre]:rounded [&_pre]:mb-2 [&_pre]:overflow-x-auto [&_pre]:whitespace-pre-wrap [&_pre]:max-w-full
  [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_pre_code]:break-normal
  [&_a]:text-blue-400 [&_a]:underline [&_a]:underline-offset-2 [&_a]:wrap-anywhere
  [&_strong]:text-foreground [&_strong]:font-semibold
  [&_hr]:border-ring/20 [&_hr]:my-2
  [&_blockquote]:border-l-2 [&_blockquote]:border-ring/40 [&_blockquote]:pl-3 [&_blockquote]:italic
`.trim()

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 Б'
  const units = ['Б', 'КБ', 'МБ', 'ГБ']
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)))
  return `${(bytes / 1024 ** i).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

interface ProcessProps {
  open: boolean
  core: string
  coreLabel: string
  version: string
  onInstalled: () => void
  onStartFailed: () => void
  onClose: () => void
}

interface LogLine {
  ts: string
  level: string
  message: string
}

/** Записи журнала: обычные строки лога и «живые» строки прогресса (по одной на файл). */
type Entry = { kind: 'log'; id: number; line: LogLine } | { kind: 'progress'; id: number; downloaded: number; total: number; speed: number }

function UpdateProcessModal({ open, core, coreLabel, version, onInstalled, onStartFailed, onClose }: ProcessProps) {
  const { dispatch, showToast } = useAppContext()
  /** Записи журнала: обычные строки лога и «живые» строки прогресса (по одной на файл). */
  const [entries, setEntries] = useState<Entry[]>([])
  const [stage, setStage] = useState('')
  const [running, setRunning] = useState(true)
  const [started, setStarted] = useState(false)
  const [result, setResult] = useState<{ success: boolean; error: string | null } | null>(null)

  const logRef = useRef<HTMLPreElement>(null)
  const doneHandledRef = useRef(false)
  const startedRef = useRef(false)
  const lastSeqRef = useRef(0)
  const nextEntryIdRef = useRef(1)
  const activeProgressIdRef = useRef<number | null>(null)
  const propsRef = useRef({ core, coreLabel, version, onInstalled, showToast })
  useEffect(() => {
    propsRef.current = { core, coreLabel, version, onInstalled, showToast }
  })

  const restoreStatus = useCallback(() => {
    apiCall<any>('GET', 'control')
      .then((data) => {
        if (data.success) {
          dispatch({ type: 'SET_SERVICE_STATUS', status: data.running === true ? 'running' : data.running === false ? 'stopped' : 'unknown' })
        }
      })
      .catch(() => dispatch({ type: 'SET_SERVICE_STATUS', status: 'unknown' }))
  }, [dispatch])

  const applyEvent = useCallback(
    (ev: UpdateEvent) => {
      // Дедупликация: событие может прийти и из истории, и из broadcast-потока.
      if (typeof ev.seq === 'number') {
        if (ev.seq <= lastSeqRef.current) return
        lastSeqRef.current = ev.seq
      }
      switch (ev.type) {
        case 'log': {
          const line = { ts: ev.ts ?? '', level: ev.level ?? 'info', message: ev.message ?? '' }
          // Любая строка лога — это граница попытки: активная строка прогресса замораживается.
          // Новая закачка получит свою строку прогресса по первому реально пришедшему чанку.
          activeProgressIdRef.current = null
          setEntries((prev) => [...prev.slice(-199), { kind: 'log' as const, id: nextEntryIdRef.current++, line }])
          break
        }
        case 'stage':
          setStage(ev.stage ?? '')
          if (ev.stage !== 'download') activeProgressIdRef.current = null
          break
        case 'progress': {
          const values = { downloaded: ev.downloaded ?? 0, total: ev.total ?? 0, speed: ev.speed ?? 0 }
          activeProgressIdRef.current ??= nextEntryIdRef.current++
          const progressId = activeProgressIdRef.current
          setEntries((prev) =>
            prev.some((e) => e.kind === 'progress' && e.id === progressId)
              ? prev.map((e) => (e.kind === 'progress' && e.id === progressId ? { ...e, ...values } : e))
              : [...prev.slice(-199), { kind: 'progress' as const, id: progressId, ...values }]
          )
          break
        }
        case 'done': {
          if (doneHandledRef.current) break
          doneHandledRef.current = true
          activeProgressIdRef.current = null
          setRunning(false)
          setResult({ success: !!ev.success, error: ev.error ?? null })
          const { core, coreLabel, version, onInstalled, showToast } = propsRef.current
          if (ev.success) {
            if (core === 'self') {
              showToast(`Установлен XKeen UI ${version} — перезапуск интерфейса`)
              setTimeout(() => window.location.reload(), 1000)
            } else {
              showToast(`Установлен ${coreLabel} ${version}`)
              onInstalled()
              restoreStatus()
            }
          } else {
            showToast(ev.error || 'Обновление отменено', ev.error?.includes('Отменено') ? 'warning' : 'error')
            restoreStatus()
          }
          break
        }
      }
    },
    [restoreStatus]
  )

  const handleWsMessage = useCallback(
    (data: WsMessage) => {
      if (data.type !== 'update') return
      if (data.history) {
        const newestSeq = data.history.at(-1)?.seq ?? 0
        if (newestSeq < lastSeqRef.current) {
          lastSeqRef.current = 0
          activeProgressIdRef.current = null
        }
        data.history.forEach(applyEvent)
      } else if (data.event) {
        applyEvent(data.event)
      }
    },
    [applyEvent]
  )

  useUpdateWebSocket(handleWsMessage, started)

  // Запуск обновления — один раз при монтировании окна процесса.
  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true
    const { version, showToast } = propsRef.current
    apiCall<{ success: boolean; error?: string }>('POST', 'core/update', { version })
      .then((data) => {
        if (data.success) {
          setStarted(true)
          return
        }
        showToast(data.error || 'Не удалось запустить обновление', 'error')
        restoreStatus()
        onStartFailed()
      })
      .catch(() => {
        showToast('Не удалось запустить обновление', 'error')
        restoreStatus()
        onStartFailed()
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Автоскролл журнала процесса.
  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [entries])

  // Страховка для self-обновления: если событие done потерялось при перезапуске бэкенда — перезагружаемся.
  useEffect(() => {
    if (core !== 'self' || !running || stage !== 'restart') return
    const timer = setTimeout(() => window.location.reload(), 20000)
    return () => clearTimeout(timer)
  }, [core, running, stage])

  const control = () => {
    apiCall('POST', 'core/update/cancel', {}).catch(() => {})
  }

  const handleClose = () => {
    if (running) return
    if (core === 'self' && result?.success) {
      window.location.reload()
      return
    }
    onClose()
  }

  // Строка прогресса живёт как строка лога и остаётся видимой после завершения загрузки.
  // Позиция строки прогресса — просто очередная запись журнала.
  const renderLogLine = ({ id, line }: Extract<Entry, { kind: 'log' }>) => (
    <div key={`l${id}`} className="flex gap-2 wrap-anywhere">
      {line.ts && <span className="text-muted-foreground/50 shrink-0">{line.ts}</span>}
      <span className={line.message.startsWith('✓') ? 'font-medium text-green-400' : (LEVEL_CLASSES[line.level] ?? LEVEL_CLASSES.info)}>
        {line.message}
      </span>
    </div>
  )

  const renderProgressLine = (e: Extract<Entry, { kind: 'progress' }>) => {
    const pct = e.total > 0 ? Math.min(100, (e.downloaded / e.total) * 100) : null
    return (
      <div key={`p${e.id}`} className="flex items-center gap-2 wrap-anywhere">
        <Progress value={pct} className="min-w-16 flex-1 [&_[data-slot=progress-track]]:h-1.5" />
        <span className="text-muted-foreground shrink-0 font-mono">
          {pct !== null && `${Math.round(pct)}% · `}
          {formatBytes(e.downloaded)}
          {running && e.id === activeProgressIdRef.current && e.speed > 0 && ` · ${formatBytes(e.speed)}/с`}
        </span>
      </div>
    )
  }
  const selfRestarting = core === 'self' && result?.success
  // Управление доступно, пока идёт загрузка; после неё процесс доводится до конца.
  const canControl = running && (stage === '' || stage === 'prepare' || stage === 'download')

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent showCloseButton={!running} className="w-full max-w-[95vw]! p-0! md:w-150">
        <div className="flex flex-col gap-4 p-6">
          <DialogHeader className="shrink-0">
            <DialogTitle className="flex items-center gap-2 pr-8">
              <IconDownload size={24} className="text-chart-2" />
              Обновление {coreLabel}
            </DialogTitle>
          </DialogHeader>

          <CodeBlock size="sm" className="bg-muted/30 ring-ring/10 border-none ring-1">
            <CodeBlockContent
              ref={logRef}
              wrap
              className="h-72 [&>code:has([data-slot=empty])]:h-full [&>code:has([data-slot=empty])]:content-center"
            >
              {entries.length === 0 ? (
                <Empty className="p-2 font-sans">
                  <EmptyMedia variant="icon">
                    <IconLogs />
                  </EmptyMedia>
                  <EmptyTitle>Журнал пуст</EmptyTitle>
                  <EmptyDescription>Ожидание событий обновления...</EmptyDescription>
                </Empty>
              ) : (
                entries.map((e) => (e.kind === 'log' ? renderLogLine(e) : renderProgressLine(e)))
              )}
            </CodeBlockContent>
          </CodeBlock>

          <DialogFooter className="shrink-0">
            {running ? (
              <div className="flex w-full gap-2">
                <Button variant="destructive" onClick={control} disabled={!canControl} className="w-full gap-1.5">
                  <IconCancel size={16} />
                  Отмена
                </Button>
              </div>
            ) : (
              <Button onClick={handleClose} className="w-full gap-1.5">
                {selfRestarting ? (
                  <>
                    <IconRefresh size={16} />
                    Перезагрузить
                  </>
                ) : (
                  'Закрыть'
                )}
              </Button>
            )}
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  )
}

interface SelfProcessProps {
  open: boolean
  version: string
  onStartFailed: () => void
  onClose: () => void
}

const SELF_UPDATE_DEADLINE_MS = 15 * 60_000

/**
 * Panel self-update (decision 026). The router runs the release's own installer
 * in a separate service; the APK upgrade restarts this panel, so the window
 * polls the status and treats a silent panel as the restart, not as a failure.
 */
function SelfUpdateProcessModal({ open, version, onStartFailed, onClose }: SelfProcessProps) {
  const { dispatch, showToast } = useAppContext()
  const [log, setLog] = useState<string[]>([])
  const [phase, setPhase] = useState<SelfPhase | { kind: 'starting' } | { kind: 'relogin' }>({ kind: 'starting' })
  const logRef = useRef<HTMLPreElement>(null)
  const startedRef = useRef(false)
  const aliveRef = useRef(true)
  const propsRef = useRef({ version, showToast, onStartFailed })
  useEffect(() => {
    propsRef.current = { version, showToast, onStartFailed }
  })
  useEffect(() => {
    aliveRef.current = true
    return () => {
      aliveRef.current = false
    }
  }, [])

  const restoreStatus = useCallback(() => {
    apiCall<any>('GET', 'control')
      .then((data) => {
        if (data.success) {
          dispatch({ type: 'SET_SERVICE_STATUS', status: data.running === true ? 'running' : data.running === false ? 'stopped' : 'unknown' })
        }
      })
      .catch(() => dispatch({ type: 'SET_SERVICE_STATUS', status: 'unknown' }))
  }, [dispatch])

  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true
    const { version, showToast, onStartFailed } = propsRef.current
    const deadline = Date.now() + SELF_UPDATE_DEADLINE_MS
    const poll = async () => {
      if (!aliveRef.current) return
      let reply: SelfStatus | null = null
      try {
        const response = await fetch('/api/self/update/status', { signal: AbortSignal.timeout(5000) })
        if (response.status === 401) {
          // The new panel is up but has forgotten this login: read the result after sign-in.
          rememberPendingUpdate(version)
          setPhase({ kind: 'relogin' })
          window.setTimeout(() => window.location.reload(), 2500)
          return
        }
        if (response.ok) reply = (await response.json()) as SelfStatus
      } catch {
        reply = null
      }
      if (!aliveRef.current) return
      if (reply?.log?.length) setLog(reply.log)
      const next = nextPhase(version, reply)
      if (next.kind === 'done') {
        setPhase(next)
        showToast(`XkeenWRT ${version} установлен. Запустите шлюз кнопкой «Запустить».`)
        window.setTimeout(() => window.location.reload(), 2000)
        return
      }
      if (next.kind === 'failed') {
        setPhase(next)
        showToast(next.message, 'error')
        restoreStatus()
        return
      }
      if (Date.now() > deadline) {
        setPhase({ kind: 'failed', message: 'Панель не ответила за 15 минут. Проверьте роутер по SSH.' })
        restoreStatus()
        return
      }
      setPhase(next)
      window.setTimeout(poll, 1500)
    }
    apiCall<{ success: boolean }>('POST', 'self/update', { version })
      .then(() => {
        setPhase({ kind: 'running' })
        window.setTimeout(poll, 1000)
      })
      .catch((error) => {
        showToast(error instanceof Error ? error.message : 'Не удалось запустить обновление', 'error')
        restoreStatus()
        onStartFailed()
      })
  }, [restoreStatus])

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [log])

  const finished = phase.kind === 'failed' || phase.kind === 'done'
  const status =
    phase.kind === 'starting'
      ? 'Проверка релиза и запуск установщика…'
      : phase.kind === 'running'
        ? 'Установщик работает на роутере…'
        : phase.kind === 'restarting'
          ? 'Панель перезапускается на новой версии…'
          : phase.kind === 'relogin'
            ? 'Панель перезапущена. Войдите снова — результат покажется после входа.'
            : phase.kind === 'done'
              ? `✓ XkeenWRT ${version} установлен`
              : phase.message

  return (
    <Dialog open={open} onOpenChange={(o) => !o && finished && phase.kind !== 'done' && onClose()}>
      <DialogContent showCloseButton={phase.kind === 'failed'} className="w-full max-w-[95vw]! p-0! md:w-150">
        <div className="flex flex-col gap-4 p-6">
          <DialogHeader className="shrink-0">
            <DialogTitle className="flex items-center gap-2 pr-8">
              <IconDownload size={24} className="text-chart-2" />
              Обновление XkeenWRT до {version}
            </DialogTitle>
            <DialogDescription>Шлюз остаётся остановленным; после обновления нажмите «Запустить».</DialogDescription>
          </DialogHeader>

          <div className={cn('flex items-center gap-2 text-sm', phase.kind === 'failed' ? 'text-red-400' : phase.kind === 'done' ? 'text-green-400' : '')}>
            {!finished && <Spinner className="text-chart-2 size-4" />}
            <span className="wrap-anywhere">{status}</span>
          </div>

          <CodeBlock size="sm" className="bg-muted/30 ring-ring/10 border-none ring-1">
            <CodeBlockContent
              ref={logRef}
              wrap
              className="h-72 [&>code:has([data-slot=empty])]:h-full [&>code:has([data-slot=empty])]:content-center"
            >
              {log.length === 0 ? (
                <Empty className="p-2 font-sans">
                  <EmptyMedia variant="icon">
                    <IconLogs />
                  </EmptyMedia>
                  <EmptyTitle>Журнал пуст</EmptyTitle>
                  <EmptyDescription>Ожидание вывода установщика...</EmptyDescription>
                </Empty>
              ) : (
                log.map((line, i) => (
                  <div key={i} className={cn('wrap-anywhere', line.startsWith('XkeenWRT:') ? LEVEL_CLASSES.error : LEVEL_CLASSES.info)}>
                    {line}
                  </div>
                ))
              )}
            </CodeBlockContent>
          </CodeBlock>

          <DialogFooter className="shrink-0">
            {phase.kind === 'failed' ? (
              <Button onClick={onClose} className="w-full">
                Закрыть
              </Button>
            ) : phase.kind === 'done' ? (
              <Button onClick={() => window.location.reload()} className="w-full gap-1.5">
                <IconRefresh size={16} />
                Перезагрузить
              </Button>
            ) : (
              <Button disabled className="w-full">
                Обновление идёт — не закрывайте страницу
              </Button>
            )}
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export function UpdateModal({ onInstalled }: { onInstalled: () => void }) {
  const { state, dispatch, showToast } = useAppContext()
  const { modals } = useModalContext()
  const { updateModalCore } = modals
  const isSelf = updateModalCore === 'self'
  const gatewayRunning = isSelf && state.serviceStatus === 'running'
  const [selfCurrent, setSelfCurrent] = useState('')
  const [releases, setReleases] = useState<Release[]>([])
  const [selectedVersion, setSelectedVersion] = useState('')
  const [openVersion, setOpenVersion] = useState('')
  const [source, setSource] = useState<'github' | 'jsdelivr' | ''>('')
  const [loading, setLoading] = useState(true)
  const [step, setStep] = useState<'select' | 'process'>('select')
  const [pending, setPending] = useState<{ version: string } | null>(null)

  const coreLabel = isSelf ? 'XkeenWRT' : 'Mihomo'
  const repo = isSelf ? 'First026/XkeenWRT-Mihomo · установщик релиза' : 'MetaCubeX/mihomo · AArch64 · каталог с закреплёнными SHA-256'
  const close = () => dispatch({ type: 'SHOW_MODAL', modal: 'showUpdateModal', show: false })

  useEffect(() => {
    if (!modals.showUpdateModal) {
      setStep('select')
      setPending(null)
      return
    }
    fetchReleases()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modals.showUpdateModal, updateModalCore])

  async function fetchReleases() {
    setLoading(true)
    setSelectedVersion('')
    setOpenVersion('')
    setReleases([])
    setSource('')
    try {
      if (updateModalCore === 'self') {
        const catalog = await apiCall<SelfCatalog>('GET', 'self/catalog')
        const parsed = selfReleases(catalog)
        setSelfCurrent(catalog.current)
        setReleases(parsed)
        if (parsed.length) {
          setSelectedVersion(parsed.at(-1)!.version)
          setOpenVersion(parsed.at(-1)!.version)
        }
        setSource('github')
        setLoading(false)
        return
      }
      if (updateModalCore !== 'mihomo') throw new Error('Unsupported core')
      const catalog = await apiCall<{ releases: Array<{ version: string; published: string; assetSize: number; elfSha256: string }> }>('GET', 'core/catalog')
      const parsed = catalog.releases.map((release) => ({
        version: release.version,
        name: `Mihomo ${release.version}`,
        published_at: release.published,
        is_prerelease: false,
        body: `Проверяемый архив: ${formatBytes(release.assetSize)}\nSHA-256 распакованного ELF: ${release.elfSha256}`,
        assets: [],
      }))
      if (!parsed.length) throw new Error('NO_RELEASES')
      setReleases(parsed)
      setSelectedVersion(parsed.at(-1)!.version)
      setOpenVersion(parsed.at(-1)!.version)
      setSource('github')
      setLoading(false)
      return
    } catch (error) {
      showToast(isSelf && error instanceof Error ? error.message : 'Не удалось получить список релизов', 'error')
    }
    setLoading(false)
  }

  function startInstall() {
    if (!selectedVersion) return
    if (updateModalCore !== 'self') dispatch({ type: 'REMOVE_TOAST', id: 'update-core' })
    dispatch({ type: 'SET_SERVICE_STATUS', status: 'pending', pendingText: 'Обновление...' })
    setPending({ version: selectedVersion })
    setStep('process')
  }

  return (
    <>
      <Dialog open={modals.showUpdateModal && step === 'select' && !pending} onOpenChange={(open) => !open && close()}>
        <DialogContent className="w-full max-w-[95vw]! p-0! md:w-187.5">
          <div className="flex max-h-[90dvh] flex-col gap-4 overflow-hidden p-6">
            <DialogHeader className="shrink-0">
              <DialogTitle className="flex items-center gap-2 pr-8 pb-3">
                <IconDownload size={24} className="text-chart-2" />
                Обновление {coreLabel}
              </DialogTitle>

              <DialogDescription
                className="flex w-full items-center justify-between"
                render={
                  <div>
                    Выберите версию
                    <span className="flex items-center gap-1.5">
                      {repo && (
                        <Badge variant="outline" className="border-ring/40 bg-muted/50 h-5 rounded-full px-2 text-xs font-medium">
                          {repo}
                        </Badge>
                      )}
                      {!loading && source && (
                        <Badge
                          variant="outline"
                          className={cn(
                            'h-5 rounded-full border-none px-2 text-xs font-medium',
                            source === 'github' ? 'bg-green-500/10 text-green-400' : 'bg-orange-500/10 text-orange-400'
                          )}
                        >
                          {source === 'github' ? 'GitHub' : 'jsDelivr'}
                        </Badge>
                      )}
                    </span>
                  </div>
                }
              />
            </DialogHeader>

            <ScrollArea className="h-125 min-h-0" hideScrollbar>
              {loading ? (
                <div className="text-muted-foreground flex min-h-125 flex-col items-center justify-center gap-3">
                  <Spinner className="text-chart-2 size-10" />
                  <span className="text-sm tracking-normal">Загрузка релизов...</span>
                </div>
              ) : releases.length === 0 ? (
                <Empty className="min-h-125 border-none">
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <IconPlaylistX className="size-8" />
                    </EmptyMedia>
                    <EmptyTitle className="text-[16px] tracking-normal">
                      {isSelf && selfCurrent ? 'Установлена последняя версия' : 'Нет доступных релизов'}
                    </EmptyTitle>
                    {isSelf && selfCurrent && <EmptyDescription>XkeenWRT {selfCurrent}</EmptyDescription>}
                  </EmptyHeader>
                  <EmptyContent>
                    <Button variant="outline" size="sm" onClick={fetchReleases} className="bg-card! hover:bg-input! gap-1.5">
                      <IconRefresh size={14} />
                      Повторить
                    </Button>
                  </EmptyContent>
                </Empty>
              ) : source === 'github' ? (
                <Accordion
                  type="single"
                  collapsible
                  value={openVersion}
                  onValueChange={setOpenVersion}
                  className="flex flex-col gap-1.5 px-0.5 py-1"
                >
                  {releases.map((release) => {
                    const checked = selectedVersion === release.version
                    return (
                      <AccordionItem
                        key={release.version}
                        value={release.version}
                        className={cn(
                          'rounded-lg border transition-all',
                          checked
                            ? 'border-[#60a5fa] bg-linear-to-b from-blue-500/25 to-blue-500/15'
                            : 'border-ring/40 bg-[linear-gradient(135deg,rgba(59,130,246,0.05)_0%,transparent_50%)] hover:border-[#60a5fa] hover:bg-linear-to-b hover:from-blue-500/15 hover:to-blue-500/5'
                        )}
                      >
                        <AccordionTrigger
                          className="min-w-0 overflow-hidden px-3 py-0 hover:no-underline *:data-[slot=accordion-trigger-icon]:hidden"
                          onClick={() => setSelectedVersion(release.version)}
                        >
                          <div className="flex w-full min-w-0 items-center justify-between gap-3 py-2.5">
                            <div className="flex min-w-0 flex-1 flex-col gap-2">
                              <div className="flex items-center gap-2">
                                <span className="truncate text-sm font-medium">{release.name || release.version}</span>
                                {release.is_prerelease && (
                                  <Badge variant="outline" className="rounded-sm border-none bg-amber-500/10 px-2 text-xs text-amber-400">
                                    Pre-Release
                                  </Badge>
                                )}
                              </div>
                              <span className="text-muted-foreground text-xs">{release.published_at}</span>
                            </div>
                            <div
                              className={cn(
                                'flex size-4 shrink-0 items-center justify-center rounded-full border-2 transition-colors',
                                checked ? 'border-primary bg-primary' : 'border-muted-foreground/50'
                              )}
                            >
                              {checked && <div className="bg-primary-foreground size-2 rounded-full" />}
                            </div>
                          </div>
                        </AccordionTrigger>
                        {release.body && (
                          <AccordionContent className="px-3 pt-0 pb-3">
                            <div className="border-ring/20 border-t pt-2.5">
                              <div className="max-h-48 w-full scrollbar-thin overflow-x-hidden overflow-y-auto">
                                <div className={cn(mdClass, 'min-w-0')}>
                                  <ReactMarkdown remarkPlugins={[remarkGfm]} components={{ img: () => null }}>
                                    {release.body}
                                  </ReactMarkdown>
                                </div>
                              </div>
                            </div>
                          </AccordionContent>
                        )}
                      </AccordionItem>
                    )
                  })}
                </Accordion>
              ) : (
                <RadioGroup value={selectedVersion} onValueChange={setSelectedVersion} className="gap-1.5 px-0.5 py-1">
                  {releases.map((release) => {
                    const checked = selectedVersion === release.version
                    return (
                      <label
                        key={release.version}
                        htmlFor={release.version}
                        className={cn(
                          'flex cursor-pointer items-start justify-between gap-3 rounded-lg border px-3 py-2.5 transition-all',
                          checked
                            ? 'border-[#60a5fa] bg-linear-to-b from-blue-500/25 to-blue-500/15'
                            : 'border-ring/40 bg-[linear-gradient(135deg,rgba(59,130,246,0.05)_0%,transparent_50%)] from-blue-500/15 to-blue-500/5 hover:border-[#60a5fa] hover:bg-linear-to-b'
                        )}
                      >
                        <span className="truncate text-sm font-medium">{release.name || release.version}</span>
                        <RadioGroupItem value={release.version} id={release.version} className="mt-0.5 shrink-0" />
                      </label>
                    )
                  })}
                </RadioGroup>
              )}
            </ScrollArea>

            <DialogFooter className="shrink-0">
              <div className="flex w-full flex-col gap-2">
                {gatewayRunning && (
                  <span className="text-center text-xs text-amber-400">Перед обновлением нажмите «Остановить»: установщик обновляет только остановленный шлюз.</span>
                )}
                <Button onClick={startInstall} disabled={!selectedVersion || gatewayRunning} className="w-full">
                  Установить
                </Button>
              </div>
            </DialogFooter>
          </div>
        </DialogContent>
      </Dialog>

      {pending && isSelf && (
        <SelfUpdateProcessModal
          open={step === 'process'}
          version={pending.version}
          onStartFailed={() => {
            setStep('select')
            window.setTimeout(() => setPending(null), 250)
          }}
          onClose={() => {
            setStep('select')
            window.setTimeout(() => {
              setPending(null)
              close()
            }, 250)
          }}
        />
      )}
      {pending && !isSelf && (
        <UpdateProcessModal
          open={step === 'process'}
          core={updateModalCore}
          coreLabel={coreLabel}
          version={pending.version}
          onInstalled={onInstalled}
          onStartFailed={() => {
            // Окно процесса закрывается с анимацией, затем возвращаемся к выбору версии.
            setStep('select')
            window.setTimeout(() => setPending(null), 250)
          }}
          onClose={() => {
            // open=false запускает exit-анимацию; размонтируем и закрываем модалку после неё.
            setStep('select')
            window.setTimeout(() => {
              setPending(null)
              close()
            }, 250)
          }}
        />
      )}
    </>
  )
}
