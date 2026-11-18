import { Button } from '@/components/ui/button'
import { ShineBorder } from '@/components/ui/shine-border'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import {
  IconBox,
  IconCpu,
  IconMemory,
  IconLogout,
  IconPlayerPlayFilled,
  IconPlayerStopFilled,
  IconSettings,
} from '@tabler/icons-react'
import { CoreLogo } from '../CoreLogo'
import { useEffect, useState } from 'react'
import { apiCall, capitalize } from '../../lib/api'
import { PROJECT_REPO } from '../../lib/types'
import { useAppContext } from '../../lib/store'
import { cn } from '../../lib/utils'
import { LanGatewayStatus } from './LanGatewayStatus'

type SystemStats = { memoryUsed: number; memoryTotal: number; cpuUsage: number }

function formatMemoryMB(bytes: number) {
  if (!bytes) return '—'
  return Math.round(bytes / 1024 / 1024).toString()
}

function usageColorClass(percent: number) {
  if (percent >= 90) return 'text-red-500'
  if (percent >= 70) return 'text-amber-500'
  return 'text-muted-foreground'
}

const REMOTE_START_HINT =
  'Через Tailscale: после включения роутер сам проверит DNS и выход в интернет; если проверка не пройдёт — сразу вернётся Direct'

export function StatusBar({
  onOpenCoreManage,
  onOpenSettings,
  onStart,
  onStop,
  onOpenUpdate,
  onLogout,
  startDisabledReason,
  appliedProfile,
  networkState,
  recoveryNotice,
  remoteCheck,
  remoteAdmin=false,
  stale=false,
}: {
  onOpenCoreManage: () => void
  onOpenSettings: () => void
  onStart: () => void
  onStop: () => void
  onOpenUpdate: (core: string) => void
  onLogout: () => void
  startDisabledReason?: string
  networkState?: string
  recoveryNotice?: 'SNAPSHOT_MISSING'
  remoteCheck?: import('../../lib/runtime-adapter').RemoteCheck
  remoteAdmin?:boolean
  stale?: boolean
  appliedProfile?: string | null
}) {
  const { state } = useAppContext({ includeSettings: true })
  const { serviceStatus, pendingText, currentCore, coreVersions, isConfigsLoading, version, isOutdatedUI, isOutdatedCore, settings } = state
  const authEnabled = settings.authEnabled

  const isRunning = serviceStatus === 'running'
  const isPending = serviceStatus === 'pending' || serviceStatus === 'loading'

  const [systemStats, setSystemStats] = useState<SystemStats | null>(null)

  useEffect(() => {
    let mounted = true
    const refreshSystemStats = async () => {
      try {
        const result = await apiCall<{ success: boolean } & SystemStats>('GET', 'system')
        if (mounted && result.success) setSystemStats(result)
      } catch {
        // The status panel remains usable if system statistics are unavailable.
      }
    }
    refreshSystemStats()
    const interval = setInterval(refreshSystemStats, 3000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [])

  const statusText =
    serviceStatus === 'running'
      ? 'Ядро Mihomo запущено'
      : serviceStatus === 'stopped'
        ? 'Ядро Mihomo остановлено'
        : serviceStatus === 'unknown'
          ? 'Состояние недоступно'
          : pendingText || 'Загрузка...'

  return (
    <>
      <TooltipProvider delayDuration={500}>
        <div className="border-border bg-card relative z-40 flex shrink-0 flex-col justify-between gap-2 rounded-xl border px-3 py-3 sm:px-4 md:flex-row md:items-center">
          {/* Статус */}
          <div className="order-2 flex w-full items-center justify-center md:order-1 md:w-auto md:justify-start">
            <div className="bg-muted/40 flex items-center gap-2 rounded-lg border px-3 py-1.5">
              <div className="flex flex-col">
                <div className="flex items-center gap-1.75 pb-0.5">
                  <div className="relative size-2.5 shrink-0">
                    {isRunning && (
                      <span className="absolute top-1/2 left-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 animate-ping rounded-full bg-emerald-400 opacity-60" />
                    )}
                    <span
                      className={cn(
                        'absolute top-1/2 left-1/2 size-1.75 -translate-x-1/2 -translate-y-1/2 rounded-full',
                        isRunning ? 'bg-emerald-500' : isPending ? 'animate-pulse bg-amber-500' : 'bg-red-500'
                      )}
                    />
                  </div>
                  <span className="text-foreground/80 text-xs font-medium">{statusText}</span>
                </div>
                <LanGatewayStatus networkState={networkState} recoveryNotice={recoveryNotice} remoteCheck={remoteCheck} stale={stale} />
                <span className="text-muted-foreground flex items-center gap-1.5 text-[11px] tracking-tight whitespace-nowrap">
                  <span className="flex items-center gap-1">
                    <IconMemory
                      className={cn('size-3.25', usageColorClass(((systemStats?.memoryUsed ?? 0) / (systemStats?.memoryTotal || 1)) * 100))}
                    />
                    <span className={usageColorClass(((systemStats?.memoryUsed ?? 0) / (systemStats?.memoryTotal || 1)) * 100)}>
                      {systemStats ? `${formatMemoryMB(systemStats.memoryUsed)}/${formatMemoryMB(systemStats.memoryTotal)} МБ` : '—/— МБ'}
                    </span>
                  </span>
                  <span className="bg-border h-3 w-px" />
                  <span className="flex items-center gap-1">
                    <IconCpu className={cn('size-3.25', systemStats ? usageColorClass(systemStats.cpuUsage) : '')} />
                    <span className={systemStats ? usageColorClass(systemStats.cpuUsage) : ''}>
                      {systemStats ? `${systemStats.cpuUsage.toFixed(0)}%` : '—'}
                    </span>
                  </span>
                </span>
              </div>

              <span className="bg-border h-6 w-px" />

              <div className="flex shrink-0 items-center gap-1">
                {isConfigsLoading ? (
                  <>
                    <Skeleton className="size-7 rounded-md" />
                    <Skeleton className="size-7 rounded-md" />
                  </>
                ) : (
                  <>
                    {(serviceStatus === 'stopped' || (isRunning && networkState === 'inactive')) && (
                      <Tooltip>
                        <TooltipTrigger
                          render={
                            <Button
                              variant="outline"
                              size="icon-sm"
                              className="text-emerald-500 hover:border-emerald-500/50 hover:text-emerald-400"
                              aria-label="Запустить"
                              onClick={onStart}
                              disabled={isPending || !!startDisabledReason||stale}
                              title={startDisabledReason ?? (remoteAdmin ? REMOTE_START_HINT : 'Запустить Mihomo и шлюз IPv4 LAN по YAML')}
                            >
                              {isPending ? (
                                <Spinner className="text-muted-foreground size-3.5" />
                              ) : (
                                <IconPlayerPlayFilled className="size-4" />
                              )}
                            </Button>
                          }
                        />
                        <TooltipContent>{startDisabledReason ?? (remoteAdmin ? REMOTE_START_HINT : `Запустить Mihomo и шлюз LAN: ${appliedProfile ?? ""}`)}</TooltipContent>
                      </Tooltip>
                    )}
                    {(isRunning || serviceStatus === 'unknown' || isPending || stale) && (
                      <Tooltip>
                        <TooltipTrigger
                          render={
                            <Button
                              variant="outline"
                              size="icon-sm"
                              className="text-destructive hover:text-destructive/80"
                              aria-label="Остановить"
                              onClick={onStop}
                              disabled={isPending}
                            >
                              {isPending ? (
                                <Spinner className="text-muted-foreground size-3.5" />
                              ) : (
                                <IconPlayerStopFilled className="size-4" />
                              )}
                            </Button>
                          }
                        />
                        <TooltipContent>Остановить</TooltipContent>
                      </Tooltip>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Логотип */}
          <div className="order-1 flex items-center justify-center md:absolute md:left-1/2 md:order-2 md:-translate-x-1/2">
            <a
              href={PROJECT_REPO}
              target="_blank"
              rel="noreferrer"
              className="rounded-md transition-opacity hover:opacity-85"
            >
              <span className="bg-linear-to-r from-[#00D3F2] via-[#2B7FFF] to-[#155DFC] bg-clip-text text-[28px] font-semibold text-transparent">
                XkeenWRT
              </span>
            </a>
          </div>

          {/* Правая сторона */}
          <div className="order-3 ml-auto flex w-full items-center justify-center gap-1.5 md:w-auto md:justify-end">
            {isConfigsLoading || !version ? (
              <Skeleton className="h-9 w-35.75" />
            ) : (
              <Tooltip>
                <TooltipTrigger
                  render={
                    <Button variant="outline" onClick={onOpenCoreManage} disabled={isPending}>
                      <CoreLogo core={currentCore} data-icon="inline-start" />
                      <span className="text-[13px]">{capitalize(currentCore)}</span>
                      {coreVersions[currentCore] && (
                        <span className="text-muted-foreground/60 mt-0.5 text-xs">{coreVersions[currentCore]}</span>
                      )}
                      {isOutdatedCore && (
                        <span className="relative mb-3 -ml-0.75 flex">
                          <span className="absolute inline-flex size-full animate-ping rounded-full bg-blue-400 opacity-75" />
                          <span className="relative inline-flex size-1.75 rounded-full bg-blue-500" />
                        </span>
                      )}
                    </Button>
                  }
                />
                <TooltipContent>Управление ядром</TooltipContent>
              </Tooltip>
            )}
            {isConfigsLoading || !version ? (
              <Skeleton className="h-9 w-18.75" />
            ) : (
              <Tooltip>
                <TooltipTrigger
                  render={
                    <Button
                      variant="outline"
                      onClick={() => onOpenUpdate('self')}
                      disabled={isPending}
                      className={cn(
                        'relative overflow-hidden text-xs tracking-wider',
                        isOutdatedUI ? 'border-none! text-cyan-300 hover:text-cyan-300' : ''
                      )}
                    >
                      {isOutdatedUI && <ShineBorder duration={7} borderWidth={2} shineColor={['#00D3F2', '#2B7FFF', '#155DFC']} />}
                      <IconBox data-icon="inline-start" className="size-4.5" />
                      {version}
                    </Button>
                  }
                />
                <TooltipContent>{isOutdatedUI ? 'Доступно обновление' : 'Версия XkeenWRT'}</TooltipContent>
              </Tooltip>
            )}
            {isConfigsLoading || !version ? (
              <Skeleton className="size-9" />
            ) : (
              <Tooltip>
                <TooltipTrigger
                  render={
                    <Button variant="outline" size="icon" aria-label="Настройки" onClick={onOpenSettings}>
                      <IconSettings className="size-4.5" />
                    </Button>
                  }
                />
                <TooltipContent>Настройки</TooltipContent>
              </Tooltip>
            )}
            {authEnabled &&
              (isConfigsLoading || !version ? (
                <Skeleton className="size-9" />
              ) : (
                <Tooltip>
                  <TooltipTrigger
                    render={
                      <Button variant="outline" size="icon" onClick={onLogout}>
                        <IconLogout className="size-4.5" />
                      </Button>
                    }
                  />
                  <TooltipContent>Выйти</TooltipContent>
                </Tooltip>
              ))}
          </div>
        </div>
      </TooltipProvider>
    </>
  )
}
