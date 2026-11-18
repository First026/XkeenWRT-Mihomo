import { resourceText } from '../../lib/resource-messages'
import type { RemoteCheck } from '../../lib/runtime-adapter'
import { cn } from '../../lib/utils'

const labels: Record<string, string> = {
  active: 'включён',
  inactive: 'выключен',
  pending: 'ожидает подтверждения',
  degraded: 'ошибка проверки',
  recovering: 'восстановление',
}

/** One line with the router's own probes for a start over Tailscale. */
export function remoteCheckText(check: RemoteCheck): string {
  const egress =
    check.egress.state === 'ok'
      ? `✓ (${check.egress.node}, ${check.egress.delay_ms} мс)`
      : check.egress.state === 'failed'
        ? `✗ (проверено узлов: ${check.egress.tested})`
        : 'не проверялся: в профиле нет прокси'
  const clients = check.lan_clients === null ? '—' : String(check.lan_clients)
  return `Проверка через Tailscale: DNS ${check.dns ? '✓' : '✗'} · выход ${egress} · устройств через шлюз: ${clients}`
}

export function LanGatewayStatus({
  networkState = 'unknown',
  recoveryNotice,
  remoteCheck,
  stale = false,
}: {
  networkState?: string
  recoveryNotice?: 'SNAPSHOT_MISSING'
  remoteCheck?: RemoteCheck
  stale?: boolean
}) {
  const remoteOk = remoteCheck?.dns === true && remoteCheck.egress.state !== 'failed'
  return (
    <div className="flex flex-col gap-0.5 text-xs">
      <span className={cn(stale ? 'text-amber-500' : networkState === 'active' ? 'text-emerald-500' : 'text-muted-foreground')}>
        LAN по YAML: {labels[networkState] ?? 'состояние недоступно'}
      </span>
      {stale && <span role="status" className="text-amber-500 text-[11px]">Данные состояния устарели. Повторяем проверку…</span>}
      {remoteCheck && (
        <span role="status" className={cn('text-[11px]', remoteOk ? 'text-muted-foreground' : 'text-amber-500')}>
          {remoteCheckText(remoteCheck)}
        </span>
      )}
      {recoveryNotice && networkState === 'inactive' && (
        <span role="alert" className="text-[11px] text-amber-500">{resourceText(recoveryNotice)}</span>
      )}
    </div>
  )
}
