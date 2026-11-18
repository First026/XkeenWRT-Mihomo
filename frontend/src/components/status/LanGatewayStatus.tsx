import { resourceText } from '../../lib/resource-messages'
import { cn } from '../../lib/utils'

const labels: Record<string, string> = {
  active: 'включён',
  inactive: 'выключен',
  pending: 'ожидает подтверждения',
  degraded: 'ошибка проверки',
  recovering: 'восстановление',
}

export function LanGatewayStatus({
  networkState = 'unknown',
  recoveryNotice,
  stale = false,
}: {
  networkState?: string
  recoveryNotice?: 'SNAPSHOT_MISSING'
  stale?: boolean
}) {
  return (
    <div className="flex flex-col gap-0.5 text-xs">
      <span className={cn(stale ? 'text-amber-500' : networkState === 'active' ? 'text-emerald-500' : 'text-muted-foreground')}>
        LAN по YAML: {labels[networkState] ?? 'состояние недоступно'}
      </span>
      {stale && <span role="status" className="text-amber-500 text-[11px]">Данные состояния устарели. Повторяем проверку…</span>}
      {recoveryNotice && networkState === 'inactive' && (
        <span role="alert" className="text-[11px] text-amber-500">{resourceText(recoveryNotice)}</span>
      )}
    </div>
  )
}
