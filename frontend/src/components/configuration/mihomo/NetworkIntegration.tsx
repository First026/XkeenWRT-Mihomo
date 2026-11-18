import { useCallback, useEffect, useRef, useState } from 'react'
import { disableOperationKey, networkRequest } from '../../../lib/network-adapter'
import { operationKey } from '../../../lib/operation-key'
import type { Profile, Validation } from '../../../lib/profile-adapter'
import { Button } from '../../ui/button'
type Plan = { plan_id: string; summary: unknown; changes: unknown; warnings: unknown; expires_at: string; can_apply: boolean }
type Status = { state: string; transaction_id?: string; remaining_seconds?: number; last_error?: string; active_generation?: number }
type Pending = { transaction_id: string; confirm_token: string }
const show = (value: unknown) => (typeof value === 'string' ? value : JSON.stringify(value, null, 2))
export function NetworkIntegration({
  available,
  profile,
  validation,
  dirty,
}: {
  available: boolean
  profile: Profile | null
  validation: Validation | null
  dirty: boolean
}) {
  const [lan, setLan] = useState('')
  const [client, setClient] = useState('')
  const [management, setManagement] = useState('')
  const [client6, setClient6] = useState('')
  const [management6, setManagement6] = useState('')
  const [failure, setFailure] = useState('')
  const [plan, setPlan] = useState<Plan | null>(null)
  const [key, setKey] = useState('')
  const [pending, setPending] = useState<Pending | null>(null)
  const scope = JSON.stringify([
    profile?.id,
    profile?.revision,
    validation?.candidate_id,
    dirty,
    lan,
    client,
    management,
    client6,
    management6,
    failure,
  ])
  const currentScope = useRef(scope)
  useEffect(() => {
    currentScope.current = scope
  }, [scope])
  const [planScope, setPlanScope] = useState('')
  const [status, setStatus] = useState<Status | null>(null)
  const disableKey = useRef<{ scope: string; key: string } | null>(null)
  const activeGeneration = useRef<number | undefined>(undefined)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [now, setNow] = useState(() => Date.now())
  const refresh = useCallback(async () => {
    try {
      const next = await networkRequest<Status>('status')
      if (typeof next.active_generation === 'number') activeGeneration.current = next.active_generation
      setStatus(next)
    } catch {
      setStatus(null)
    }
  }, [])
  useEffect(() => {
    if (!available) return
    void Promise.resolve().then(refresh)
    const timer = setInterval(() => {
      setNow(Date.now())
      void refresh()
    }, 2000)
    return () => clearInterval(timer)
  }, [available, refresh])
  const ready = !!(
    profile &&
    validation &&
    !dirty &&
    validation.profile_id === profile.id &&
    validation.revision === profile.revision &&
    lan.trim() &&
    client.trim() &&
    management.trim() &&
    failure
  )
  const makePlan = async () => {
    if (!ready || !profile || !validation) return
    const requestedScope = scope
    setBusy(true)
    setError('')
    setPlan(null)
    setKey('')
    try {
      const result = await networkRequest<Plan>('plan', {
        candidate_id: validation.candidate_id,
        profile_id: profile.id,
        expected_revision: profile.revision,
        lan_interface: lan.trim(),
        selected_ipv4: client.trim(),
        management_ipv4: management.trim(),
        selected_ipv6: client6
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean),
        management_ipv6: management6
          .split(',')
          .map((x) => x.trim())
          .filter(Boolean),
        ipv6_policy: 'block_external',
        failure_policy: failure,
      })
      if (!result.plan_id || typeof result.can_apply !== 'boolean') throw new Error('Некорректный ответ планирования.')
      if (currentScope.current === requestedScope) {
        setPlan(result)
        setPlanScope(requestedScope)
        setKey(operationKey())
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка планирования.')
    } finally {
      setBusy(false)
    }
  }
  const apply = async () => {
    if (
      !plan?.can_apply ||
      planScope !== currentScope.current ||
      !key ||
      !Number.isFinite(Date.parse(plan.expires_at)) ||
      Date.parse(plan.expires_at) <= Date.now() ||
      !confirm('Применить показанный план? Потребуется отдельное подтверждение после проверки доступа.')
    )
      return
    setBusy(true)
    setError('')
    try {
      const result = await networkRequest<Pending & { state: string; confirm_within_seconds: number }>('apply', {
        plan_id: plan.plan_id,
        idempotency_key: key,
      })
      if (result.state !== 'pending' || !result.transaction_id || !result.confirm_token || result.confirm_within_seconds !== 120)
        throw new Error('Не удалось подтвердить запуск независимого таймера. Проверьте состояние сети.')
      setPending({ transaction_id: result.transaction_id, confirm_token: result.confirm_token })
      setPlan(null)
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка применения.')
    } finally {
      setBusy(false)
    }
  }
  const confirmNetwork = async () => {
    if (!pending || !confirm('Подтвердить перехват после проверки доступа и выбранного клиента?')) return
    setBusy(true)
    setError('')
    try {
      await networkRequest('confirm', pending)
      setPending(null)
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка подтверждения.')
    } finally {
      setBusy(false)
    }
  }
  const disable = async () => {
    if (!confirm('Отключить сетевой перехват?')) return
    setBusy(true)
    setError('')
    const attemptScope = JSON.stringify([scope, activeGeneration.current])
    disableKey.current = disableOperationKey(disableKey.current, attemptScope, operationKey)
    try {
      const result = await networkRequest<{ state: string; event_id: string; outcome?: string; error_code?: string }>(
        'disable', { idempotency_key: disableKey.current.key }
      )
      if (!result.event_id || !['pending', 'completed', 'error'].includes(result.state))
        throw new Error('Некорректный ответ отключения.')
      if (result.state === 'completed' && result.outcome === 'disabled') {
        disableKey.current = null
        setPending(null)
      } else if (result.state === 'error') {
        throw new Error('Отключение не завершено. Проверьте состояние сети.')
      } else if (result.state === 'pending') {
        setError('Отключение выполняется. Повторите запрос для проверки результата.')
      } else if (result.state !== 'pending') {
        throw new Error('Отключение не подтверждено.')
      }
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка отключения.')
    } finally {
      setBusy(false)
    }
  }
  return (
    <section className="bg-card rounded-xl border p-4" aria-label="Сетевой перехват">
      <h2 className="font-medium">Сетевой перехват{available ? '' : ': недоступен'}</h2>
      <p className="text-muted-foreground mt-1 text-sm">
        {available
          ? 'План охватывает один выбранный клиент. Данные проверяются по состоянию платформы.'
          : 'Планирование и независимый откат сети ещё не готовы. Ручной режим не включает перехват.'}
      </p>
      <p className="text-muted-foreground mt-1 text-sm">
        После применения требуется отдельное подтверждение в течение 120 секунд; иначе независимый механизм должен отменить изменения.
      </p>
      {available && (
        <>
          <fieldset disabled={busy} className="mt-3 grid gap-2 sm:grid-cols-2">
            {(
              [
                ['LAN интерфейс', lan, setLan],
                ['IPv4 клиента', client, setClient],
                ['IPv4 управления', management, setManagement],
                ['IPv6 клиента (CIDR через запятую)', client6, setClient6],
                ['IPv6 управления (CIDR через запятую)', management6, setManagement6],
              ] as const
            ).map(([label, value, set]) => (
              <label key={label} className="text-sm">
                {label}
                <input
                  className="bg-background mt-1 block w-full rounded-md border p-2"
                  value={value}
                  onChange={(e) => {
                    setPlan(null)
                    setKey('')
                    set(e.target.value)
                  }}
                />
              </label>
            ))}
            <label className="text-sm">
              Политика при отказе
              <select
                className="bg-background mt-1 block w-full rounded-md border p-2"
                value={failure}
                onChange={(e) => {
                  setPlan(null)
                  setKey('')
                  setFailure(e.target.value)
                }}
              >
                <option value="">Выберите политику</option>
                <option value="direct_on_failure">Прямой доступ при отказе</option>
                <option value="block_selected_on_failure">Блокировать выбранный клиент при отказе</option>
              </select>
            </label>
          </fieldset>
          <p className="mt-2 text-sm">
            IPv6: блокировать внешний трафик выбранного клиента; адреса управления исключаются. Неизвестный scope блокирует план.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button disabled={busy || !ready} onClick={() => void makePlan()}>
              Показать план сети
            </Button>
            <Button variant="outline" disabled={busy} onClick={() => void disable()}>
              Отключить перехват
            </Button>
          </div>
          {plan && planScope === scope && (
            <div className="mt-3 rounded-md border p-3">
              <h3 className="font-medium">План изменений</h3>
              <pre className="overflow-auto text-sm break-words whitespace-pre-wrap">
                {show(plan.summary)}
                {'\n'}
                {show(plan.changes)}
                {'\n'}
                {show(plan.warnings)}
              </pre>
              <p className="text-sm">Действителен до: {plan.expires_at}</p>
              <Button
                className="mt-2"
                disabled={
                  busy ||
                  planScope !== scope ||
                  !plan.can_apply ||
                  !Number.isFinite(Date.parse(plan.expires_at)) ||
                  Date.parse(plan.expires_at) <= now
                }
                onClick={() => void apply()}
              >
                Применить план сети
              </Button>
            </div>
          )}
          <p className="mt-3 text-sm">
            Состояние: {status?.state ?? 'недоступно'}
            {typeof status?.remaining_seconds === 'number' && `; осталось ${status.remaining_seconds} с`}
            {status?.last_error && '; последнее действие завершилось ошибкой'}
          </p>
          {pending && (
            <Button
              className="mt-2"
              disabled={
                busy ||
                status?.state !== 'pending' ||
                status.transaction_id !== pending.transaction_id ||
                (typeof status.remaining_seconds === 'number' && status.remaining_seconds <= 0)
              }
              onClick={() => void confirmNetwork()}
            >
              Подтвердить сеть
            </Button>
          )}
          {error && (
            <p role="alert" className="text-destructive mt-2 text-sm">
              {error}
            </p>
          )}
        </>
      )}
    </section>
  )
}
