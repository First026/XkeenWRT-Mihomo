import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { checkCompatibility, type CompatibilityReport } from '../../lib/compatibility'
import { issueText } from '../../lib/resource-messages'

export function CompatibilityCheck({ disabled = false }: { disabled?: boolean }) {
  const [report, setReport] = useState<CompatibilityReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function check() {
    setBusy(true); setError('')
    try { setReport(await checkCompatibility()) }
    catch (e) { setReport(null); setError(e instanceof Error ? e.message : 'Проверка недоступна.') }
    finally { setBusy(false) }
  }
  return <section className="border-border space-y-2 rounded-lg border p-3" aria-labelledby="compatibility-heading">
    <h3 id="compatibility-heading" className="font-medium">Предпроверка следующего запуска</h3>
    <Button size="sm" variant="outline" disabled={disabled || busy} onClick={() => void check()}>{busy ? 'Проверка…' : 'Проверить совместимость'}</Button>
    {error && <p role="alert">{error}</p>}
    {report && <div role="status" className="space-y-1">
      <p>{report.ready ? 'Препятствий следующему запуску не найдено.' : 'Есть препятствия следующему запуску.'} Проверено условий: {report.completed_checks.length}. Перед запуском условия проверяются заново.</p>
      {report.issues.map((issue, index) => <p key={`${issue.code}-${index}`}>
        <strong>{issue.severity === 'blocker' ? 'Препятствие' : 'Предупреждение'}:</strong> {issueText(issue)}
        {issue.firewall && <span> Таблица {issue.firewall.table}, цепочка {issue.firewall.chain}, hook {issue.firewall.hook}, priority {issue.firewall.priority ?? '—'}, правило {issue.firewall.rule_id}; {issue.firewall.reason}, область {issue.firewall.affected_traffic}.</span>}
        {issue.flowtable && <span> Flowtable {issue.flowtable.family === 1 ? 'inet' : issue.flowtable.family === 2 ? 'ip' : 'ip6'} {issue.flowtable.table}/{issue.flowtable.name}, hook ingress, priority {issue.flowtable.priority}, flags {issue.flowtable.flags}, devices {issue.flowtable.devices.join(', ')}; область IPv4 LAN.</span>}
        <span className="text-muted-foreground"> [{issue.code}]</span>
      </p>)}
      {report.truncated > 0 && <p role="alert">Отчёт ограничен: ещё {report.truncated} результатов. Полная проверка не завершена.</p>}
    </div>}
  </section>
}
