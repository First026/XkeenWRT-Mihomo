export interface CompatibilityIssue {
  severity: 'blocker' | 'warning'
  check: string
  code: string
  message: string
  flowtable?: { family: number; table: string; name: string; hook: number; priority: number; flags: number; devices: string[] }
  firewall?: { table: string; chain: string; hook: string; priority: number | null; rule_id: string; reason: string; affected_traffic: string }
  detail?: import('./resource-messages').ResourceDetail
}
export interface CompatibilityReport {
  ready: boolean
  issues: CompatibilityIssue[]
  completed_checks: string[]
  truncated: number
}
export async function checkCompatibility(fetcher: typeof fetch = fetch): Promise<CompatibilityReport> {
  const response = await fetcher('/api/network/compatibility', { cache: 'no-store' })
  const data = await response.json()
  const report = data.network?.compatibility
  if (!response.ok || !data.success || !report || typeof report.ready !== 'boolean' || !Array.isArray(report.issues) || !Array.isArray(report.completed_checks) || !Number.isSafeInteger(report.truncated)) throw new Error(data.code === 'BUSY' ? 'Служба занята. Повторите проверку после завершения операции.' : 'Проверка совместимости недоступна.')
  return report
}
