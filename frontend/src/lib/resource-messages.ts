/** Numbers the backend attaches to a resource finding; never paths or YAML. */
export interface ResourceDetail {
  resource?: string
  available_mib?: number
  reclaimable_mib?: number
  required_mib?: number
  used_entries?: number
  limit_entries?: number
  needed_entries?: number
  reclaimable_entries?: number
  cleanup_entries?: number
}

const count = (value: unknown): number | null =>
  Number.isSafeInteger(value) && (value as number) >= 0 ? (value as number) : null

/** Russian text for a resource or recovery code, with its numbers when known. */
export function resourceText(code: string, detail?: ResourceDetail | null): string | null {
  const d = detail ?? {}
  const available = count(d.available_mib)
  const required = count(d.required_mib)
  switch (code) {
    case 'NETWORK_MEMORY': {
      if (available === null || required === null) return 'Мало свободной памяти для запуска.'
      const reclaimable = count(d.reclaimable_mib)
      const release = reclaimable ? ` (+${reclaimable} МиБ освободит текущий Mihomo)` : ''
      return `Мало свободной памяти: доступно ${available} МиБ${release}, нужно ${required} МиБ.`
    }
    case 'NETWORK_TMP':
      return available === null || required === null
        ? 'Мало места во временном хранилище.'
        : `Мало места во временном хранилище: свободно ${available} МиБ, нужно ${required} МиБ.`
    case 'NETWORK_FLASH':
      return available === null || required === null
        ? 'Мало места во флеш-памяти.'
        : `Мало места во флеш-памяти: свободно ${available} МиБ, нужно ${required} МиБ.`
    case 'NETWORK_HISTORY': {
      const used = count(d.used_entries)
      const limit = count(d.limit_entries)
      const needed = count(d.needed_entries)
      const reclaimable = count(d.reclaimable_entries)
      if (used === null || limit === null || needed === null || reclaimable === null)
        return 'История заполнена, и очистка не освободит достаточно места.'
      return `История заполнена: занято ${used} из ${limit} записей, нужно ещё ${needed}, очистка освободит только ${reclaimable}.`
    }
    case 'NETWORK_HISTORY_CLEANUP': {
      const entries = count(d.cleanup_entries)
      return entries === null
        ? 'Перед запуском будут удалены старые неиспользуемые записи истории.'
        : `Перед запуском будет удалено старых записей истории: ${entries}.`
    }
    case 'NETWORK_RESOURCES':
      return 'Не удалось проверить свободные ресурсы роутера.'
    case 'SNAPSHOT_MISSING':
      return 'Откат завершён в Direct: снимок для восстановления отсутствовал или был повреждён. Перехват выключен, запустите шлюз снова.'
    default:
      return null
  }
}

/** A compatibility finding as text: resource numbers first, else its message. */
export function issueText(issue: { code: string; message: string; detail?: ResourceDetail | null }): string {
  return resourceText(issue.code, issue.detail) ?? issue.message
}
