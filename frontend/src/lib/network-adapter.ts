import { retryRuntimeBusy } from './runtime-http.ts'
export async function networkRequest<T = Record<string, unknown>>(
  operation: 'plan' | 'apply' | 'confirm' | 'status' | 'disable',
  body?: object,
  fetcher: typeof fetch = fetch
): Promise<T> {
  const response = await retryRuntimeBusy(fetcher,
    `/api/network/${operation}`,
    body === undefined
      ? undefined
      : {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        }
  )
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.success !== true) {
    const code = typeof data.code === 'string' && /^[A-Z_]{1,64}$/.test(data.code) ? data.code : `HTTP ${response.status}`
    throw new Error(`Сетевая операция не выполнена (${code}).`)
  }
  if (data.network === null || typeof data.network !== 'object' || Array.isArray(data.network))
    throw new Error('Ответ сетевой операции имеет неверный формат.')
  return data.network as T
}

/** Keep the key across retries until the server confirms completion or scope changes. */
export function disableOperationKey(
  previous: { scope: string; key: string } | null,
  scope: string,
  create: () => string
): { scope: string; key: string } {
  return previous?.scope === scope ? previous : { scope, key: create() }
}
