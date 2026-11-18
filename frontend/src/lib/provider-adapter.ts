import type { Validation } from './profile-adapter'
export interface ManagedProvider {
  id: string
  name: string
}
async function read(response: Response): Promise<any> {
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.success !== true) {
    const code = typeof data.code === 'string' && /^[A-Z_]{1,64}$/.test(data.code) ? data.code : `HTTP ${response.status}`
    throw new Error(`Обновление provider недоступно или завершилось ошибкой (${code}).`)
  }
  return data
}
export async function listManagedProviders(id: string, revision: string, fetcher: typeof fetch = fetch): Promise<ManagedProvider[]> {
  const data = await read(
    await fetcher(`/api/profiles/${encodeURIComponent(id)}/providers?${new URLSearchParams({ expected_revision: revision })}`)
  )
  if (
    data.revision !== revision ||
    !Array.isArray(data.providers) ||
    !data.providers.every(
      (p: ManagedProvider | null) =>
        p !== null && typeof p === 'object' && typeof p.name === 'string' && typeof p.id === 'string' && /^(proxy|rule)-\d+$/.test(p.id)
    )
  )
    throw new Error('Ответ provider не соответствует выбранной ревизии.')
  return data.providers
}
export async function refreshManagedProvider(
  id: string,
  provider: string,
  revision: string,
  fetcher: typeof fetch = fetch
): Promise<Validation> {
  if (!/^(proxy|rule)-\d+$/.test(provider)) throw new Error('Некорректный идентификатор provider.')
  const data = await read(
    await fetcher(`/api/profiles/${encodeURIComponent(id)}/providers/${provider}/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ expected_revision: revision }),
    })
  )
  const validation = data.validation
  if (
    !validation ||
    validation.profile_id !== id ||
    validation.revision !== revision ||
    validation.status !== 'valid' ||
    typeof validation.candidate_id !== 'string' ||
    !validation.candidate_id
  )
    throw new Error('Ответ обновления не соответствует выбранной ревизии.')
  return validation
}
