import { confirmNetworkIfPending } from './service-control.ts'
import { retryRuntimeBusy } from './runtime-http.ts'
export interface Profile {
  id: string
  revision: string
  source: string
}
export class ProfileConflict extends Error {}

async function request<T>(path: string, init?: RequestInit, fetcher: typeof fetch = fetch, preparing = false): Promise<T> {
  const response = await retryRuntimeBusy(fetcher, `/api/${path}`, init)
  const data = await response.json()
  if (preparing && (!response.ok || data.success === false)) {
    if (data.code === 'CONFLICT') throw new ProfileConflict('Профиль изменён в другом сеансе. Загрузите его заново перед подготовкой.')
    if (data.code === 'AMBIGUOUS_YAML')
      throw new Error(
        'YAML содержит неподдерживаемые или неоднозначные конструкции: циклические ссылки, теги, повторяющиеся ключи, некорректное слияние или неоднозначные значения без кавычек (например on или числа с ведущим нулём). Исправьте их и сохраните профиль перед подготовкой.'
      )
    if (data.code === 'INVALID_YAML') throw new Error('Не удалось прочитать YAML. Исправьте синтаксис и сохраните профиль.')
    if (data.code === 'PREPARATION_LIMIT' || data.code === 'TOO_LARGE')
      throw new Error('Профиль превышает ограничение размера или сложности подготовки. Упростите его и сохраните.')
    if (data.code === 'BUSY') throw new Error('Хранилище занято. Повторите попытку позже.')
    throw new Error('Не удалось подготовить YAML. Проверьте профиль и повторите попытку.')
  }
  if (response.status === 409 && data.code === 'CONFLICT')
    throw new ProfileConflict(
      'Профиль изменён в другом сеансе. Ваши изменения сохранены в редакторе; скопируйте их перед повторной загрузкой.'
    )
  if (data.code === 'COMMIT_UNCERTAIN')
    throw new Error(
      'Результат сохранения неизвестен. Скопируйте изменения из редактора и заново откройте профиль, чтобы проверить сохранённую версию перед повторной попыткой.'
    )
  if (data.code === 'BUSY') throw new Error('Хранилище занято. Повторите попытку позже.')
  if (!response.ok || data.success === false) throw new Error(data.error || `HTTP ${response.status}`)
  return data as T
}
export async function listProfiles() {
  return (await request<{ profiles: string[] }>('profiles')).profiles
}
export async function loadProfile(id: string) {
  return (await request<{ profile: Profile }>(`profiles/${encodeURIComponent(id)}`)).profile
}
export async function saveProfile(id: string, source: string, expectedRevision: string | null, fetcher: typeof fetch = fetch) {
  return (
    await request<{ profile: Profile }>(
      `profiles/${encodeURIComponent(id)}`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, expected_revision: expectedRevision }),
      },
      fetcher
    )
  ).profile
}

export interface PreparedPreview {
  profile_id: string
  revision: string
  source: string
  effective_yaml: string
  mode: 'manual-preview'
  core_validation: 'not_run'
  activatable: false
  changes: { path: string; before: string | null; after: string | null; reason: string }[]
  diagnostics: { code: string; path: string; message: string }[]
}

export async function prepareProfile(id: string, expectedRevision: string, fetcher: typeof fetch = fetch) {
  return (
    await request<{ preparation: PreparedPreview }>(
      `profiles/${encodeURIComponent(id)}/prepare`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expected_revision: expectedRevision }),
      },
      fetcher,
      true
    )
  ).preparation
}

export interface Validation {
  profile_id: string
  revision: string
  candidate_id: string
  status: string
  code: string
}
export class RuntimeError extends Error {
  code: string
  constructor(code: string, message?: string) {
    super(message ?? `Операция недоступна или завершилась ошибкой (${code}).`)
    this.code = code
  }
}
export interface ManualTransaction {
  id: string
  state: string
  revision: string
}

async function runtimePost<T>(path: string, body: object, fetcher: typeof fetch): Promise<T> {
  const response = await retryRuntimeBusy(fetcher, `/api/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.success !== true) {
    const code = typeof data.code === 'string' && /^[A-Z_]{1,64}$/.test(data.code) ? data.code : `HTTP ${response.status}`
    // Only the typed validation response carries a server-generated, redacted diagnostic.
    // Other runtime failures retain fixed client messages rather than echoing arbitrary details.
    const message = code === 'VALIDATION_FAILED'
      && ['subscription', 'download', 'ruleset', 'policy', 'core_validation'].includes(data.stage)
      && typeof data.error === 'string' && data.error.length <= 1024
      ? data.error : undefined
    throw new RuntimeError(code, message)
  }
  return data as T
}
export async function validateProfile(id: string, revision: string, fetcher: typeof fetch = fetch) {
  const result = await runtimePost<{ validation: Validation }>(
    `profiles/${encodeURIComponent(id)}/validate`,
    { expected_revision: revision },
    fetcher
  )
  if (
    !result.validation ||
    result.validation.profile_id !== id ||
    result.validation.revision !== revision ||
    !result.validation.candidate_id
  )
    throw new Error('Ответ проверки не соответствует выбранной ревизии.')
  return result.validation
}
export async function applyProfile(id: string, revision: string, candidate: string, key: string, fetcher: typeof fetch = fetch) {
  const result = await runtimePost<{ transaction?: ManualTransaction; network?: {state:string;transaction_id?:string;confirm_token?:string} }>(
    `profiles/${encodeURIComponent(id)}/apply`,
    {
      expected_revision: revision,
      candidate_id: candidate,
      idempotency_key: key,
    },
    fetcher
  )
  if (result.network?.state === 'pending') {
    await confirmNetworkIfPending(result.network,fetcher)
    return {id:result.network.transaction_id!,state:'confirmed',revision}
  }
  if (!result.transaction || result.transaction.revision !== revision || !result.transaction.id)
    throw new Error('Ответ применения не соответствует выбранной ревизии. Проверьте состояние ядра.')
  return result.transaction
}

export async function cancelProfileCandidate(
  id: string, revision: string, candidate: string, fetcher: typeof fetch = fetch
): Promise<void> {
  if (!candidate) return
  await runtimePost(
    `profiles/${encodeURIComponent(id)}/candidate/cancel`,
    { expected_revision: revision, candidate_id: candidate },
    fetcher
  )
}

/** Provider windows show the running generation, not the currently edited tab. */
export async function refreshAppliedProvider(kind: 'proxy' | 'rule', name: string, key: string, fetcher: typeof fetch = fetch) {
  type Binding = {activeProfileId?: string; activeProfileRevision?: string}
  const binding=await request<Binding>('control',{cache:'no-store'},fetcher)
  const id=binding.activeProfileId, revision=binding.activeProfileRevision
  if (!id || !revision) throw new Error('Нет применённого профиля для обновления провайдера.')
  const current=(await request<{profile:Profile}>(`profiles/${encodeURIComponent(id)}`,undefined,fetcher)).profile
  if (current.id!==id || current.revision!==revision) throw new ProfileConflict('Сохранённая ревизия отличается от применённой. Обновление отменено; сначала явно примените нужный профиль.')
  const listed=await request<{providers:Array<{id:string;name:string}>}>(`profiles/${encodeURIComponent(id)}/providers?${new URLSearchParams({expected_revision:revision})}`,undefined,fetcher)
  const provider=listed.providers.find(p=>p.name===name && p.id.startsWith(kind+'-'))
  if (!provider) throw new Error('Провайдер отсутствует в применённом профиле.')
  const refreshed=await runtimePost<{validation:Validation}>(`profiles/${encodeURIComponent(id)}/providers/${encodeURIComponent(provider.id)}/refresh`,{expected_revision:revision},fetcher)
  const validation=refreshed.validation
  if (!validation || validation.status!=='valid' || validation.profile_id!==id || validation.revision!==revision || !validation.candidate_id) throw new Error('Проверка обновления не подтвердила применённый профиль.')
  const latest=await request<Binding>('control',{cache:'no-store'},fetcher)
  if (latest.activeProfileId!==id || latest.activeProfileRevision!==revision) {
    await cancelProfileCandidate(id,revision,validation.candidate_id,fetcher)
    throw new ProfileConflict('Применённый профиль изменился во время обновления.')
  }
  return {profileId:id,transaction:await applyProfile(id,revision,validation.candidate_id,key,fetcher)}
}

export function preparationMessages(preview: PreparedPreview): {messages:string[]; blocked:boolean} {
  const descriptions:Record<string,string>={
    PROVIDER_UNRESOLVED:'Подписки и правила ещё не загружены. Их загрузка и проверка выполняются на Validate.',
    ASSET_UNRESOLVED:'Профиль ссылается на неподдерживаемый внешний ресурс или сертификат.',
    OUTBOUND_UNREVIEWED:'Тип или параметры подключения не поддерживаются политикой порта.',
    UNSUPPORTED_FIELD:'Профиль содержит неподдерживаемое поле.',
    UNKNOWN_SETTING:'UNKNOWN_SETTING: поле вне разрешённой схемы OpenWrt-профиля.',
    MANAGED_SETTING:'MANAGED_SETTING: параметр принадлежит runtime и не может задаваться профилем.',
    UNRESOLVED_SETTING:'UNRESOLVED_SETTING: требуется неподдерживаемый внешний ресурс или режим.',
    ADDITIONAL_DIAGNOSTICS:'Есть дополнительные ограничения профиля; исправьте показанные ошибки и повторите Prepare.',
  }
  return {messages:[...new Set(preview.diagnostics.map(d=>descriptions[d.code]??'Профиль содержит неподдерживаемые параметры; применение остановлено.'))],blocked:preview.diagnostics.some(d=>d.code!=='PROVIDER_UNRESOLVED')}
}
