import { retryRuntimeBusy } from './runtime-http.ts'
import { RuntimeError } from './profile-adapter.ts'

export const nativeCapabilities = [
  'platform_inspect',
  'profile_validate',
  'profile_apply_manual',
  'core_control',
  'core_relay',
  'provider_refresh',
  'network_integration',
] as const
export type NativeCapability = (typeof nativeCapabilities)[number]
const nativeCapabilitySet = new Set<string>(nativeCapabilities)
function capabilitiesFrom(value: unknown): NativeCapability[] {
  if (!Array.isArray(value)) return []
  return [...new Set(value.filter((entry): entry is NativeCapability => typeof entry === 'string' && nativeCapabilitySet.has(entry)))]
}

export interface PlatformStatus {
  capabilities: NativeCapability[]
  unsupportedReasons: string[]
}
export async function loadPlatformStatus(fetcher: typeof fetch = fetch): Promise<PlatformStatus> {
  const response = await retryRuntimeBusy(fetcher, '/api/platform', { method: 'GET', cache: 'no-store' })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || !data || typeof data !== 'object') {
    const code = typeof data.code === 'string' && /^[A-Z_]{1,64}$/.test(data.code) ? data.code : `HTTP ${response.status}`
    throw new RuntimeError(code)
  }
  return {
    capabilities: capabilitiesFrom(data.capabilities),
    unsupportedReasons: Array.isArray(data.unsupported_reasons)
      ? data.unsupported_reasons.filter((reason: unknown): reason is string => typeof reason === 'string')
      : [],
  }
}

export interface ManagedInputStatus {
  core: string
  explicit: string
  explicit_selected: boolean
  trusted_bindings: Array<{ interface: string; address: string; port: number }>
}
export interface ControlStatus {
  inputs?: ManagedInputStatus
  stale?: boolean
  networkState?: string
  /** Why recovery ended the last transaction Direct, when it reported one. */
  recoveryNotice?: 'SNAPSHOT_MISSING'
  running: boolean | null
  resumeRequestId: string | null
  activeProfileId?: string | null
  activeProfileRevision?: string | null
  providerMetadata?: Array<{id:string; name:string; subscriptionInfo?: import('./types').ProxySubscriptionInfo | null}>
  capabilities: NativeCapability[]
}

const isRequestId = (value: unknown): value is string =>
  typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)

export async function loadControlStatus(fetcher: typeof fetch = fetch): Promise<ControlStatus> {
  const response = await retryRuntimeBusy(fetcher, '/api/control', { method: 'GET', cache: 'no-store' })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.success !== true) {
    const code = typeof data.code === 'string' && /^[A-Z_]{1,64}$/.test(data.code) ? data.code : `HTTP ${response.status}`
    throw new RuntimeError(code)
  }
  return controlStatusFromReply(data)
}

/** Both background reads and an action's already verified fresh reply use
 * the same complete view, including independent input selection. */
export function controlStatusFromReply(data: {
  inputs?: ManagedInputStatus | null; stale?: unknown; running?: unknown
  activeProfileId?: unknown; activeProfileRevision?: unknown; providerMetadata?: unknown
  network?: { state?: unknown; recovery_notice?: unknown } | null; resumeRequestId?: unknown; capabilities?: unknown
}): ControlStatus {
  return {
    ...(data.inputs && typeof data.inputs === 'object' && Array.isArray(data.inputs.trusted_bindings) ? { inputs: data.inputs as ManagedInputStatus } : {}),
    ...(data.stale === true ? { stale: true } : {}),
    ...(typeof data.activeProfileId === 'string' ? { activeProfileId: data.activeProfileId } : {}),
    ...(typeof data.activeProfileRevision === 'string' ? { activeProfileRevision: data.activeProfileRevision } : {}),
    ...(Array.isArray(data.providerMetadata) ? {providerMetadata: data.providerMetadata} : {}),
    ...(typeof data.network?.state === 'string' ? { networkState: data.network.state } : {}),
    ...(data.network?.recovery_notice === 'SNAPSHOT_MISSING' ? { recoveryNotice: 'SNAPSHOT_MISSING' as const } : {}),
    running: typeof data.running === 'boolean' ? data.running : null,
    resumeRequestId: isRequestId(data.resumeRequestId) ? data.resumeRequestId : null,
    capabilities: capabilitiesFrom(data.capabilities),
  }
}

export async function resumeAfterReinstall(requestId: string, fetcher: typeof fetch = fetch): Promise<void> {
  if (!isRequestId(requestId)) throw new RuntimeError('INVALID')
  const response = await retryRuntimeBusy(fetcher, '/api/control', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'resume_after_reinstall', request_id: requestId }),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.success !== true) {
    const code = typeof data.code === 'string' && /^[A-Z_]{1,64}$/.test(data.code) ? data.code : `HTTP ${response.status}`
    throw new RuntimeError(code)
  }
  if (data.running !== false) throw new RuntimeError('NOT_READY')
}
