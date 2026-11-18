import type { Release } from './types'

/** Panel self-update (decision 026): `/api/self/catalog` and `/api/self/update/status`. */
export interface SelfCatalog {
  current: string
  repository: string
  releases: Array<{ version: string; published: string; notes: string; current: boolean }>
}

export interface SelfStatus {
  state: 'idle' | 'running' | 'done' | 'failed' | 'interrupted'
  target: string | null
  exit_code: number | null
  log: string[]
  /** Package version of the panel that answered, e.g. `0.1.26.5-r0`. */
  current: string
}

export type SelfPhase =
  | { kind: 'running' }
  | { kind: 'restarting' }
  | { kind: 'done' }
  | { kind: 'failed'; message: string }

/** Newer releases only, oldest first: the installed one is not offered. */
export function selfReleases(catalog: SelfCatalog): Release[] {
  return catalog.releases
    .filter((release) => !release.current)
    .map((release) => ({
      version: release.version,
      name: `XkeenWRT ${release.version}`,
      published_at: release.published,
      is_prerelease: false,
      body: release.notes,
      assets: [],
    }))
}

/** `0.1.26.5-r0` is release `0.1.26.5`. */
export function isInstalled(packageVersion: string, target: string): boolean {
  return packageVersion.startsWith(`${target}-r`) && /^\d+$/.test(packageVersion.slice(target.length + 2))
}

/**
 * One poll of the update status. `reply` is null when the panel did not answer:
 * the APK upgrade restarts it, so silence is the expected middle of an update.
 */
export function nextPhase(target: string, reply: SelfStatus | null): SelfPhase {
  if (!reply) return { kind: 'restarting' }
  const installed = isInstalled(reply.current, target)
  switch (reply.state) {
    case 'running':
      return { kind: 'running' }
    case 'done':
      // The installer finished but the old panel still answers: wait for the new one.
      return installed ? { kind: 'done' } : { kind: 'restarting' }
    case 'failed': {
      const last = [...reply.log].reverse().find((line) => line.trim())
      return { kind: 'failed', message: last ?? `Установщик завершился с кодом ${reply.exit_code ?? '?'}` }
    }
    case 'interrupted':
      return { kind: 'failed', message: 'Установщик прервался. Проверьте роутер по SSH.' }
    default:
      return installed ? { kind: 'done' } : { kind: 'failed', message: 'Обновление не запущено' }
  }
}

const PENDING_KEY = 'xkeenwrt-self-update'

/** The restarted panel forgets the login, so the result is read after the next sign-in. */
export function rememberPendingUpdate(version: string): void {
  try {
    sessionStorage.setItem(PENDING_KEY, version)
  } catch {
    /* storage unavailable: the result is still in the router log */
  }
}

export function takePendingUpdate(): string | null {
  try {
    const version = sessionStorage.getItem(PENDING_KEY)
    sessionStorage.removeItem(PENDING_KEY)
    return version && /^\d+(\.\d+){1,4}$/.test(version) ? version : null
  } catch {
    return null
  }
}
