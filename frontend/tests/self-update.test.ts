import { describe, expect, test } from 'bun:test'
import { isInstalled, nextPhase, selfReleases, type SelfStatus } from '../src/lib/self-update'

const status = (over: Partial<SelfStatus>): SelfStatus => ({
  state: 'running',
  target: '0.1.26.5',
  exit_code: null,
  log: [],
  current: '0.1.26.4-r0',
  ...over,
})

describe('panel self-update', () => {
  test('offers only releases newer than the installed one', () => {
    const releases = selfReleases({
      current: '0.1.26.4',
      repository: 'First026/XkeenWRT-Mihomo',
      releases: [
        { version: '0.1.26.4', published: '2026-11-18', notes: 'four', current: true },
        { version: '0.1.26.5', published: '2026-12-01', notes: 'five', current: false },
      ],
    })
    expect(releases.map((r) => [r.version, r.name, r.body, r.published_at])).toEqual([
      ['0.1.26.5', 'XkeenWRT 0.1.26.5', 'five', '2026-12-01'],
    ])
  })

  test('matches the package version of the target release exactly', () => {
    expect(isInstalled('0.1.26.5-r0', '0.1.26.5')).toBe(true)
    expect(isInstalled('0.1.26.5-r12', '0.1.26.5')).toBe(true)
    expect(isInstalled('0.1.26.4-r0', '0.1.26.5')).toBe(false)
    expect(isInstalled('0.1.26.5.1-r0', '0.1.26.5')).toBe(false)
    expect(isInstalled('0.1.26.5-rc', '0.1.26.5')).toBe(false)
  })

  test('a silent panel is the restart in the middle of the update', () => {
    expect(nextPhase('0.1.26.5', null)).toEqual({ kind: 'restarting' })
    expect(nextPhase('0.1.26.5', status({}))).toEqual({ kind: 'running' })
    expect(nextPhase('0.1.26.5', status({ state: 'done', exit_code: 0 }))).toEqual({ kind: 'restarting' })
  })

  test('the update is done only when the new panel answers', () => {
    expect(nextPhase('0.1.26.5', status({ state: 'done', exit_code: 0, current: '0.1.26.5-r0' }))).toEqual({ kind: 'done' })
    expect(nextPhase('0.1.26.5', status({ state: 'running', current: '0.1.26.5-r0' }))).toEqual({ kind: 'running' })
    expect(nextPhase('0.1.26.5', status({ state: 'idle', target: null, current: '0.1.26.5-r0' }))).toEqual({ kind: 'done' })
  })

  test('a failed installer reports its last message', () => {
    const failed = status({ state: 'failed', exit_code: 1, log: ['Загрузка XkeenWRT 0.1.26.5 с GitHub…', 'XkeenWRT: Контрольная сумма APK не совпала.', ''] })
    expect(nextPhase('0.1.26.5', failed)).toEqual({ kind: 'failed', message: 'XkeenWRT: Контрольная сумма APK не совпала.' })
    expect(nextPhase('0.1.26.5', status({ state: 'failed', exit_code: 2 }))).toEqual({ kind: 'failed', message: 'Установщик завершился с кодом 2' })
    expect(nextPhase('0.1.26.5', status({ state: 'interrupted' })).kind).toBe('failed')
    expect(nextPhase('0.1.26.5', status({ state: 'idle', target: null })).kind).toBe('failed')
    const lateFailure = status({ state: 'failed', exit_code: 1, current: '0.1.26.5-r0', log: ['XkeenWRT: Не удалось подтвердить установку обоих APK.'] })
    expect(nextPhase('0.1.26.5', lateFailure).kind).toBe('failed')
  })
})
