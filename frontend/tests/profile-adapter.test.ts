import { describe, expect, test } from 'bun:test'
import { prepareProfile, saveProfile, ProfileConflict } from '../src/lib/profile-adapter'

describe('profile adapter', () => {
  test('sends the revision and returns the persisted profile', async () => {
    const fetcher: typeof fetch = async (_url, init) => {
      expect(JSON.parse(String(init?.body))).toEqual({ source: 'proxies: []\n', expected_revision: 'old' })
      return Response.json({ success: true, profile: { id: 'home', revision: 'new', source: 'proxies: []\n' } })
    }
    expect(await saveProfile('home', 'proxies: []\n', 'old', fetcher)).toEqual({ id: 'home', revision: 'new', source: 'proxies: []\n' })
  })

  test('reports a stale revision without changing the caller’s edit', async () => {
    const edit = 'proxies:\n  - name: local edit\n'
    const fetcher: typeof fetch = async () =>
      Response.json({ success: false, code: 'CONFLICT', error: 'Revision conflict' }, { status: 409 })
    await expect(saveProfile('home', edit, 'stale', fetcher)).rejects.toBeInstanceOf(ProfileConflict)
  })
})

describe('profile preparation', () => {
  test('reports preparation failures without using save-specific messages or server details', async () => {
    const conflict: typeof fetch = async () => Response.json({ success: false, code: 'CONFLICT' }, { status: 409 })
    await expect(prepareProfile('home', 'stale', conflict)).rejects.toThrow('Профиль изменён')
    const ambiguous: typeof fetch = async () =>
      Response.json({ success: false, code: 'AMBIGUOUS_YAML', error: 'private details' }, { status: 400 })
    await expect(prepareProfile('home', 'rev', ambiguous)).rejects.toThrow('циклические ссылки')
    const limit: typeof fetch = async () => Response.json({ success: false, code: 'PREPARATION_LIMIT' }, { status: 400 })
    await expect(prepareProfile('home', 'rev', limit)).rejects.toThrow('ограничение')
  })

  test('requests the saved revision and returns the preview', async () => {
    const preparation = {
      profile_id: 'home',
      revision: 'rev-1',
      source: 'proxies: []\n',
      effective_yaml: 'mixed-port: 7890\n',
      mode: 'manual-preview',
      core_validation: 'not_run',
      activatable: false,
      changes: [{ path: 'mixed-port', before: null, after: '7890', reason: 'Ручной режим' }],
      diagnostics: [{ code: 'ASSET', path: 'providers', message: 'Требуется проверка' }],
    } as const
    const fetcher: typeof fetch = async (url, init) => {
      expect(String(url)).toBe('/api/profiles/home%20profile/prepare')
      expect(init?.method).toBe('POST')
      expect(JSON.parse(String(init?.body))).toEqual({ expected_revision: 'rev-1' })
      return Response.json({ success: true, preparation })
    }
    expect(await prepareProfile('home profile', 'rev-1', fetcher)).toEqual(preparation)
  })
})

test('validation exposes the safe provider stage and reason instead of a generic code', async () => {
  const {validateProfile} = await import('../src/lib/profile-adapter')
  const fetcher: typeof fetch = async () => Response.json({success:false,code:'VALIDATION_FAILED',stage:'subscription',diagnostic:{reason:'subscription_format',provider:'proxy-0'},error:'Разбор подписки (proxy-0): ожидался YAML с proxies, список URI или его Base64.'},{status:422})
  await expect(validateProfile('config','rev',fetcher)).rejects.toThrow('Разбор подписки (proxy-0)')
})
