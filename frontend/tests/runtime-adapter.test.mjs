import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cancelProfileCandidate, validateProfile, applyProfile } from '../src/lib/profile-adapter.ts'
import { loadControlStatus, loadPlatformStatus, resumeAfterReinstall } from '../src/lib/runtime-adapter.ts'

const requestId = '00000000-0000-4000-8000-000000000002'

test('control status only reads and returns the exact completed Remove request', async () => {
  const requests = []
  const status = await loadControlStatus(async (url, init) => {
    requests.push([url, init?.method ?? 'GET'])
    return Response.json({ success: true, running: false, resumeRequestId: requestId, capabilities: ['core_control'] })
  })
  assert.deepEqual(requests, [['/api/control', 'GET']])
  assert.deepEqual(status, { running: false, resumeRequestId: requestId, capabilities: ['core_control'] })
})

test('platform capability list comes from one read-only status response and rejects unknown flags', async () => {
  let request
  const status = await loadPlatformStatus(async (url, init) => {
    request = [url, init.method, init.cache]
    return Response.json({
      platform: 'openwrt',
      capabilities: ['platform_inspect', 'profile_validate', 'not_a_capability'],
      unsupported_reasons: ['Native provider prerequisites are unavailable'],
    })
  })
  assert.deepEqual(request, ['/api/platform', 'GET', 'no-store'])
  assert.deepEqual(status, {
    capabilities: ['platform_inspect', 'profile_validate'],
    unsupportedReasons: ['Native provider prerequisites are unavailable'],
  })
})

test('resume is one explicit request and never starts the core', async () => {
  const requests = []
  await resumeAfterReinstall(requestId, async (url, init) => {
    requests.push([url, init.method, JSON.parse(init.body)])
    return Response.json({ success: true, running: false })
  })
  assert.deepEqual(requests, [[
    '/api/control',
    'POST',
    { action: 'resume_after_reinstall', request_id: requestId },
  ]])
})

test('resume does not report success unless the backend confirms stopped state', async () => {
  await assert.rejects(
    resumeAfterReinstall(requestId, async () => Response.json({ success: true, running: true })),
    error => error.message.includes('NOT_READY'),
  )
})

test('validation and apply use the exact saved revision and candidate', async () => {
  const requests = []
  const fetcher = async (url, init) => {
    requests.push([url, JSON.parse(init.body)])
    return requests.length === 1
      ? Response.json({ success: true, validation: { profile_id: 'home', revision: 'rev', candidate_id: 'candidate', status: 'valid', code: 'OK' } })
      : Response.json({ success: true, transaction: { id: 'tx', state: 'active', revision: 'rev' } })
  }
  const validation = await validateProfile('home', 'rev', fetcher)
  const transaction = await applyProfile('home', validation.revision, validation.candidate_id, 'key', fetcher)
  assert.deepEqual(requests, [
    ['/api/profiles/home/validate', { expected_revision: 'rev' }],
    ['/api/profiles/home/apply', { expected_revision: 'rev', candidate_id: 'candidate', idempotency_key: 'key' }],
  ])
  assert.equal(transaction.state, 'active')
})
test('cancelling a preview invalidates only its exact saved-revision candidate', async () => {
  const requests = []
  await cancelProfileCandidate('home', 'rev', 'candidate', async (url, init) => {
    requests.push([url, init.method, JSON.parse(init.body)])
    return Response.json({ success: true })
  })
  assert.deepEqual(requests, [[
    '/api/profiles/home/candidate/cancel',
    'POST',
    { expected_revision: 'rev', candidate_id: 'candidate' },
  ]])
})
test('runtime errors are failures and do not expose server details', async () => {
  const fetcher = async () => Response.json({success: false, code: 'UNAVAILABLE', error: 'synthetic secret'}, {status: 503})
  await assert.rejects(validateProfile('home', 'rev', fetcher), error => error.message.includes('UNAVAILABLE') && !error.message.includes('synthetic secret'))
})

test('an explicit BUSY rejection retries the same apply key, but an uncertain transport does not', async () => {
  const requests = []
  const result = await applyProfile('home', 'rev', 'candidate', 'same-key', async (_url, init) => {
    requests.push(init.body)
    return requests.length === 1
      ? Response.json({ success: false, code: 'BUSY' }, { status: 503 })
      : Response.json({ success: true, transaction: { id: 'tx', state: 'committed', revision: 'rev' } })
  })
  assert.equal(result.id, 'tx')
  assert.equal(requests.length, 2)
  assert.equal(requests[0], requests[1])
  let attempts = 0
  await assert.rejects(applyProfile('home', 'rev', 'candidate', 'same-key', async () => {
    attempts++
    throw new Error('connection lost after send')
  }))
  assert.equal(attempts, 1)
})

test('status carries the Tailscale channel and a well-formed remote check only', async () => {
  const { controlStatusFromReply } = await import('../src/lib/runtime-adapter.ts')
  const remote = {dns:true,egress:{state:'ok',node:'🇩🇪 reality-Тест',delay_ms:49},lan_clients:2}
  const status = controlStatusFromReply({running:true,network:{state:'active',management_channel:'tailscale',remote_check:remote}})
  assert.equal(status.managementChannel, 'tailscale')
  assert.deepEqual(status.remoteCheck, remote)
  const lan = controlStatusFromReply({running:true,network:{state:'active',management_channel:null,remote_check:null}})
  assert.equal(lan.managementChannel, undefined)
  assert.equal(lan.remoteCheck, undefined)
  const forged = controlStatusFromReply({running:true,network:{state:'active',management_channel:'wan',remote_check:{dns:'yes',egress:{state:'ok'}}}})
  assert.equal(forged.managementChannel, undefined)
  assert.equal(forged.remoteCheck, undefined)
})
