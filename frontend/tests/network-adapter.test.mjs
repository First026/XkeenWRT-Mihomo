import { test } from 'node:test'
import assert from 'node:assert/strict'
import { disableOperationKey, networkRequest } from '../src/lib/network-adapter.ts'

test('network plan is requested with explicit scope and policy', async () => {
  const policy = {candidate_id:'c', profile_id:'p', expected_revision:'r', lan_interface:'br-lan', selected_ipv4:'192.0.2.2', management_ipv4:'192.0.2.3', selected_ipv6:['2001:db8::2/128'], management_ipv6:['2001:db8::3/128'], ipv6_policy:'block_external', failure_policy:'direct_on_failure'}
  const fetcher = async (url, init) => {
    assert.equal(url, '/api/network/plan')
    assert.deepEqual(JSON.parse(init.body), policy)
    return Response.json({success:true,network:{plan_id:'plan',summary:'scope',changes:[],warnings:[],expires_at:'later',can_apply:false}})
  }
  assert.equal((await networkRequest('plan', policy, fetcher)).can_apply, false)
})
test('unavailable network operation is not successful', async () => {
  await assert.rejects(networkRequest('disable', {idempotency_key:'key'}, async () => Response.json({success:false,code:'UNAVAILABLE'}, {status:503})), /UNAVAILABLE/)
})
test('disable retries retain the key for the same scope', async () => {
  let count = 0
  const create = () => `key-${++count}`
  const first = disableOperationKey(null, 'generation-1', create)
  const retry = disableOperationKey(first, 'generation-1', create)
  assert.equal(retry.key, first.key)
  const changed = disableOperationKey(retry, 'generation-2', create)
  assert.notEqual(changed.key, retry.key)
  const fetcher = async (url, init) => {
    assert.equal(url, '/api/network/disable')
    assert.deepEqual(JSON.parse(init.body), {idempotency_key: first.key})
    return Response.json({success:true,network:{state:'pending',event_id:'event'}})
  }
  assert.equal((await networkRequest('disable', {idempotency_key:first.key}, fetcher)).state, 'pending')
})
test('network adapter unwraps only the real network response envelope', async () => {
  await assert.rejects(
    networkRequest('status', undefined, async () => Response.json({success:true,state:'active'})),
    /неверный формат/
  )
  assert.deepEqual(
    await networkRequest('status', undefined, async () => Response.json({success:true,network:{state:'active'}})),
    {state:'active'}
  )
})
