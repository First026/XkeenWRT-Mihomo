import { test } from 'node:test'
import assert from 'node:assert/strict'
import { listManagedProviders, refreshManagedProvider } from '../src/lib/provider-adapter.ts'

test('provider list and refresh are bound to the saved revision without sending URLs', async () => {
  const calls = []
  const fetcher = async (url, init) => {
    calls.push([url, init?.method ?? 'GET', init?.body && JSON.parse(init.body)])
    return calls.length === 1
      ? Response.json({success:true, revision:'rev', providers:[{id:'proxy-0',name:'Home'}]})
      : Response.json({success:true, validation:{profile_id:'home',revision:'rev',candidate_id:'new',status:'valid'}})
  }
  assert.deepEqual(await listManagedProviders('home','rev',fetcher), [{id:'proxy-0',name:'Home'}])
  assert.equal((await refreshManagedProvider('home','proxy-0','rev',fetcher)).candidate_id, 'new')
  assert.deepEqual(calls, [['/api/profiles/home/providers?expected_revision=rev','GET',undefined], ['/api/profiles/home/providers/proxy-0/refresh','POST',{expected_revision:'rev'}]])
})
test('stale lists and failed refresh do not produce a candidate or reveal backend details', async () => {
  await assert.rejects(listManagedProviders('home','rev',async () => Response.json({success:true,revision:'other',providers:[]})), /ревизии/)
  await assert.rejects(refreshManagedProvider('home','proxy-0','rev',async () => Response.json({success:false,code:'UNAVAILABLE',error:'synthetic-secret'}, {status:503})), e => e.message.includes('UNAVAILABLE') && !e.message.includes('synthetic-secret'))
})
test('malformed provider and candidate responses are rejected', async () => {
  await assert.rejects(listManagedProviders('home','rev',async () => Response.json({success:true,revision:'rev',providers:[null]})), /ревизии/)
  await assert.rejects(refreshManagedProvider('home','proxy-0','rev',async () => Response.json({success:true,validation:{profile_id:'home',revision:'rev',candidate_id:42,status:'valid'}})), /ревизии/)
})
