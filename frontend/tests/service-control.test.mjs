import test from 'node:test'
import assert from 'node:assert/strict'
import { startLanService, stopLanService } from '../src/lib/service-control.ts'

function server(replies) {
  const calls = []
  return { calls, fetch: async (url, init) => {
    calls.push({url, body: init.body ? JSON.parse(init.body) : null})
    assert.ok(replies.length, 'unexpected request')
    return Response.json({success:true, ...replies.shift()})
  }}
}
test('Start activates LAN and confirms only after a fresh matching management round trip', async () => {
  const s = server([
    {network:{state:'pending',transaction_id:'tx',confirm_token:'token'}},
    {network:{state:'pending',transaction_id:'tx'}},
    {network:{state:'confirmed'}},
    {running:true,network:{state:'active'}},
  ])
  await startLanService(s.fetch)
  assert.deepEqual(s.calls.map(c=>c.url), ['/api/control','/api/network/status','/api/network/confirm','/api/control'])
  assert.deepEqual(s.calls[2].body, {transaction_id:'tx',confirm_token:'token'})
})
test('Changed transaction is never confirmed; running core alone is not success', async () => {
  const changed = server([{network:{state:'pending',transaction_id:'tx',confirm_token:'token'}}, {network:{state:'pending',transaction_id:'other'}}])
  await assert.rejects(startLanService(changed.fetch), /CONFLICT/)
  assert.equal(changed.calls.length,2)
  const manual = server([{network:{state:'active'}},{running:true,network:{state:'inactive'}}])
  await assert.rejects(startLanService(manual.fetch), /NOT_READY/)
})
test('Stop waits for capture cleanup and verifies stopped core and direct networking', async () => {
  const s = server([{network:{state:'stopping'}},{network:{state:'stopped'}},{running:false,network:{state:'inactive'}}])
  await stopLanService(s.fetch, async()=>{})
  assert.deepEqual(s.calls.slice(0,2).map(c=>c.body),[{action:'stop'},{action:'stop'}])
  const stale = server([{network:{state:'stopped'}},...Array.from({length:12},()=>({running:false,network:{state:'active'}}))])
  await assert.rejects(stopLanService(stale.fetch, async()=>{}), /NOT_READY/)
})

test('Unavailable status during recovery contention is retried without a false failure toast', async () => {
  const s = server([{network:{state:'active'}},{running:true,network:{state:'unknown'}},{running:true,network:{state:'active'}}])
  await startLanService(s.fetch,async()=>{})
  assert.equal(s.calls.length,3)
})

test('Start displays bounded firewall diagnostics without confirming a rejected operation', async () => {
  let calls=0
  const fetcher=async()=>{calls++;return Response.json({success:false,code:'NETWORK_FIREWALL_CONFLICT',error:'Конфликт firewall: таблица stgws, цепочка prerouting_mark, hook prerouting: mark_expression.'},{status:409})}
  await assert.rejects(startLanService(fetcher),/stgws.*prerouting_mark.*mark_expression/)
  assert.equal(calls,1)
})

test('Start displays the occupied fixed port and protocol without sending Confirm', async () => {
  let calls=0
  const fetcher=async()=>{calls++;return Response.json({success:false,code:'NETWORK_PORT_CONFLICT',error:'Порт 7893/TCP, необходимый шлюзу Mihomo, уже занят. Перехват не включён.'},{status:409})}
  await assert.rejects(startLanService(fetcher),/Порт 7893\/TCP.*уже занят/)
  assert.equal(calls,1)
})

test('Apply confirmation reuses READY round trip and never silently confirms another generation', async () => {
  const { confirmNetworkIfPending } = await import('../src/lib/service-control.ts')
  const s = server([{network:{state:'pending',transaction_id:'apply-tx'}},{network:{state:'confirmed'}}])
  await confirmNetworkIfPending({state:'pending',transaction_id:'apply-tx',confirm_token:'token'},s.fetch)
  assert.deepEqual(s.calls.map(c=>c.url),['/api/network/status','/api/network/confirm'])
  const stale=server([{network:{state:'pending',transaction_id:'newer'}}])
  await assert.rejects(confirmNetworkIfPending({state:'pending',transaction_id:'old',confirm_token:'token'},stale.fetch),/CONFLICT/)
  assert.equal(stale.calls.length,1)
})

test('Disable follows helper receipt or cancellation to inactive and never sends Confirm', async()=>{
 const {disableGateway}=await import('../src/lib/service-control.ts')
 for(const reply of [{state:'pending',event_id:'helper-event'},{state:'cancelling',transaction_id:'capture-tx'}]){
  const s=server([{network:reply},{network:{state:'recovering'}},{network:{state:'inactive'}}])
  await disableGateway(s.fetch,async()=>{})
  assert.deepEqual(s.calls.map(c=>c.url),['/api/network/disable','/api/network/status','/api/network/status'])
 }
})

test('Operation verification requests a fresh observation and rejects a stale display snapshot', async () => {
  const calls=[]
  const replies=[{network:{state:'active'}},{running:true,network:{state:'active'},stale:true},{running:true,network:{state:'active'},stale:false}]
  await startLanService(async (url,init)=>{calls.push({url,init});return Response.json({success:true,...replies.shift()})},async()=>{})
  assert.equal(calls.length,3)
  assert.equal(calls[1].init.headers['X-XkeenWRT-Status-Fresh'],'1')
})

test('Stop returns its complete fresh verified snapshot for display even if background polling is unavailable', async () => {
  const final={running:false,network:{state:'inactive'},inputs:{core:'stopped',explicit:'inactive',explicit_selected:false,trusted_bindings:[]},activeProfileId:'config',activeProfileRevision:'saved'}
  const s=server([{network:{state:'stopped'}},final])
  assert.deepEqual(await stopLanService(s.fetch,async()=>{}),{success:true,...final})
})
