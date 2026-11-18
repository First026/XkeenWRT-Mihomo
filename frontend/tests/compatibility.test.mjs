import test from 'node:test'
import assert from 'node:assert/strict'
import { checkCompatibility } from '../src/lib/compatibility.ts'
test('compatibility is a single read-only request returning every finding', async () => {
  let calls=[]
  const report={ready:false,issues:[{severity:'blocker',code:'HARDWARE_OFFLOAD_UNVERIFIED'},{severity:'warning',code:'FIREWALL_UNKNOWN'}],completed_checks:['firewall','dns','resources'],truncated:0}
  const result=await checkCompatibility(async(url,init)=>{calls.push({url,init});return Response.json({success:true,network:{compatibility:report}})})
  assert.deepEqual(result,report)
  assert.equal(calls.length,1)
  assert.equal(calls[0].url,'/api/network/compatibility')
  assert.equal(calls[0].init.method,undefined)
})
test('BUSY never becomes a successful compatibility result', async()=>{
  await assert.rejects(checkCompatibility(async()=>Response.json({success:false,code:'BUSY'},{status:503})),/занята/)
})
