import {expect, test} from 'bun:test'
import {refreshAppliedProvider} from '../src/lib/profile-adapter'

test('refresh is bound to the committed profile, regardless of the editor tab', async () => {
  const seen: string[]=[]
  const fetcher = (async (url: string, init?: RequestInit) => {
    seen.push(url)
    if (url==='/api/control') return Response.json({success:true,activeProfileId:'applied-one',activeProfileRevision:'rev-one'})
    if (url==='/api/profiles/applied-one') return Response.json({success:true,profile:{id:'applied-one',revision:'rev-one',source:''}})
    if (url.startsWith('/api/profiles/applied-one/providers?')) return Response.json({success:true,providers:[{id:'proxy-0',name:'same-name'}]})
    if (url.endsWith('/refresh')) {
      expect(JSON.parse(init!.body as string)).toEqual({expected_revision:'rev-one'})
      return Response.json({success:true,validation:{profile_id:'applied-one',revision:'rev-one',candidate_id:'candidate-one',status:'valid'}})
    }
    if (url.endsWith('/apply')) return Response.json({success:true,transaction:{id:'tx-one',revision:'rev-one',state:'committed'}})
    throw new Error(`Unexpected synthetic endpoint: ${url}`)
  }) as typeof fetch
  const result=await refreshAppliedProvider('proxy','same-name','synthetic-operation',fetcher)
  expect(result.profileId).toBe('applied-one')
  expect(seen.some(p=>p.includes('editor-two'))).toBe(false)
  expect(seen.filter(p=>p.endsWith('/refresh'))).toEqual(['/api/profiles/applied-one/providers/proxy-0/refresh'])
})

test('a saved but unapplied revision cannot replace the applied profile through Refresh', async () => {
  const seen:string[]=[]
  const fetcher=(async (url:string,init?:RequestInit)=>{
    seen.push(init?.method??'GET')
    return Response.json(url==='/api/control'?{success:true,activeProfileId:'one',activeProfileRevision:'committed'}:{success:true,profile:{id:'one',revision:'new-draft',source:''}})
  }) as typeof fetch
  await expect(refreshAppliedProvider('proxy','same-name','key',fetcher)).rejects.toThrow('применённой')
  expect(seen.every(m=>m==='GET')).toBe(true)
})
