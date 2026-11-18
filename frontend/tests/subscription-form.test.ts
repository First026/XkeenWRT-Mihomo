import {expect, test} from 'bun:test'
import {parse} from 'yaml'
import {createDefaultForm, generateSubYaml, HEALTH_CHECK_URL} from '../src/lib/subscription-form'
import {subscriptionUrl, checkedMihomoUri} from '../src/lib/uri-policy'
import {bindProviderToGroup, importGroups, insertMihomoItem} from '../src/lib/profile-insertion'

test('actual subscription form emits a policy-compatible provider for the active draft', () => {
  const form = createDefaultForm('  https://example.invalid/sub  ', 'proxy-providers:\n  subscription_1: {}\n')
  form.hwid = 'synthetic-hwid'; form.fingerprint = 'chrome'
  const provider = parse(generateSubYaml(form)).subscription_2
  expect(provider).toEqual({type:'http',url:'https://example.invalid/sub',override:{udp:true,'client-fingerprint':'chrome'},'health-check':{enable:true,url:HEALTH_CHECK_URL,interval:300,'expected-status':204},header:{'User-Agent':['ClashMeta/1.19.30; mihomo/1.19.30'],'x-hwid':['synthetic-hwid']}})
  expect(createDefaultForm(form.url, 'proxy-providers: {}').name).toBe('subscription_1')
  for (const change of [{x25519:'enable'},{hcUrl:'https://other.example/test'},{interval:3600},{fingerprint:'unsupported'},{name:''}])
    expect(()=>generateSubYaml({...form,...change} as typeof form)).toThrow()
})

test('URL form matches transport constraints without silently repairing internal spaces', () => {
  expect(subscriptionUrl(' http://example.org:80/sub ')).toBe('http://example.org/sub')
  expect(subscriptionUrl(' https://example.org:443/sub ')).toBe('https://example.org/sub')
  for (const url of ['https://example.org/sub path','https://example.org:444/sub','https://user:secret@example.org/','https://example.org/#','file:///etc/passwd']) expect(()=>subscriptionUrl(url)).toThrow()
})

test('provider insertion binds the chosen group and preserves include-all and draft isolation', () => {
  const a='proxy-providers: {}\nproxy-groups: [{name: A, type: select, proxies: [DIRECT]}, {name: ALL, type: select, include-all: true}]\nrules: ["MATCH,A"]\n'
  const b='proxy-groups: [{name: B, type: select, proxies: [DIRECT]}]\n'
  const addition=generateSubYaml({...createDefaultForm('https://example.org/sub',a),name:'subscription_1'})
  const inserted=insertMihomoItem(a,addition,'proxy-provider','end')
  const linked=bindProviderToGroup(inserted,'subscription_1','A')
  expect(parse(linked)['proxy-groups'][0].use).toEqual(['subscription_1'])
  expect(bindProviderToGroup(inserted,'subscription_1','ALL')).toBe(inserted)
  expect(importGroups(b).map(g=>g.name)).toEqual(['B'])
  expect(()=>bindProviderToGroup(inserted,'subscription_1','B')).toThrow()
})

test('shared negative URI cases are rejected by the direct importer without exposing unknown keys', async () => {
  const cases=(await import('../../backend/tests/fixtures/subscription-negative.json')).default
  for (const uri of cases) expect(()=>checkedMihomoUri(uri)).toThrow()
  try { checkedMihomoUri(cases.at(-1)!) } catch (error) { expect(String(error)).not.toContain('private-credential-name') }
})
