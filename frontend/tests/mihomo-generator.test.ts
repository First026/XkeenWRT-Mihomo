import { expect, test } from 'bun:test'
import { parse } from 'yaml'
import { insertMihomoItem } from '../src/lib/profile-insertion'

// Exercise the same generator entry point used by the import dialog.
const browser = (globalThis as any).window ??= {}
await import('../src/lib/generator.js')
const generate = browser.generateConfigForCore

test('VLESS Reality preserves numeric short IDs and string transport fields through insertion', () => {
  for (const sid of ['0123456789abcdef', '01234567', '12345678', '00000000']) {
    const uri = `vless://00000000-0000-4000-8000-000000000001@vpn.example:443?security=reality&pbk=synthetic-public-key&sid=${sid}&sni=on&type=grpc&serviceName=0123#off`
    const generated = generate(uri, 'mihomo', '')
    const result = insertMihomoItem('proxies: []\nrules: ["MATCH,DIRECT"]\n', generated.content, generated.type, 'end')
    const proxy = parse(result).proxies[0]
    expect(proxy['reality-opts']['short-id']).toBe(sid)
    expect(proxy.servername).toBe('on')
    expect(proxy['grpc-opts']['grpc-service-name']).toBe('0123')
    expect(proxy.name).toBe('off')
    expect(proxy.port).toBe(443)
    expect(proxy.tls).toBe(true)
    expect(result).toMatch(/servername: ["']on["']/)
  }
})

test('subscription generator emits supported structured overrides and manual refresh', () => {
  const result = generate('https://example.invalid/sub?token=synthetic', 'mihomo', '')
  const provider = parse(result.content).subscription_1
  expect(provider.header['User-Agent']).toEqual(['ClashMeta/1.19.30; mihomo/1.19.30'])
  expect(provider.header['x-hwid']).toHaveLength(1)
  expect(provider.override['override-expr']).toBeUndefined()
  expect(provider.interval).toBeUndefined()
})

test('direct URI import refuses transports and connection options outside the provider policy', () => {
  const root = 'vless://00000000-0000-4000-8000-000000000001@vpn.example:443?'
  for (const q of ['type=xhttp', 'type=httpupgrade', 'type=tcp&headerType=http', 'spx=%2F', 'private-unknown-key=secret'])
    expect(() => generate(root + q, 'mihomo', '')).toThrow()
  expect(() => generate('hy2://synthetic@vpn.example:443?minPacketSize=64', 'mihomo', '')).toThrow()
})

test('HTTP subscription importer and UI use the same six synthetic node contracts', async () => {
  const fixtures = (await import('../../backend/tests/fixtures/subscription-import.json')).default
  for (const {uri, node} of fixtures) expect(parse(generate(uri, 'mihomo', '').content)[0]).toEqual(node)
})

test('3x-ui REALITY flag preserves true, false and the r17 default in direct import', async () => {
  const fixture=(await import('../../backend/tests/fixtures/subscription-import.json')).default.find(v=>v.case==='3x-ui-reality-mlkem-true')!
  for (const [uri,expected] of [[fixture.uri,true],[fixture.uri.replace('support-x25519mlkem768=true','support-x25519mlkem768=false'),false],[fixture.uri.replace('&support-x25519mlkem768=true',''),true]] as const) {
    const node=parse(generate(uri,'mihomo','').content)[0]
    expect(node['reality-opts']['support-x25519mlkem768']).toBe(expected)
    expect(node['reality-opts']['short-id']).toBe('01234567')
  }
})

test('3x-ui invalid MLKEM choices fail with the canonical name in direct and subscription imports', async () => {
  const cases=(await import('../../backend/tests/fixtures/subscription-mlkem-negative.json')).default
  for (const {uri} of cases) expect(()=>generate(uri,'mihomo','')).toThrow('support-x25519mlkem768')
})
