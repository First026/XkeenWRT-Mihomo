import { test } from 'node:test'
import assert from 'node:assert/strict'
import { load } from 'js-yaml'
import { importAmnezia } from '../src/lib/amnezia.ts'

const config = `[Interface]
PrivateKey = synthetic-private
Address = 192.0.2.2/32, 2001:db8::2/128
Version = 3.1
Jc = 4
[Peer]
PublicKey = synthetic-public-1
Endpoint = [2001:db8::1]:51820
[Peer]
PublicKey = synthetic-public-2
Endpoint = example.test:51821
`

test('imports repeated peers and both address families', () => {
  const result = importAmnezia(config, 'example.conf')
  const proxies = load(result.yaml) as any[]
  assert.equal(proxies.length, 2)
  assert.equal(proxies[0].ip, '192.0.2.2/32')
  assert.equal(proxies[0].ipv6, '2001:db8::2/128')
  assert.equal(proxies[1]['public-key'], 'synthetic-public-2')
  assert.equal(proxies[0]['amnezia-wg-option'].version, 3)
})

test('preserves legacy fields in engine types', () => {
  const input = config.replace('Version = 3.1', 'Version = 1.5\nJ1 = <b 0x01>\nJ2 = <b 0x02>\nJ3 = <b 0x03>\nItime = 10')
  const options = (load(importAmnezia(input, 'legacy.conf').yaml) as any[])[0]['amnezia-wg-option']
  assert.deepEqual([options.version, options.j1, options.j2, options.j3, options.itime], [2, '<b 0x01>', '<b 0x02>', '<b 0x03>', 10])
})

test('rejects malformed numeric inputs and incompatible versions', () => {
  for (const input of [
    config.replace(']:51820', ']:65536'),
    config.replace('Jc = 4', 'Jc = nope'),
    config.replace('Jc = 4', 'Jc = 1.5'),
    config.replace('Jc = 4', 'MTU = -1'),
    config.replace('Endpoint = example.test:51821', 'Endpoint = example.test:51821\nPersistentKeepalive = 12-bad'),
    config.replace('Endpoint = example.test:51821', 'Endpoint = example.test:51821\nPersistentKeepalive = 20-10'),
    config.replace('Version = 3.1', 'Version = 9'),
    config.replace('Version = 3.1', 'Version = 3.1\nJ1 = <b 0x01>'),
    config.replace('Jc = 4', 'RandomTrailers = maybe'),
  ])
    assert.throws(() => importAmnezia(input, 'bad.conf'))
})

test('selects integer engine versions for all explicit supported versions', () => {
  for (const [version, expected] of [
    ['1.0', 2],
    ['1.5', 2],
    ['2.0', 2],
    ['3.0', 3],
    ['3.1', 3],
  ] as const) {
    const proxies = load(importAmnezia(config.replace('Version = 3.1', `Version = ${version}`), 'version.conf').yaml) as any[]
    assert.equal(proxies[0]['amnezia-wg-option'].version, expected)
  }
})

test('rejects malformed header ranges', () => {
  for (const value of ['bad', '3-1', '1-bad', '4294967296']) {
    assert.throws(() => importAmnezia(config.replace('Jc = 4', `H1 = ${value}`), 'bad.conf'))
  }
})

test('preserves peer allowed IPs, preshared key and keepalive in engine fields', () => {
  const input = config.replace(
    'PublicKey = synthetic-public-1',
    'PublicKey = synthetic-public-1\nPresharedKey = synthetic-psk\nAllowedIPs = 192.0.2.0/24, 2001:db8::/32\nPersistentKeepalive = 25'
  )
  const proxy = (load(importAmnezia(input, 'peer.conf').yaml) as any[])[0]
  assert.deepEqual(proxy.peers[0]['allowed-ips'], ['192.0.2.0/24', '2001:db8::/32'])
  assert.equal(proxy.peers[0]['pre-shared-key'], 'synthetic-psk')
  assert.equal(proxy.peers[0]['public-key'], 'synthetic-public-1')
  assert.equal(proxy['persistent-keepalive'], 25)
})

test('validates and preserves v3 numeric ranges as engine strings', () => {
  for (const value of ['bad', '10-1', '1-no', '4294967296']) {
    assert.throws(() => importAmnezia(config.replace('Jc = 4', `RekeyTimeout = ${value}`), 'bad.conf'))
  }
  const proxy = (load(importAmnezia(config.replace('Jc = 4', 'RekeyTimeout = 5-10'), 'v3.conf').yaml) as any[])[0]
  assert.equal(proxy['amnezia-wg-option']['rekey-timeout'], '5-10')
})

test('rejects unsupported and repeated fields and sections without exposing values', () => {
  const cases = [
    [config.replace('Jc = 4', 'J4 = secret-value'), 'J4'],
    [config.replace('PrivateKey = synthetic-private', 'PrivateKey = synthetic-private\nPrivateKey = secret-value'), 'PrivateKey'],
    [config.replace('Endpoint = [2001:db8::1]:51820', 'Endpoint = [2001:db8::1]:51820\nEndpoint = secret-value'), 'Endpoint'],
    [config + '\n[Unsupported]\nKey = secret-value\n', 'Unsupported'],
  ]
  for (const [input, name] of cases) {
    assert.throws(
      () => importAmnezia(input, 'invalid.conf'),
      (error: unknown) => {
        assert.ok(error instanceof Error)
        assert.ok(error.message.includes(name))
        assert.ok(!error.message.includes('secret-value'))
        return true
      }
    )
  }
})
