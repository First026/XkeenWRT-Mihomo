import { describe, expect, test } from 'bun:test'
import { parse } from 'yaml'
import { insertMihomoItem } from '../src/lib/profile-insertion'

describe('Mihomo insertion', () => {
  test('inserts a proxy while retaining existing nodes and comments', () => {
    const result = insertMihomoItem(
      '# my profile\nproxies:\n  - name: first\n    type: direct\nrules: [MATCH,DIRECT]\n',
      '- name: second\n  type: direct\n',
      'proxy',
      'end'
    )
    expect(result).toContain('# my profile')
    expect(parse(result)).toEqual({
      proxies: [
        { name: 'first', type: 'direct' },
        { name: 'second', type: 'direct' },
      ],
      rules: ['MATCH', 'DIRECT'],
    })
  })
  test('handles flow collections and empty provider maps', () => {
    const proxy = insertMihomoItem('proxies: [{name: old, type: direct}]\n', '- name: new\n  type: direct\n', 'proxy', 'start')
    expect(parse(proxy).proxies.map((p: { name: string }) => p.name)).toEqual(['new', 'old'])
    const provider = insertMihomoItem(
      'proxy-providers: {}\n',
      "  'my provider':\n    type: http\n    url: https://example.invalid/list\n",
      'proxy-provider',
      'end'
    )
    expect(parse(provider)['proxy-providers']['my provider'].type).toBe('http')
  })
  test('recognizes quoted keys and refuses name collisions or ambiguous shapes', () => {
    expect(() =>
      insertMihomoItem('"proxy-providers": {"my provider": {type: http}}\n', "'my provider': {type: http}\n", 'proxy-provider', 'end')
    ).toThrow()
    expect(() =>
      insertMihomoItem(
        'proxy-groups: [{name: existing, type: select, proxies: [DIRECT]}]\n',
        '- name: existing\n  type: direct\n',
        'proxy',
        'end'
      )
    ).toThrow()
    expect(() => insertMihomoItem('proxies: invalid\n', '- name: new\n  type: direct\n', 'proxy', 'end')).toThrow()
  })
})

describe('multi-peer import', () => {
  const peers = '- name: peer-one\n  type: wireguard\n- name: peer-two\n  type: wireguard\n'
  test('inserts all peers in order before existing proxies', () => {
    const result = insertMihomoItem('proxies: [{name: old, type: direct}]\n', peers, 'proxy', 'start')
    expect(parse(result).proxies.map((item: { name: string }) => item.name)).toEqual(['peer-one', 'peer-two', 'old'])
  })
  test('rejects a batch containing duplicate names', () => {
    expect(() =>
      insertMihomoItem('proxies: []\n', '- name: peer\n  type: wireguard\n- name: peer\n  type: wireguard\n', 'proxy', 'end')
    ).toThrow()
  })
})
