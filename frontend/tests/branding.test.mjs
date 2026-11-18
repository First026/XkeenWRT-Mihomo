import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { PROJECT_REPO } from '../src/lib/types.ts'

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8')

test('Browser tab names the XkeenWRT panel', () => {
  assert.match(read('../index.html'), /<title>XkeenWRT<\/title>/)
})

test('Header logo opens the XkeenWRT repository', () => {
  assert.equal(PROJECT_REPO, 'https://github.com/First026/XkeenWRT-Mihomo')
  const header = read('../src/components/status/StatusBar.tsx')
  assert.match(header, /href=\{PROJECT_REPO\}/)
  assert.doesNotMatch(header, /zxc-rv\/XKeen-UI/)
})
