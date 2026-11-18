import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { readFileSync, realpathSync } from 'node:fs'

// GHSA-fc5q-39xc-vjpf: picomatch <= 4.0.7 compiles a repeated extglob around
// a `*` into nested quantifiers that backtrack exponentially. The build tools
// get the patched copy in vendor/picomatch through package.json overrides.
const require = createRequire(import.meta.url)
const vendored = require('../vendor/picomatch')

const hostile = [
  ['+(*)c', 'a'.repeat(40)],
  ['+(*a)', 'a'.repeat(40) + 'b'],
  ['*(*)c', 'a'.repeat(40)],
  ['*(*a)x', 'a'.repeat(40)],
  ['+(a*)', 'a'.repeat(40) + '/'],
  ['+(*.js)', '.js'.repeat(14) + 'x'],
  ['+(*a|b)', 'a'.repeat(40) + 'c'],
  ['*(a*|b)', 'a'.repeat(40) + '/'],
  ['*(x*|y)z', 'x'.repeat(40)],
  ['+([ab]*)c', 'a'.repeat(40)],
  ['+(*@(a))', 'a'.repeat(40) + 'b'],
  ['+(@(*a))', 'a'.repeat(40) + 'b'],
]

test('repeated extglobs around a star finish in bounded time', () => {
  for (const [glob, input] of hostile) {
    const re = vendored.makeRe(glob)
    const started = performance.now()
    assert.equal(re.test(input), false, glob)
    const ms = performance.now() - started
    assert.ok(ms < 200, `${glob} took ${ms.toFixed(1)} ms (${re.source})`)
  }
})

test('a single simple branch keeps its meaning without the repetition', () => {
  assert.ok(vendored.isMatch('abc', '+(*)c'))
  for (const s of ['a', 'xa', 'aba']) assert.ok(vendored.isMatch(s, '+(*a)'), s)
  assert.ok(!vendored.isMatch('ab', '+(*a)'))
  for (const s of ['x', 'ax', 'bax']) assert.ok(vendored.isMatch(s, '*(*a)x'), s)
  assert.ok(vendored.isMatch('a.jsb.js', '+(*.js)'))
  assert.ok(!vendored.isMatch('a/b.js', '+(*.js)'))
  assert.equal(vendored.makeRe('+(*a)').source, '^(?:(?=.)(?:[^/]*?a))$')
  assert.equal(vendored.makeRe('*(*a)x').source, '^(?:(?=.)(?:[^/]*?a)?x)$')
})

test('ambiguous repeated extglobs around a star are literalized', () => {
  assert.equal(vendored.makeRe('+(*a|b)').source, '^(?:\\+\\(\\*a\\|b\\))$')
  assert.ok(vendored.isMatch('+(*a|b)', '+(*a|b)'))
  assert.ok(!vendored.isMatch('aab', '+(*a|b)'))
})

test('globs without a repeated star are unchanged', () => {
  assert.ok(vendored.isMatch('src/a/b.ts', '**/*.{js,ts}'))
  assert.ok(vendored.isMatch('abcabc', '+(abc)'))
  assert.ok(vendored.isMatch('fffooo', '*(*(f)*(o))'))
  assert.equal(vendored.makeRe('@(*a)').source, '^(?:([^/]*?a))$')
})

test('the build tools resolve the patched copy, never the registry package', () => {
  const patched = readFileSync(new URL('../vendor/picomatch/lib/parse.js', import.meta.url), 'utf8')
  assert.match(patched, /GHSA-fc5q-39xc-vjpf/)
  // bun installs the override next to each consumer; check the build path.
  const vite = createRequire(require.resolve('vite/package.json'))
  const tinyglobby = createRequire(vite.resolve('tinyglobby/package.json'))
  const compression = createRequire(require.resolve('vite-plugin-compression2/package.json'))
  const pluginutils = createRequire(compression.resolve('@rollup/pluginutils/package.json'))
  for (const [name, from] of [['vite', vite], ['tinyglobby', tinyglobby], ['@rollup/pluginutils', pluginutils]]) {
    const installed = realpathSync(from.resolve('picomatch/lib/parse.js'))
    assert.equal(readFileSync(installed, 'utf8'), patched, `${name} resolves another picomatch: ${installed}`)
  }
  const lock = readFileSync(new URL('../bun.lock', import.meta.url), 'utf8')
  assert.doesNotMatch(lock, /\["picomatch@\d/)
  assert.match(lock, /\["picomatch@file:vendor\/picomatch"/)
})
