const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright')
const { spawn, spawnSync } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const net = require('node:net')
const assert = require('node:assert/strict')
const YAML = require('../../frontend/node_modules/yaml')
const base = 'http://127.0.0.1:18080'
const password = 'synthetic-preview-password'
const artifacts = '/tmp/xkeenwrt-preparation-artifacts'
let fixture = `# synthetic original formatting
mixed-port: 9999
bind-address: 0.0.0.0
allow-lan: true
port: 8080
socks-port: 8081
redir-port: 8082
tproxy-port: 8083
external-controller: 0.0.0.0:9090
secret: synthetic-secret
routing-mark: 123
interface-name: synthetic-interface
tun: {enable: true, auto-route: true}
dns: {enable: true, enhanced-mode: fake-ip}
listeners: [{name: unsafe, type: http, port: 8888}]
proxy-providers:
  synthetic:
    type: http
    url: https://example.invalid/synthetic-subscription
    path: /tmp/synthetic-do-not-read
    interval: 3600
proxy-groups:
  - {name: choice, type: select, use: [synthetic]}
rules: ["MATCH,DIRECT"]
`
async function ensurePortFree() {
  const server = net.createServer()
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(18080, '127.0.0.1', resolve) })
  await new Promise(resolve => server.close(resolve))
}
;(async () => {
  assert.notEqual(process.getuid?.(), 0, 'run the preview unprivileged')
  await ensurePortFree()
  const root = await fs.mkdtemp('/tmp/xkeenwrt-preparation-')
  await fs.chmod(root, 0o700)
  const sentinel = path.join(root, 'provider-must-not-be-created')
  fixture = fixture.replace('/tmp/synthetic-do-not-read', sentinel)
  const state = path.join(root, 'state')
  const server = spawn(path.resolve('backend/target/debug/xkeenwrt-ui'), ['preview', '--state-dir', state, '--port', '18080'], { stdio: 'ignore' })
  let browser
  const errors = [], external = []
  try {
    for (let i = 0; i < 100; i++) {
      if (server.exitCode !== null) throw new Error('preview process exited before becoming ready')
      try { if ((await fetch(`${base}/api/auth/login`)).ok) break } catch {}
      if (i === 99) throw new Error('preview did not start')
      await new Promise(r => setTimeout(r, 100))
    }
    const token = await fs.readFile(path.join(state, 'bootstrap-token'), 'utf8')
    const api = async (method, url, data, cookie) => {
      const response = await fetch(base + url, {method, headers: {...(data ? {'content-type':'application/json'} : {}), ...(cookie ? {cookie} : {})}, ...(data ? {body:JSON.stringify(data)} : {})})
      return {response, body: await response.json()}
    }
    const unauthorized = await api('POST', '/api/profiles/test/prepare', {expected_revision:'stale'})
    assert.equal(unauthorized.response.status, 401)
    const setup = await api('POST', '/api/auth/setup', {token, password})
    assert.equal(setup.response.status, 200)
    const cookie = setup.response.headers.get('set-cookie').split(';')[0]
    const save = async (id, source, revision = null) => {
      const r = await api('PUT', `/api/profiles/${id}`, {source, expected_revision:revision}, cookie)
      assert.equal(r.response.status, 200)
      return r.body.profile
    }
    const prepare = async profile => api('POST', `/api/profiles/${profile.id}/prepare`, {expected_revision:profile.revision}, cookie)
    const profile = await save('hostile', fixture)
    const result = await prepare(profile)
    assert.equal(result.response.status, 200, `prepare returned ${result.response.status}`)
    assert.match(result.response.headers.get('cache-control') || '', /no-store/)
    const p = result.body.preparation
    assert.equal(p.source, fixture); assert.equal(p.revision, profile.revision)
    assert.equal(p.mode, 'manual-preview'); assert.equal(p.core_validation, 'not_run'); assert.equal(p.activatable, false)
    const effective = YAML.parse(p.effective_yaml)
    assert.equal(effective['mixed-port'], 7890); assert.equal(effective['bind-address'], '127.0.0.1'); assert.equal(effective['allow-lan'], false)
    for (const key of ['port', 'socks-port', 'redir-port', 'tproxy-port', 'routing-mark']) assert.equal(effective[key], 0)
    assert.equal(effective['interface-name'], ''); assert.equal(effective.tun.enable, false); assert.equal(effective.dns.enable, false)
    assert.equal(effective['proxy-providers'].synthetic.url, 'https://example.invalid/synthetic-subscription')
    assert.match(effective['proxy-providers'].synthetic.path, /^providers\/proxies\//)
    assert.deepEqual(effective['proxy-groups'][0].use, ['synthetic']); assert.deepEqual(effective.rules, ['MATCH,DIRECT'])
    assert.ok(p.changes.length); assert.ok(p.diagnostics.some(d => d.code === 'PROVIDER_UNRESOLVED'))
    await assert.rejects(fs.stat(sentinel), {code:'ENOENT'})
    assert.doesNotMatch(JSON.stringify(p.changes), /synthetic-secret/)
    assert.doesNotMatch(JSON.stringify(p.diagnostics), /synthetic-secret|example\.invalid|provider-must-not-be-created/)
    const read = await api('GET', '/api/profiles/hostile', null, cookie)
    assert.equal(read.body.profile.source, fixture); assert.equal(read.body.profile.revision, profile.revision)
    const updated = await save('hostile', fixture + '# newer revision\n', profile.revision)
    const stale = await prepare(profile)
    assert.equal(stale.response.status, 409); assert.equal(stale.body.code, 'CONFLICT')
    const after = await api('GET', '/api/profiles/hostile', null, cookie)
    assert.equal(after.body.profile.source, updated.source)
    console.log('PASS authenticated preparation, overrides, provider handling, source preservation and stale revision')
    for (const [name, source] of [['simple', 'proxies: []\nrules: [\"MATCH,DIRECT\"]\n'], ['v3', await fs.readFile('tests/lab/amnezia-v3.yaml', 'utf8')], ['legacy', await fs.readFile('tests/lab/amnezia-legacy.yaml', 'utf8')]]) {
      const item = await save(name, source)
      const r = await prepare(item)
      assert.equal(r.response.status, 200, `prepare ${name}`)
      const candidate = path.join(root, `${name}.yaml`)
      await fs.writeFile(candidate, r.body.preparation.effective_yaml, {mode:0o600})
      const validation = spawnSync('tests/lab/validate-mihomo.sh', ['/workspace/.cache/xkeenwrt/mihomo-linux-amd64-v1.19.34.gz', candidate], {encoding:'utf8', timeout:60000})
      assert.equal(validation.status, 0, `isolated core parser rejected ${name}: ${validation.stderr} ${validation.stdout}`)
      console.log(`PASS pinned isolated Mihomo parser accepted ${name}`)
    }
    browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless:true, args:['--no-sandbox']})
    const context = await browser.newContext({viewport:{width:1440,height:900}, permissions:['clipboard-read', 'clipboard-write']})
    await context.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort())
    context.on('request', req => { if (new URL(req.url()).origin !== base) external.push(new URL(req.url()).origin) })
    const page = await context.newPage()
    page.on('pageerror', error => errors.push(error.message))
    await page.goto(base)
    await page.locator('#password').fill(password)
    await page.getByRole('button', {name:'Войти', exact:true}).click()
    await page.getByLabel('Профиль', {exact:true}).selectOption('hostile')
    const editor = page.locator('.cm-content')
    await editor.waitFor()
    const replace = async value => { await editor.click(); await page.keyboard.press('Control+A'); await page.keyboard.insertText(value) }
    const readEditor = async () => { await editor.click(); await page.keyboard.press('Control+A'); await page.keyboard.press('Control+C'); return page.evaluate(() => navigator.clipboard.readText()) }
    const button = page.getByRole('button', {name:'Подготовить YAML'})
    await replace(fixture + '# dirty\n')
    assert.equal(await button.isDisabled(), true)
    page.once('dialog', dialog => dialog.accept())
    await page.getByRole('button', {name:'Загрузить заново'}).click()
    await button.click()
    const preview = page.getByRole('region', {name:'Подготовленный YAML'})
    await preview.waitFor()
    assert.match(await preview.innerText(), /Проверка ядром Mihomo не выполнялась/ )
    assert.match(await preview.innerText(), /Изменения параметров/ )
    assert.match(await preview.innerText(), /Ограничения и замечания/ )
    assert.equal(await preview.getByLabel('Исходный YAML').inputValue(), updated.source)
    assert.match(await preview.getByLabel('Подготовленный YAML').inputValue(), /synthetic-subscription/)
    await fs.mkdir(artifacts, {recursive:true, mode:0o700})
    await page.screenshot({path:`${artifacts}/desktop.png`, fullPage:true})
    await page.setViewportSize({width:390,height:844})
    await page.screenshot({path:`${artifacts}/mobile.png`, fullPage:true})
    const dims = await page.evaluate(() => ({scroll:document.documentElement.scrollWidth, width:document.documentElement.clientWidth}))
    assert.ok(dims.scroll <= dims.width, `mobile overflow ${JSON.stringify(dims)}`)
    const concurrent = await save('hostile', updated.source + '# concurrent writer\n', updated.revision)
    const conflict = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/prepare'))
    await button.click()
    assert.equal((await conflict).status(), 409)
    await page.getByText(/Профиль изменён в другом сеансе/).waitFor()
    assert.equal(await readEditor(), updated.source)
    await page.getByRole('button', {name:'Загрузить заново'}).click()
    await button.click()
    await preview.waitFor()
    assert.equal(await preview.getByLabel('Исходный YAML').inputValue(), concurrent.source)
    await replace(fixture + '# edited after preview\n')
    assert.equal(await preview.count(), 0)
    const ambiguous = 'proxies: &saved []\nrules: [\"MATCH,DIRECT\"]\n'
    await replace(ambiguous)
    const saveResponse = page.waitForResponse(r => r.request().method() === 'PUT' && r.url().includes('/api/profiles/'))
    await page.getByRole('button', {name:'Сохранить', exact:true}).click()
    assert.equal((await saveResponse).status(), 200)
    const failure = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/prepare'))
    await button.click()
    assert.notEqual((await failure).status(), 200)
    await page.getByText(/неоднозначные конструкции/).waitFor()
    assert.equal(await readEditor(), ambiguous)
    assert.deepEqual(errors, []); assert.deepEqual(external, [])
    console.log('PASS UI dirty guard, preview, invalidation, ambiguous YAML preservation and mobile layout')
  } finally {
    if (browser) await browser.close()
    if (server.exitCode === null && server.signalCode === null) {
      const exited = new Promise(resolve => server.once('exit', resolve))
      server.kill('SIGTERM')
      let timer
      await Promise.race([exited, new Promise(resolve => { timer = setTimeout(resolve, 3000) })])
      clearTimeout(timer)
      if (server.exitCode === null && server.signalCode === null) {
        server.kill('SIGKILL')
        await Promise.race([exited, new Promise(resolve => { timer = setTimeout(resolve, 3000) })])
        clearTimeout(timer)
      }
    }
    await fs.rm(root, {recursive:true, force:true})
    if (server.exitCode === null && server.signalCode === null) throw new Error('preview child did not exit after SIGKILL')
  }
})().catch(error => { console.error(error.stack); process.exitCode = 1 })
