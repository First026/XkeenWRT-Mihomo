const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright')
const { spawn } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')
const state = `/tmp/xkeenwrt-runtime-ui-${process.pid}`
const base = 'http://127.0.0.1:18080'
const server = spawn(process.env.XKEENWRT_UI_BINARY || path.resolve('backend/target/debug/xkeenwrt-ui'), ['preview', '--state-dir', state, '--port', '18080'], {stdio:'ignore'})
let browser
;(async () => {
  try {
    for (let i=0; i<100; i++) { try { if ((await fetch(base)).ok) break } catch {} await new Promise(r=>setTimeout(r,100)); if (i===99) throw Error('preview unavailable') }
    const token = await fs.readFile(path.join(state,'bootstrap-token'),'utf8')
    browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless:true, args:['--no-sandbox']})
    const context = await browser.newContext()
    let revision = '', networkRequests = [], applyBody
    const requestId = '00000000-0000-4000-8000-000000000002'
    let resumeRequestId = requestId, controlRunning = false, controlPosts = []
    await context.route('**/api/platform', route => route.fulfill({json:{platform:'test',capabilities:['profile_validate','profile_apply_manual','core_control','network_integration','provider_refresh'],unsupported_reasons:[]}}))
    await context.route('**/api/control', route => {
      if (route.request().method() === 'GET') return route.fulfill({json:{success:true,running:controlRunning,resumeRequestId}})
      const body = route.request().postDataJSON()
      controlPosts.push(body)
      if (body.action === 'resume_after_reinstall') {
        assert.equal(body.request_id, requestId)
        resumeRequestId = null
      } else if (body.action === 'start') controlRunning = true
      else if (body.action === 'stop') controlRunning = false
      return route.fulfill({json:{success:true,...(body.action === 'resume_after_reinstall' ? {running:false} : {})}})
    })
    await context.route('**/api/profiles/*/validate', route => { revision = route.request().postDataJSON().expected_revision; return route.fulfill({json:{success:true,validation:{profile_id:'demo',revision,candidate_id:'candidate',status:'valid'}}}) })
    await context.route('**/api/profiles/*/providers?*', route => route.fulfill({json:{success:true,revision:new URL(route.request().url()).searchParams.get('expected_revision'),providers:[{id:'proxy-0',name:'Provider'}]}}))
    await context.route('**/api/profiles/*/providers/*/refresh', route => { assert.deepEqual(route.request().postDataJSON(), {expected_revision:revision}); return route.fulfill({json:{success:true,validation:{profile_id:'demo',revision,candidate_id:'refreshed',status:'valid'}}}) })
    await context.route('**/api/profiles/*/apply', route => { applyBody=route.request().postDataJSON(); return route.fulfill({json:{success:true,transaction:{id:'tx',state:'active',revision}}}) })
    await context.route('**/api/network/*', route => {
      const op = new URL(route.request().url()).pathname.split('/').pop()
      if (op !== 'status') networkRequests.push([op,route.request().postDataJSON()])
      if (op === 'status') return route.fulfill({json:{success:true,network:{state:'pending',transaction_id:'network-tx',remaining_seconds:90}}})
      if (op === 'plan') return route.fulfill({json:{success:true,network:{plan_id:'plan',summary:'Один клиент',changes:['DNS'],warnings:[],expires_at:'2099-01-01T00:00:00Z',can_apply:true}}})
      if (op === 'apply') return route.fulfill({json:{success:true,network:{transaction_id:'network-tx',state:'pending',confirm_token:'token',confirm_within_seconds:120}}})
      return route.fulfill({json:{success:true,network:{state:'active'}}})
    })
    const page = await context.newPage()
    await page.goto(base); await page.locator('#password').fill('synthetic-password'); await page.locator('#token').fill(token)
    await page.getByRole('button',{name:'Установить пароль'}).click()
    await page.getByRole('button',{name:'Возобновить после переустановки'}).waitFor()
    assert.deepEqual(controlPosts, [], 'page load must not resume or start runtime')
    assert.equal(await page.getByRole('button',{name:'Запустить ядро'}).isDisabled(), true, 'Start is gated until explicit Resume')
    await page.getByRole('button',{name:'Возобновить после переустановки'}).click()
    await page.getByRole('button',{name:'Возобновить после переустановки'}).waitFor({state:'detached'})
    assert.deepEqual(controlPosts, [{action:'resume_after_reinstall',request_id:requestId}])
    assert.equal(controlRunning, false, 'resume must leave core stopped')
    await page.getByRole('button',{name:'Запустить ядро'}).click()
    await page.getByRole('button',{name:'Остановить ядро'}).waitFor()
    await page.getByText('Mihomo: работает').waitFor()
    assert.deepEqual(controlPosts, [
      {action:'resume_after_reinstall',request_id:requestId},
      {action:'start'},
    ])
    controlRunning = null
    await page.getByRole('button',{name:'Обновить состояние'}).click()
    assert.equal(await page.getByRole('button',{name:'Остановить ядро'}).isDisabled(), false)
    await page.getByRole('button',{name:'Остановить ядро'}).click()
    assert.equal(controlPosts.at(-1).action, 'stop', 'unknown running state keeps emergency Stop available')
    await page.getByLabel('Новый профиль').fill('demo'); await page.getByRole('button',{name:'Создать',exact:true}).click()
    await page.locator('.cm-content').waitFor()
    await page.getByRole('button',{name:'Подготовить YAML'}).click()
    await page.getByRole('region',{name:'Подготовленный YAML'}).waitFor()
    await page.getByRole('button',{name:'Проверить ядром'}).click()
    await page.getByText('Проверка ядром пройдена. Профиль ещё не применён.').waitFor()
    const net = page.getByRole('region',{name:'Сетевой перехват'})
    await net.getByLabel('LAN интерфейс').fill('br-lan'); await net.getByLabel('IPv4 клиента').fill('192.0.2.2'); await net.getByLabel('IPv4 управления').fill('192.0.2.3')
    await net.getByLabel('IPv6 клиента (CIDR через запятую)').fill('2001:db8::2/128'); await net.getByLabel('IPv6 управления (CIDR через запятую)').fill('2001:db8::3/128')
    await net.getByLabel('Политика при отказе').selectOption('direct_on_failure')
    await net.getByRole('button',{name:'Показать план сети'}).click(); await net.getByText('Один клиент').waitFor()
    assert.equal(networkRequests[0][1].expected_revision, revision); assert.equal(networkRequests[0][1].failure_policy,'direct_on_failure')
    page.once('dialog', d=>d.accept()); await net.getByRole('button',{name:'Применить план сети'}).click()
    await net.getByRole('button',{name:'Подтвердить сеть'}).waitFor(); assert.deepEqual(networkRequests.map(x=>x[0]), ['plan','apply'])
    page.once('dialog', d=>d.accept()); await net.getByRole('button',{name:'Подтвердить сеть'}).click()
    await page.waitForTimeout(100); assert.deepEqual(networkRequests[2], ['confirm',{transaction_id:'network-tx',confirm_token:'token'}])
    const providers = page.getByRole('region',{name:'Обновление provider'})
    await providers.getByText('Provider',{exact:true}).waitFor()
    await providers.getByRole('button',{name:'Обновить'}).click()
    await page.getByText('Provider обновлён и candidate проверен. Профиль ещё не применён.').waitFor()
    page.once('dialog', d=>d.accept()); await page.getByRole('button',{name:'Применить вручную'}).click()
    await page.getByText(/Транзакция ручного режима: active/).waitFor(); assert.equal(applyBody.candidate_id,'refreshed'); assert.equal(applyBody.expected_revision,revision)
    assert.equal(await page.getByRole('button',{name:'Применить вручную'}).isDisabled(), true)
    await page.getByRole('button',{name:'Проверить ядром'}).click()
    await page.getByText('Проверка ядром пройдена. Профиль ещё не применён.').waitFor()
    await page.locator('.cm-content').click(); await page.keyboard.press('End'); await page.keyboard.insertText(' # dirty')
    assert.equal(await page.getByRole('button',{name:'Применить вручную'}).isDisabled(), true)
    assert.equal(await page.getByRole('region',{name:'Подготовленный YAML'}).count(), 0)
    console.log('PASS реальный preview backend и имитированные runtime DTO: ревизия, план, отдельное подтверждение, ручное применение')
  } finally { if (browser) await browser.close(); server.kill('SIGTERM'); if (server.exitCode===null) await new Promise(r=>server.once('exit',r)); await fs.rm(state,{recursive:true,force:true}) }
})().catch(e=>{console.error(e.stack);process.exitCode=1})
