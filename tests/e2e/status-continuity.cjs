// Public UI seam: traffic controls, advanced settings, diagnostics and their HTTP contracts.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright')
const http = require('node:http')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')
const dist = path.resolve('frontend/dist')
const server = http.createServer(async (req, res) => {
  try {
    const file = path.join(dist, req.url === '/' ? 'index.html' : req.url.split('?')[0])
    const data = await fs.readFile(file).catch(async error => {
      if (error.code !== 'ENOENT') throw error
      return require('node:zlib').gunzipSync(await fs.readFile(file+'.gz'))
    })
    res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html')
    res.end(data)
  } catch { res.statusCode = 404; res.end() }
})
let browser
;(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${server.address().port}`
  browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless:true, args:['--no-sandbox']})
  const page = await browser.newPage()
  // Loopback is a secure context in Chromium. Match the router's ordinary HTTP origin.
  await page.addInitScript(() => Object.defineProperty(crypto, 'randomUUID', { value: undefined }))
  let running = false, network = 'inactive', explicit = false, pollFailure = false, pollUnknown = false, confirmSeen = false, controlReads = 0
  let holdNextRead = false, heldRead = null
  const actions = []
  const binding = {interface:'br-lan',address:'192.0.2.1',port:7890}
  const inputs = () => ({core:running?'running':'stopped', explicit:explicit?'active':'inactive', explicit_selected:explicit, trusted_bindings:[binding]})
  const lanStatus = state => page.getByText(`LAN по YAML: ${state}`,{exact:true})
  const openSettings = async name => {
    await page.getByRole('button',{name:'Настройки',exact:true}).click()
    const dialog = page.getByRole('dialog',{name:'Настройки'})
    await dialog.getByRole('tab',{name,exact:true}).click()
    return dialog
  }
  const capture = async name => {
    if (process.env.XKEENWRT_EVIDENCE_DIR) {
      await page.screenshot({path:path.join(process.env.XKEENWRT_EVIDENCE_DIR,name+'.png'),fullPage:true,animations:'disabled'})
    }
  }
  await page.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method()
    const json = data => route.fulfill({json:{success:true,...data}})
    if (url.pathname === '/api/auth/login') return json({enabled:false})
    if (url.pathname === '/api/app-info') return json({ui_base_version:'1.4.3',package_version:'test',build_id:'synthetic',management_scope:'lan'})
    if (url.pathname === '/api/core/catalog') return json({installedVersion:'1.19.34',integrity:'verified'})
    if (url.pathname === '/api/profiles') return json({profiles:['config']})
    if (url.pathname === '/api/profiles/config') return json({profile:{id:'config',revision:'saved',source:'mode: rule\nproxies: []\nrules: ["MATCH,DIRECT"]\n'}})
    if (url.pathname === '/api/control' && method === 'GET') {
      controlReads++
      const data = {running,activeProfileId:'config',activeProfileRevision:'saved',capabilities:['core_control','network_integration'],network:{state:network},inputs:inputs()}
      if (holdNextRead) { holdNextRead = false; heldRead = {route,data}; return }
      if (pollFailure && request.headers()['x-xkeenwrt-status-fresh'] !== '1') return route.fulfill({status:503,json:{success:false,code:'BUSY'}})
      if (pollUnknown) return json({...data,running:null,network:{state:'unknown'}})
      return json(data)
    }
    if (url.pathname === '/api/inputs') {
      if (pollFailure) return route.fulfill({status:503,json:{success:false,code:'BUSY'}})
      return json({network:inputs()})
    }
    if (url.pathname === '/api/control' && method === 'POST') {
      const body = request.postDataJSON();actions.push(body.action)
      if (body.action === 'start') { running = true; network = 'pending'; return json({network:{state:'pending',transaction_id:'tx',confirm_token:'token'}}) }
      if (body.action === 'stop') { running = false; network = 'inactive'; explicit = false; return json({network:{state:'stopped'}}) }
      throw new Error(`Unexpected action ${body.action}`)
    }
    if (url.pathname === '/api/inputs/explicit' && method === 'POST') {
      const data = request.postDataJSON()
      assert.deepEqual(data,data.enabled?{enabled:true,binding:{interface:binding.interface,address:binding.address}}:{enabled:false})
      explicit = data.enabled
      running = explicit || network === 'active'
      return json({network:{state:network}})
    }
    if (url.pathname === '/api/network/disable' && method === 'POST') {
      assert.match(request.postDataJSON().idempotency_key,/^[a-f0-9]{32}$/)
      network = 'inactive'
      running = explicit
      return json({network:{state:network}})
    }
    if (url.pathname === '/api/network/compatibility') {
      assert.equal(method,'GET')
      const issues = network !== 'active' ? [] : [
        {severity:'blocker',code:'BLOCKER',message:'Несовместимое правило',firewall:{table:'fw4',chain:'forward',hook:'forward',priority:0,rule_id:'17',reason:'пересечение',affected_traffic:'IPv4 LAN'}},
        {severity:'warning',code:'WARNING',message:'Неизвестное ускорение',flowtable:{family:1,table:'fw4',name:'ft',priority:0,flags:0,devices:['br-lan']}},
      ]
      return json({network:{compatibility:{ready:issues.length===0,completed_checks:['firewall'],issues,truncated:0}}})
    }
    if (url.pathname === '/api/network/status') { actions.push('fresh-status');return json({network:{state:network,transaction_id:'tx'}}) }
    if (url.pathname === '/api/network/confirm') {
      assert.equal(actions.at(-1),'fresh-status');assert.deepEqual(request.postDataJSON(),{transaction_id:'tx',confirm_token:'token'})
      actions.push('confirm');confirmSeen = true;network = 'active';return json({network:{state:'active'}})
    }
    if (url.pathname === '/api/system') return json({memoryUsed:1,memoryTotal:2,cpuUsage:1})
    return json({capabilities:['core_control','network_integration'],providers:[],settings:{},logs:[]})
  })
  try {
    await page.goto(base)
    await page.getByText('Ядро Mihomo остановлено',{exact:true}).waitFor()
    await lanStatus('выключен').waitFor()
    for (const name of ['Перезапустить','Включить HTTP/SOCKS','Выключить HTTP/SOCKS','Выключить перехват','Проверить совместимость']) {
      assert.equal(await page.getByRole('button',{name,exact:true}).count(),0)
    }
    assert.equal(await page.getByRole('combobox',{name:'Доверенный адрес HTTP/SOCKS'}).count(),0)
    let dialog = await openSettings('Диагностика')
    const currentGateway = () => dialog.getByRole('heading',{name:'Текущее состояние шлюза'}).locator('..')
    const compatibility = () => dialog.getByRole('region',{name:'Предпроверка следующего запуска'})
    await compatibility().getByRole('button',{name:'Проверить совместимость'}).click()
    await compatibility().getByText(/Препятствий следующему запуску не найдено/).waitFor()
    assert.equal(await currentGateway().getByText('LAN по YAML: выключен').isVisible(),true)
    await page.keyboard.press('Escape')
    await page.getByRole('button',{name:'Запустить',exact:true}).click()
    await lanStatus('включён').waitFor()
    assert.equal(confirmSeen,true)
    assert.deepEqual(actions,['start','fresh-status','confirm'])
    await capture('main-active')
    dialog = await openSettings('Диагностика')
    await compatibility().getByRole('button',{name:'Проверить совместимость'}).click()
    await compatibility().getByText(/Есть препятствия следующему запуску/).waitFor()
    assert.equal(await compatibility().getByText(/Несовместимое правило.*priority 0.*правило 17/).isVisible(),true)
    assert.equal(await compatibility().getByText(/Неизвестное ускорение.*Flowtable inet fw4\/ft/).isVisible(),true)
    assert.equal(await currentGateway().getByText('LAN по YAML: включён').isVisible(),true)
    await capture('diagnostics-active-with-blocker')
    await page.keyboard.press('Escape')
    pollFailure = true
    const readsBefore = controlReads
    await page.waitForTimeout(7000)
    assert.ok(controlReads > readsBefore,'background polling must continue')
    assert.equal(await page.getByText('Ядро Mihomo запущено',{exact:true}).isVisible(),true,'BUSY must preserve the last confirmed running status')
    assert.equal(await lanStatus('включён').isVisible(),true,'BUSY must preserve confirmed LAN status')
    assert.equal(await page.getByText('Данные состояния устарели. Повторяем проверку…',{exact:true}).isVisible(),true)
    assert.equal(await page.getByRole('button',{name:'Остановить',exact:true}).isEnabled(),true,'safe Stop stays available while stale')
    pollFailure = false
    pollUnknown = true
    await page.waitForTimeout(3500)
    assert.equal(await lanStatus('включён').isVisible(),true,'an unknown observation is not a stopped gateway')
    assert.equal(await page.getByRole('button',{name:'Остановить',exact:true}).isEnabled(),true)
    pollUnknown = false
    holdNextRead = true
    for (let attempt=0;!heldRead && attempt<60;attempt++) await page.waitForTimeout(100)
    assert.ok(heldRead,'hold one old background GET across Stop')
    await page.getByRole('button',{name:'Остановить',exact:true}).click()
    await page.getByText('Ядро Mihomo остановлено',{exact:true}).waitFor()
    await heldRead.route.fulfill({json:{success:true,...heldRead.data}})
    await page.waitForTimeout(300)
    assert.equal(await page.getByText('Ядро Mihomo остановлено',{exact:true}).isVisible(),true,'an old GET cannot resurrect running state after Stop')
    assert.equal(actions.at(-1),'stop')
    assert.equal(await page.getByRole('button',{name:'Запустить',exact:true}).isEnabled(),true)
    dialog = await openSettings('Расширенные настройки')
    const getExplicit = () => dialog.getByRole('region',{name:'HTTP/SOCKS'})
    assert.equal(await dialog.getByRole('button',{name:'Проверить совместимость'}).count(),0)
    await getExplicit().getByRole('combobox',{name:'Доверенный адрес HTTP/SOCKS'}).selectOption('br-lan/192.0.2.1')
    await getExplicit().getByRole('button',{name:'Включить HTTP/SOCKS'}).click()
    await getExplicit().getByText('включён',{exact:true}).waitFor()
    await getExplicit().getByRole('button',{name:'Выключить HTTP/SOCKS'}).click()
    await getExplicit().getByText('выключен',{exact:true}).waitFor()
    await getExplicit().getByRole('button',{name:'Включить HTTP/SOCKS'}).click()
    await getExplicit().getByText('включён',{exact:true}).waitFor()
    await page.keyboard.press('Escape')
    await page.getByText('Ядро Mihomo запущено',{exact:true}).waitFor()
    await page.getByRole('button',{name:'Запустить',exact:true}).click()
    await lanStatus('включён').waitFor()
    assert.equal(explicit,true,'upper Start keeps the selected explicit input')
    assert.deepEqual(actions.slice(-3),['start','fresh-status','confirm'])
    assert.equal(await page.getByRole('button',{name:'Запустить шлюз',exact:true}).count(),0)
    dialog = await openSettings('Расширенные настройки')
    await capture('advanced-combined')
    await dialog.getByRole('button',{name:'Выключить перехват'}).click()
    await dialog.getByRole('button',{name:'Выключить перехват'}).and(dialog.locator(':disabled')).waitFor()
    assert.equal(await getExplicit().getByText('включён',{exact:true}).isVisible(),true)
    assert.equal(running,true)
    await page.keyboard.press('Escape')
    await lanStatus('выключен').waitFor()
    await page.getByRole('button',{name:'Запустить',exact:true}).click()
    await lanStatus('включён').waitFor()
    pollFailure = true
    await page.getByText('Данные состояния устарели. Повторяем проверку…',{exact:true}).waitFor()
    await page.getByRole('button',{name:'Остановить',exact:true}).click()
    await page.getByText('Ядро Mihomo остановлено',{exact:true}).waitFor()
    await lanStatus('выключен').waitFor()
    dialog = await openSettings('Расширенные настройки')
    assert.equal(await getExplicit().getByText('выключен',{exact:true}).isVisible(),true,'fresh Stop snapshot updates inputs while polling fails')
    await page.keyboard.press('Escape')
    const readsAfterStop = controlReads
    await page.waitForTimeout(3500)
    assert.ok(controlReads > readsAfterStop,'polling continues after Stop even when its background refresh fails')
    assert.equal(await page.getByText('Ядро Mihomo остановлено',{exact:true}).isVisible(),true)
    await page.setViewportSize({width:390,height:844})
    dialog = await openSettings('Диагностика')
    const modalBounds = await dialog.boundingBox()
    for (const name of ['Расширенные настройки','Диагностика']) {
      const tabBounds = await dialog.getByRole('tab',{name,exact:true}).boundingBox()
      assert.ok(tabBounds && modalBounds && tabBounds.x + tabBounds.width <= modalBounds.x + modalBounds.width)
    }
    await capture('diagnostics-mobile')
    console.log('PASS three sections; diagnostic readiness independent of active LAN; explicit on/off, Disable preserves HTTP/SOCKS, upper Start + fresh Confirm, stale + safe Stop, late GET fenced, verified Stop')
  } finally {
    if (process.env.XKEENWRT_EVIDENCE_SCREENSHOT) await page.screenshot({path:process.env.XKEENWRT_EVIDENCE_SCREENSHOT,fullPage:true})
    await browser.close();await new Promise(resolve=>server.close(resolve))
  }
})().catch(async error=>{console.error(error);if(browser)await browser.close();server.close();process.exitCode=1})
