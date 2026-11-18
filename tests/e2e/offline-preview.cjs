const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright')
const { spawn } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')
const state = `/tmp/xkeenwrt-preview-${process.pid}-${Date.now()}`
const base = 'http://127.0.0.1:18080'
const out = process.env.XKEEN_E2E_OUTPUT || '/workspace/outputs/xkeenwrt-r17-verification/ui'
const server = spawn(path.resolve('backend/target/debug/xkeenwrt-ui'), ['preview', '--state-dir', state, '--port', '18080'], {stdio: 'ignore'})
let browser
;(async () => {
  await fs.mkdir(out, {recursive:true})
  try {
    let ready = false
    for (let i=0;i<100;i++) { try { if ((await fetch(base)).ok) {ready=true;break} } catch {} await new Promise(r=>setTimeout(r,100)) }
    assert(ready, 'Preview did not start')
    browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium',headless:true,args:['--no-sandbox']})
    const context = await browser.newContext({viewport:{width:1440,height:1000},permissions:['clipboard-read','clipboard-write']})
    await context.route('**/*', route=>new URL(route.request().url()).origin===base?route.continue():route.abort())
    const page = await context.newPage(); page.setDefaultTimeout(8000); const errors=[]
    page.on('pageerror', e=>errors.push(e.message))
    await page.goto(base)
    await page.locator('#password').fill('synthetic-preview-password')
    await page.locator('#token').fill(await fs.readFile(path.join(state,'bootstrap-token'),'utf8'))
    await page.getByRole('button',{name:'Установить пароль'}).click()
    await page.locator('.cm-content').waitFor()
    const editor=page.locator('.cm-content')
    const readEditor=async()=>{await editor.click();await page.keyboard.press('Control+A');await page.keyboard.press('Control+C');return page.evaluate(()=>navigator.clipboard.readText())}
    const replaceEditor=async text=>{await editor.click();await page.keyboard.press('Control+A');await page.keyboard.insertText(text)}
    const tool=async name=>{await page.getByRole('button',{name:'Утилиты',exact:true}).click();await page.getByRole('menuitem',{name,exact:true}).click()}
    const close=async()=>{await page.keyboard.press('Escape');await page.getByRole('dialog').waitFor({state:'hidden'})}
    const original='proxies: [{name: config-only, type: ss, server: example.invalid, port: 443, cipher: aes-128-gcm, password: synthetic}]\nrules: ["MATCH,DIRECT"]\n'
    await page.evaluate(async source=>{
      for(const id of ['config','beta']) {
        const previous=await fetch('/api/profiles/'+id).then(r=>r.ok?r.json():null)
        const r=await fetch('/api/profiles/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({source,expected_revision:previous?.profile.revision??null})})
        if(!r.ok)throw Error('Cannot seed profile')
      }
    },original)
    await page.reload();await editor.waitFor();await page.getByRole('tab',{name:'beta',exact:true}).click()
    const draft='proxies: [{name: beta-only, type: ss, server: example.invalid, port: 443, cipher: aes-128-gcm, password: synthetic}]\nproxy-providers: {subscription_1: {type: http, url: "https://example.invalid/old"}}\nproxy-groups: [{name: PICK, type: select, proxies: [DIRECT]}]\nrules: ["MATCH,DIRECT"]\n'
    await replaceEditor(draft)
    await tool('Добавить подключение')
    const input=page.getByPlaceholder('vless://...')
    await input.fill('  https://example.invalid/subscription  ')
    assert(await page.getByRole('button',{name:'Сгенерировать',exact:true}).isEnabled(), 'trimmed HTTPS link must enable Generate')
    await input.press('Enter')
    await page.getByText('Название провайдера',{exact:true}).waitFor()
    assert.equal(await page.getByLabel('Название провайдера',{exact:true}).inputValue(),'subscription_2','Name uses the unsaved beta draft')
    assert.equal(await page.getByLabel('URL подписки',{exact:true}).inputValue(),'https://example.invalid/subscription')
    assert(await page.getByLabel('Интервал автообновления (не поддерживается)').isDisabled())
    await page.locator('#subscription-group').selectOption('PICK')
    await page.screenshot({path:path.join(out,'import-form.png')})
    await page.getByRole('button',{name:'В конец',exact:true}).click()
    await page.getByRole('dialog').waitFor({state:'hidden'})
    const inserted=await readEditor();assert.match(inserted,/subscription_2/);assert.match(inserted,/use:.*subscription_2/s);assert.match(inserted,/beta-only/)
    await page.getByRole('tab',{name:'config',exact:true}).click();assert.equal(await readEditor(),original)
    await page.getByRole('tab',{name:'beta',exact:true}).click();assert.equal(await readEditor(),inserted)
    console.log('PASS actual UI: trimmed HTTPS button/Enter, real form, active draft naming, selected group, two-profile isolation')
    const uri=JSON.parse(await fs.readFile('backend/tests/fixtures/subscription-import.json','utf8')).at(-1).uri
    const anchored='proxies: &saved\n - {name: beta-only, type: ss, server: example.invalid, port: 443, cipher: aes-128-gcm, password: synthetic}\nrules: ["MATCH,DIRECT"]\n'
    await replaceEditor(anchored);await tool('Добавить подключение');await input.fill('  '+uri+'  ')
    await page.getByRole('button',{name:'Сгенерировать',exact:true}).click();await page.getByRole('button',{name:'В конец',exact:true}).click()
    await page.getByText('Вставка в коллекцию с YAML-якорями или ссылками не поддерживается.',{exact:true}).last().waitFor()
    assert.equal(await input.inputValue(),'  '+uri+'  ');assert.match(await page.getByRole('dialog').innerText(),/short-id/)
    await page.screenshot({path:path.join(out,'insert-error.png')});await close();assert.equal(await readEditor(),anchored)
    await tool('Добавить подключение');await input.fill(uri);await page.getByRole('button',{name:'Сгенерировать',exact:true}).click()
    await page.waitForTimeout(350);assert.equal(await input.inputValue(),uri)
    await page.getByRole('button',{name:'Заменить',exact:true}).click();await page.getByPlaceholder('Выберите прокси').click()
    await page.getByRole('option',{name:'beta-only',exact:true}).waitFor();assert.equal(await page.getByRole('option',{name:'config-only',exact:true}).count(),0)
    await page.keyboard.press('Escape');await close()
    console.log('PASS actual UI: failed insertion preserves preview/input/draft; reopening retains fresh input; Replace uses beta draft')
    const alias='proxies:\n - &used {name: beta-only, type: ss, server: example.invalid, port: 443, cipher: aes-128-gcm, password: synthetic}\ncopy: *used\nrules: ["MATCH,DIRECT"]\n'
    await replaceEditor(alias);await tool('Добавить подключение');await input.fill(uri);await input.press('Enter')
    await page.getByRole('button',{name:'Заменить',exact:true}).click();await page.getByPlaceholder('Выберите прокси').click();await page.getByRole('option',{name:'beta-only',exact:true}).click()
    await page.getByRole('button',{name:'Заменить',exact:true}).last().click()
    await page.getByText('Замена прокси в flow-стиле не поддерживается',{exact:true}).waitFor();assert.equal(await input.inputValue(),uri)
    await close();assert.equal(await readEditor(),alias)
    await replaceEditor(anchored);await tool('Импорт AmneziaWG')
    const conf='[Interface]\nPrivateKey = SYNTHETIC_PRIVATE_KEY\nAddress = 10.0.0.2/32\nJc = 4\n\n[Peer]\nPublicKey = SYNTHETIC_PUBLIC_KEY\nEndpoint = 192.0.2.1:51820\n'
    await page.getByRole('dialog').locator('input[type=file]').setInputFiles({name:'fixture.conf',mimeType:'text/plain',buffer:Buffer.from(conf)})
    await page.getByRole('button',{name:'В конец',exact:true}).click();await page.getByText('Вставка в коллекцию с YAML-якорями или ссылками не поддерживается.',{exact:true}).last().waitFor()
    assert.match(await page.getByRole('dialog').innerText(),/fixture/);await close();assert.equal(await readEditor(),anchored)
    console.log('PASS actual UI: failed Replace and Amnezia insertion keep draft and preview')
    await replaceEditor('proxies: []\nrules: ["MATCH,DIRECT"]\n');await tool('Импорт AmneziaWG')
    await page.getByRole('dialog').locator('input[type=file]').setInputFiles({name:'fresh.conf',mimeType:'text/plain',buffer:Buffer.from(conf)})
    await page.waitForTimeout(350);assert.match(await page.getByRole('dialog').innerText(),/fresh/)
    await page.getByRole('button',{name:'В конец',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});assert.match(await readEditor(),/fresh/)
    await page.screenshot({path:path.join(out,'draft-success.png')})
    assert.equal(errors.length,0,JSON.stringify(errors))
    await fs.writeFile(path.join(out,'results.json'),JSON.stringify({jsErrors:errors,passed:['trim-button-enter','form','active-draft','two-profiles','use-binding','failed-insert','failed-replace','failed-amnezia','rapid-reopen','successful-amnezia']},null,2))
  } finally {
    await browser?.close(); server.kill('SIGTERM'); await fs.rm(state,{recursive:true,force:true})
  }
})().catch(e=>{console.error(e.stack);process.exitCode=1})
