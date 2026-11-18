import test from 'node:test'
import assert from 'node:assert/strict'
import { issueText, resourceText } from '../src/lib/resource-messages.ts'
import { ServiceError, startLanService } from '../src/lib/service-control.ts'
import { controlStatusFromReply } from '../src/lib/runtime-adapter.ts'

test('Memory shortage shows what the running Mihomo will release', () => {
  assert.equal(
    resourceText('NETWORK_MEMORY', { resource: 'memory', available_mib: 243, reclaimable_mib: 74, required_mib: 256 }),
    'Мало свободной памяти: доступно 243 МиБ (+74 МиБ освободит текущий Mihomo), нужно 256 МиБ.',
  )
  assert.equal(
    resourceText('NETWORK_MEMORY', { resource: 'memory', available_mib: 243, reclaimable_mib: 0, required_mib: 256 }),
    'Мало свободной памяти: доступно 243 МиБ, нужно 256 МиБ.',
  )
})

test('Storage, history and cleanup texts carry their numbers', () => {
  assert.equal(resourceText('NETWORK_TMP', { available_mib: 20, required_mib: 38 }), 'Мало места во временном хранилище: свободно 20 МиБ, нужно 38 МиБ.')
  assert.equal(resourceText('NETWORK_FLASH', { available_mib: 30, required_mib: 33 }), 'Мало места во флеш-памяти: свободно 30 МиБ, нужно 33 МиБ.')
  assert.equal(
    resourceText('NETWORK_HISTORY', { used_entries: 530, limit_entries: 512, needed_entries: 145, reclaimable_entries: 40 }),
    'История заполнена: занято 530 из 512 записей, нужно ещё 145, очистка освободит только 40.',
  )
  assert.equal(resourceText('NETWORK_HISTORY_CLEANUP', { cleanup_entries: 48 }), 'Перед запуском будет удалено старых записей истории: 48.')
  assert.match(resourceText('SNAPSHOT_MISSING'), /снимок для восстановления отсутствовал или был повреждён/)
  assert.equal(resourceText('NETWORK_FIREWALL_CONFLICT'), null)
  assert.equal(issueText({ code: 'NETWORK_LAN', message: 'Основная LAN не определена.' }), 'Основная LAN не определена.')
  assert.equal(issueText({ code: 'NETWORK_MEMORY', message: 'x' }), 'Мало свободной памяти для запуска.')
})

test('Refused Start explains a resource shortage; an unknown code keeps the backend text', async () => {
  const refuse = (body) => async () => Response.json({ success: false, ...body }, { status: 409 })
  await assert.rejects(startLanService(refuse({
    code: 'NETWORK_MEMORY', error: 'Проверка совместимости обнаружила препятствия запуску.',
    network: { compatibility: { issues: [{ severity: 'blocker', code: 'NETWORK_MEMORY', message: 'x', detail: { resource: 'memory', available_mib: 243, reclaimable_mib: 0, required_mib: 256 } }] } },
  })), { message: 'Мало свободной памяти: доступно 243 МиБ, нужно 256 МиБ.' })
  await assert.rejects(startLanService(refuse({ code: 'NEW_FUTURE_CODE', error: 'Понятный текст от backend.' })), (error) =>
    error instanceof ServiceError && error.message === 'NEW_FUTURE_CODE' && error.serverText === 'Понятный текст от backend.')
})

test('Control status carries the recovery notice', () => {
  assert.equal(controlStatusFromReply({ running: false, network: { state: 'inactive', recovery_notice: 'SNAPSHOT_MISSING' } }).recoveryNotice, 'SNAPSHOT_MISSING')
  assert.equal(controlStatusFromReply({ running: false, network: { state: 'inactive', recovery_notice: 'OTHER' } }).recoveryNotice, undefined)
})
