import { toMihomoYaml } from './mihomo-yaml'
import { subscriptionUrl } from './uri-policy'

export const HEALTH_CHECK_URL = 'https://www.gstatic.com/generate_204'
export const CLIENT_FINGERPRINTS = ['chrome', 'firefox', 'safari', 'iOS', 'android', 'edge', '360', 'qq', 'random']
export interface SubscriptionForm {
  name: string; url: string; interval: number
  hcEnable: boolean; hcUrl: string; hcInterval: number; hcExpectedStatus: number
  headerEnable: boolean; userAgent: string; hwid: string
  filterEnable: boolean; filter: string; excludeFilter: string; excludeType: string
  fingerprint: string; x25519: 'inherit' | 'enable' | 'disable'
}
export const randomHwid = () => Array.from(crypto.getRandomValues(new Uint8Array(6)), n => n.toString(16).padStart(2, '0').toUpperCase()).join('')
export function createDefaultForm(url: string, existingConfig: string): SubscriptionForm {
  let idx = 1
  while (existingConfig.includes(`subscription_${idx}`)) idx++
  return {name: `subscription_${idx}`, url: subscriptionUrl(url), interval: 0, hcEnable: true, hcUrl: HEALTH_CHECK_URL, hcInterval: 300, hcExpectedStatus: 204, headerEnable: true, userAgent: 'ClashMeta/1.19.30; mihomo/1.19.30', hwid: randomHwid(), filterEnable: false, filter: '', excludeFilter: '', excludeType: '', fingerprint: '', x25519: 'inherit'}
}
/** Used by the actual dialog and the HTTP-link generator; never emits expressions. */
export function generateSubYaml(form: SubscriptionForm): string {
  const name = form.name.trim()
  if (!name || name.length > 128 || /[\x00-\x1f\x7f]/.test(name)) throw new Error('Укажите имя провайдера от 1 до 128 символов.')
  if (form.interval !== 0) throw new Error('Автообновление подписки не поддерживается: обновляйте её вручную в «Подписки».')
  if (form.x25519 !== 'inherit') throw new Error('Принудительный X25519 для провайдера не поддерживается; используются параметры узлов.')
  if (form.fingerprint && !CLIENT_FINGERPRINTS.includes(form.fingerprint)) throw new Error('Неподдерживаемый Client Fingerprint.')
  const sub: Record<string, any> = { type: 'http', url: subscriptionUrl(form.url), override: {udp: true} }
  if (form.fingerprint) sub.override['client-fingerprint'] = form.fingerprint
  if (form.hcEnable) {
    if (form.hcUrl !== HEALTH_CHECK_URL || !Number.isInteger(form.hcInterval) || form.hcInterval < 30 || form.hcInterval > 86400 || !Number.isInteger(form.hcExpectedStatus) || form.hcExpectedStatus < 100 || form.hcExpectedStatus > 599)
      throw new Error('Проверка задержки: только фиксированный HTTPS URL, интервал 30–86400 с и HTTP-статус 100–599.')
    sub['health-check'] = {enable: true, url: HEALTH_CHECK_URL, interval: form.hcInterval, 'expected-status': form.hcExpectedStatus}
  }
  if (form.headerEnable) {
    for (const value of [form.userAgent, form.hwid]) if (value.length > 512 || /[\x00-\x1f\x7f]/.test(value)) throw new Error('Недопустимый заголовок подписки.')
    sub.header = {'User-Agent': [form.userAgent], 'x-hwid': [form.hwid]}
  }
  if (form.filterEnable) {
    if (form.filter) sub.filter = form.filter
    if (form.excludeFilter) sub['exclude-filter'] = form.excludeFilter
    if (form.excludeType) sub['exclude-type'] = form.excludeType
  }
  return toMihomoYaml({[name]: sub}, 2).trimEnd() + '\n'
}
