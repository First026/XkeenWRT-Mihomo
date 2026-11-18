const common = ['type', 'security', 'sni', 'fp', 'alpn', 'insecure', 'allowinsecure', 'servicename', 'path', 'host', 'mode']
const fields: Record<string, string[]> = {
  vless: [...common, 'pbk', 'sid', 'flow', 'encryption', 'spx', 'headertype', 'support-x25519mlkem768'],
  trojan: common,
  hysteria2: ['sni', 'fp', 'alpn', 'insecure', 'allowinsecure', 'obfs', 'obfs-password', 'up', 'down'],
  ss: [],
}
const publicNames: Record<string, string> = {'support-x25519mlkem768': 'support-x25519mlkem768', type: 'type', security: 'security', spx: 'spx', headertype: 'headerType', flow: 'flow', encryption: 'encryption', mode: 'mode', pqv: 'pqv', extra: 'extra', minpacketsize: 'minPacketSize', maxpacketsize: 'maxPacketSize', 'obfs-min-packet-size': 'minPacketSize', 'obfs-max-packet-size': 'maxPacketSize'}
const unsupported = (key: string, position?: number): never => {
  throw new Error(`Параметр ${publicNames[key] ?? 'с неизвестным именем (имя скрыто)'}${position === undefined ? '' : `, позиция ${position} в URI query,`} не поддерживается или несовместим с выбранным транспортом Mihomo.`)
}

export const SUBSCRIPTION_URL_HINT = 'HTTPS:443 или HTTP:80 без userinfo и #fragment. Проверяются DNS и все IP; локальные адреса запрещены. До 5 HTTPS-переходов; при смене origin заголовки не пересылаются. HTTP без шифрования и без редиректов.'
export function subscriptionUrl(input: string): string {
  const value = input.trim()
  try {
    const u = new URL(value)
    if (value.length > 4096 || /\s/.test(value) || value.includes('#') || u.username || u.password || !u.hostname || !['https:', 'http:'].includes(u.protocol) || u.port)
      throw new Error()
    return u.href
  } catch { throw new Error(`Недопустимый URL подписки. ${SUBSCRIPTION_URL_HINT}`) }
}
export function isSupportedImport(input: string): boolean {
  return /^(?:ss|vless|vmess|hysteria2|hy2|https?|trojan):\/\//i.test(input.trim())
}

/** Match the managed subscription contract before rendering a direct URI preview. */
export function checkedMihomoUri(input: string): string {
  const uri = input.trim()
  if (!isSupportedImport(uri) || uri.length > 16 * 1024 || /[\x00-\x1f\x7f-\x9f]/.test(uri)) throw new Error('Некорректная ссылка подключения.')
  if (/^https?:\/\//i.test(uri)) return subscriptionUrl(uri)
  if (uri.startsWith('vmess://')) {
    let d: Record<string, unknown>
    try { d = JSON.parse(atob(uri.slice(8).replace(/-/g, '+').replace(/_/g, '/'))) } catch { throw new Error('Некорректная VMess-ссылка.') }
    const known = ['v','ps','add','port','id','aid','scy','net','type','host','path','tls','sni','fp','alpn','allowInsecure']
    if (!d || Array.isArray(d) || Object.keys(d).some(k => !known.includes(k))) unsupported('unknown')
    if (!['tcp','ws','grpc'].includes(String(d.net || 'tcp'))) unsupported('type')
    if (d.type && d.type !== 'none') unsupported('headertype')
    if (d.tls && !['none','tls'].includes(String(d.tls))) unsupported('security')
    return uri
  }
  let u: URL
  try { u = new URL(uri) } catch { throw new Error('Некорректная ссылка подключения.') }
  const kind = u.protocol.slice(0, -1).replace(/^hy2$/, 'hysteria2')
  const allowed = fields[kind]
  if (!allowed) throw new Error('Протокол не поддерживается Mihomo.')
  const q: Record<string, string> = {}
  let position = 0
  for (const [rawKey, value] of u.searchParams) {
    const key = rawKey.toLowerCase(); position++
    if (!allowed.includes(key)) unsupported(key, position)
    if (Object.hasOwn(q, key)) {
      if (key === 'support-x25519mlkem768') throw new Error(`Повторяющийся параметр support-x25519mlkem768, позиция ${position} в URI query.`)
      throw new Error('Повторяющийся параметр ссылки.')
    }
    q[key] = value
  }
  if (q['support-x25519mlkem768'] !== undefined && (kind !== 'vless' || q.security !== 'reality' || !['true','false'].includes(q['support-x25519mlkem768'])))
    unsupported('support-x25519mlkem768', [...u.searchParams.keys()].findIndex(k => k.toLowerCase() === 'support-x25519mlkem768') + 1)
  for (const k of ['insecure','allowinsecure']) if (q[k] !== undefined && !['0','1','true','false'].includes(q[k])) unsupported(k)
  if (['vless','trojan'].includes(kind)) {
    const net = q.type ?? 'tcp', security = q.security ?? 'none'
    if (!['tcp','ws','grpc'].includes(net)) unsupported('type')
    if (!['none','tls','reality',''].includes(security)) unsupported('security')
    if (q.spx !== undefined && (kind !== 'vless' || security !== 'reality' || q.spx.length > 2048 || !q.spx.startsWith('/') || q.spx.startsWith('//') || /[\x00-\x1f\x7f-\x9f]/.test(q.spx))) unsupported('spx')
    if (q.headertype !== undefined && (net !== 'tcp' || q.headertype !== 'none')) unsupported('headertype')
    if ((net !== 'grpc' && (q.servicename !== undefined || q.mode !== undefined)) || (net === 'tcp' && (q.path !== undefined || q.host !== undefined)) || (net === 'grpc' && q.host !== undefined)) unsupported('type')
    if (net === 'grpc' && q.mode !== undefined && q.mode !== 'gun') unsupported('mode')
    if (security !== 'reality' && (q.pbk !== undefined || q.sid !== undefined)) unsupported('security')
    if (!['tls','reality'].includes(security) && ['sni','fp','alpn','insecure','allowinsecure'].some(k => q[k] !== undefined)) unsupported('security')
    if (security === 'reality' && (kind !== 'vless' || !q.pbk)) unsupported('security')
    if (q.sid !== undefined && (!/^[0-9a-f]*$/i.test(q.sid) || q.sid.length > 16 || q.sid.length % 2)) throw new Error('Недопустимый Reality short-id.')
    if (q.encryption !== undefined && q.encryption !== 'none') unsupported('encryption')
    if (q.flow && (q.flow !== 'xtls-rprx-vision' || net !== 'tcp' || !['tls','reality'].includes(security))) unsupported('flow')
  }
  return uri
}
