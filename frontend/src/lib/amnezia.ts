import * as jsyaml from 'js-yaml'

type AmneziaVersion = '1.0' | '1.5' | '2.0' | '3.0' | '3.1'

export interface DetectedAmneziaVersion {
  version: AmneziaVersion
  confidence: 'exact' | 'minimum'
}

interface AmneziaConfig {
  interface: Record<string, string>
  peers: Array<Record<string, string>>
  detectedVersion: DetectedAmneziaVersion
}

function detectAmneziaVersion(iface: Record<string, string>): DetectedAmneziaVersion {
  /*
   * Explicit Version has the highest priority.
   */
  if (iface.Version !== undefined) {
    const version = iface.Version.trim()

    if (['1', '1.0'].includes(version)) {
      return {
        version: '1.0',
        confidence: 'exact',
      }
    }

    if (version === '1.5') {
      return {
        version: '1.5',
        confidence: 'exact',
      }
    }

    if (['2', '2.0'].includes(version)) {
      return {
        version: '2.0',
        confidence: 'exact',
      }
    }

    if (['3', '3.0'].includes(version)) {
      return {
        version: '3.0',
        confidence: 'exact',
      }
    }

    if (version === '3.1') {
      return {
        version: '3.1',
        confidence: 'exact',
      }
    }

    throw new Error('Неподдерживаемая версия AmneziaWG в поле Version')
  }

  /*
   * AWG 3.1
   *
   * This params was be added in 3.1.
   */
  if (hasAny(iface, ['RandomTrailers', 'DisableCookies'])) {
    return {
      version: '3.1',
      confidence: 'minimum',
    }
  }

  /*
   * AWG 3.0+
   */
  if (
    hasAny(iface, [
      'HeaderProtectionKey',
      'ContentPaddingAddition',
      'RekeyAfterTime',
      'RekeyTimeout',
      'RejectAfterTime',
      'KeepaliveTimeout',
      'MaxHandshakeAttempts',
    ])
  ) {
    return {
      version: '3.0',
      confidence: 'minimum',
    }
  }

  /*
   * AWG 1.5+ / 2.x
   *
   * S3/S4 and I1-I5 was added from 1.5 version.
   *
   * If exists old J1-J3/ITime,
   * this allows to recognize exactly 1.5.
   */
  if (hasAny(iface, ['J1', 'J2', 'J3', 'Itime'])) {
    return {
      version: '1.5',
      confidence: 'minimum',
    }
  }

  /*
   * If there are S3/S4/I1-I5, this is already definitely not 1.0.
   *
   * But without Version it is impossible to reliably distinguish
   * AWG 1.5 from AWG 2.0.
   *
   * Therefore we choose 2.0 as the modern legacy branch,
   * but confidence = minimum.
   */
  if (hasAny(iface, ['S3', 'S4', 'I1', 'I2', 'I3', 'I4', 'I5'])) {
    return {
      version: '2.0',
      confidence: 'minimum',
    }
  }

  /*
   * AWG 1.0 remaining.
   */
  if (hasAny(iface, ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'])) {
    return {
      version: '1.0',
      confidence: 'minimum',
    }
  }

  throw new Error('Не удалось определить версию AmneziaWG: параметры AWG не найдены')
}

function hasAny(obj: Record<string, string>, keys: string[]): boolean {
  return keys.some((key) => obj[key] != null && obj[key] !== '')
}

function parseAmneziaConfig(content: string): AmneziaConfig {
  let iface: Record<string, string> | undefined
  const peers: Array<Record<string, string>> = []
  let currentSection: Record<string, string> | undefined
  let currentKind: 'Interface' | 'Peer' | undefined

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim()

    if (!line || line.startsWith('#') || line.startsWith(';')) continue

    const sectionMatch = line.match(/^\[([^\]]+)]$/)
    if (sectionMatch) {
      const section = sectionMatch[1].trim()
      if (section === 'Interface') {
        if (iface) throw new Error('Повторная секция [Interface]')
        iface = {}
        currentSection = iface
        currentKind = 'Interface'
      } else if (/^Peer(?:\s+\d+)?$/i.test(section)) {
        currentSection = {}
        peers.push(currentSection)
        currentKind = 'Peer'
      } else {
        throw new Error(`Неподдерживаемая секция [${section}]`)
      }

      continue
    }

    const separator = line.indexOf('=')

    if (separator === -1 || !currentSection || !currentKind) throw new Error('Некорректная строка конфигурации')

    const key = line.slice(0, separator).trim()
    const value = line.slice(separator + 1).trim()

    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(key)) throw new Error('Некорректное имя поля')
    const supported =
      currentKind === 'Interface'
        ? ['PrivateKey', 'Address', 'DNS', 'MTU', 'Version'].includes(key) || AMNEZIA_OPTIONS.has(key)
        : ['Endpoint', 'PublicKey', 'PresharedKey', 'PersistentKeepalive', 'AllowedIPs'].includes(key)
    if (!supported) throw new Error(`Неподдерживаемое поле ${key} в [${currentKind}]`)
    if (Object.hasOwn(currentSection, key)) throw new Error(`Повторное поле ${key} в [${currentKind}]`)
    currentSection[key] = value
  }

  if (!iface) {
    throw new Error('Секция [Interface] не найдена')
  }

  if (!peers.length) {
    throw new Error('Секция [Peer] не найдена')
  }

  if (!iface.PrivateKey) {
    throw new Error('В [Interface] отсутствует PrivateKey')
  }

  const detectedVersion = detectAmneziaVersion(iface)

  return {
    interface: iface,
    peers,
    detectedVersion,
  }
}

function parseEndpoint(endpoint: string): { server: string; port: number } {
  const value = endpoint.trim()

  // [2001:db8::1]:51820
  const ipv6 = value.match(/^\[([^\]]+)]:(\d+)$/)

  if (ipv6) {
    const port = Number(ipv6[2])
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('Некорректный порт Endpoint')
    return { server: ipv6[1], port }
  }

  const match = value.match(/^([^:\[\]]+):(\d+)$/)
  if (!match) throw new Error('Некорректный Endpoint')
  const server = match[1].trim()
  const port = Number(match[2])
  if (!server || !Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error('Некорректный порт Endpoint')
  }

  return { server, port }
}

function splitList(value?: string): string[] {
  if (!value) return []

  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
}

function parseNumber(value: string, name: string, min = 0, max = 2147483647): number {
  if (!/^\d+$/.test(value)) throw new Error(`Некорректное числовое значение ${name}`)
  const result = Number(value)
  if (!Number.isSafeInteger(result) || result < min || result > max) {
    throw new Error(`Некорректное числовое значение ${name}`)
  }
  return result
}

function toMihomoKey(key: string): string {
  const map: Record<string, string> = {
    J1: 'j1',
    J2: 'j2',
    J3: 'j3',
    Itime: 'itime',
    Jc: 'jc',
    Jmin: 'jmin',
    Jmax: 'jmax',
    S1: 's1',
    S2: 's2',
    S3: 's3',
    S4: 's4',
    H1: 'h1',
    H2: 'h2',
    H3: 'h3',
    H4: 'h4',
    I1: 'i1',
    I2: 'i2',
    I3: 'i3',
    I4: 'i4',
    I5: 'i5',
    HeaderProtectionKey: 'header-protection-key',
    ContentPaddingAddition: 'content-padding-addition',
    RekeyAfterTime: 'rekey-after-time',
    RekeyTimeout: 'rekey-timeout',
    RejectAfterTime: 'reject-after-time',
    KeepaliveTimeout: 'keepalive-timeout',
    MaxHandshakeAttempts: 'max-handshake-attempts',
    RandomTrailers: 'random-trailers',
    DisableCookies: 'disable-cookies',
  }

  return map[key] ?? key
}

const AMNEZIA_OPTIONS = new Set([
  'J1',
  'J2',
  'J3',
  'Itime',

  'Jc',
  'Jmin',
  'Jmax',

  'S1',
  'S2',
  'S3',
  'S4',

  'H1',
  'H2',
  'H3',
  'H4',

  'I1',
  'I2',
  'I3',
  'I4',
  'I5',

  'HeaderProtectionKey',
  'ContentPaddingAddition',

  'RekeyAfterTime',
  'RekeyTimeout',
  'RejectAfterTime',
  'KeepaliveTimeout',
  'MaxHandshakeAttempts',

  'RandomTrailers',
  'DisableCookies',
])

function createAmneziaOptions(
  iface: Record<string, string>,
  detectedVersion: DetectedAmneziaVersion
): Record<string, string | number | boolean> {
  const options: Record<string, string | number | boolean> = {
    version: detectedVersion.version === '3.0' || detectedVersion.version === '3.1' ? 3 : 2,
  }

  if (detectedVersion.version !== '1.5' && hasAny(iface, ['J1', 'J2', 'J3', 'Itime'])) {
    throw new Error('J1, J2, J3 и Itime поддерживаются только для AmneziaWG 1.5')
  }

  for (const key of AMNEZIA_OPTIONS) {
    const value = iface[key]

    if (value == null) continue
    if (value === '') throw new Error(`Пустое значение ${key}`)

    const mihomoKey = toMihomoKey(key)

    if (key === 'RandomTrailers' || key === 'DisableCookies') {
      const normalized = value.toLowerCase()

      if (!['true', 'false', 'on', 'off', '1', '0'].includes(normalized)) throw new Error(`Некорректное значение ${key}`)
      options[mihomoKey] = normalized === 'true' || normalized === 'on' || normalized === '1'

      continue
    }

    if (
      key === 'Itime' ||
      key === 'Jc' ||
      key === 'Jmin' ||
      key === 'Jmax' ||
      key === 'S1' ||
      key === 'S2' ||
      key === 'S3' ||
      key === 'S4'
    ) {
      options[mihomoKey] = parseNumber(value, key)
      continue
    }

    if (
      /^H[1-4]$/.test(key) ||
      ['ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts'].includes(
        key
      )
    ) {
      const parts = value.split('-')
      if (parts.length > 2 || parts.some((part) => !/^\d+$/.test(part))) throw new Error(`Некорректный диапазон ${key}`)
      const numbers = parts.map((part) => parseNumber(part, key, 0, 4294967295))
      if (numbers.length === 2 && numbers[0] > numbers[1]) throw new Error(`Некорректный диапазон ${key}`)
    }
    options[mihomoKey] = value
  }

  return options
}

function indentYaml(yaml: string, spaces: number): string {
  const indentation = ' '.repeat(spaces)

  return yaml
    .split('\n')
    .map((line) => (line ? indentation + line : line))
    .join('\n')
}

function addMtuComment(yaml: string): string {
  return yaml.replace(/^(\s*)(mtu:\s+\S+)$/gm, '$1# В случае недоступности сети, попробуйте увеличить MTU до 1420 или 1500\n$1$2')
}

function convertToMihomo(config: AmneziaConfig, fileName: string): string {
  const iface = config.interface

  const address = splitList(iface.Address)
  const dns = splitList(iface.DNS)
  const ipv4 = address.filter((item) => !item.includes(':'))
  const ipv6 = address.filter((item) => item.includes(':'))
  if (ipv4.length > 1 || ipv6.length > 1) throw new Error('Mihomo поддерживает только один адрес каждого семейства')

  if (!address.length) {
    throw new Error('В [Interface] отсутствует Address')
  }

  if (!iface.PrivateKey) {
    throw new Error('В [Interface] отсутствует PrivateKey')
  }

  const proxies = config.peers.map((peer, index) => {
    if (!peer.Endpoint) {
      throw new Error(`[Peer ${index + 1}] отсутствует Endpoint`)
    }

    if (!peer.PublicKey) {
      throw new Error(`[Peer ${index + 1}] отсутствует PublicKey`)
    }

    const { server, port } = parseEndpoint(peer.Endpoint)

    const proxy: Record<string, unknown> = {
      name: config.peers.length === 1 ? fileName.replace(/\.[^.]+$/, '') : `${fileName.replace(/\.[^.]+$/, '')}_${index + 1}`,

      type: 'wireguard',

      server,
      port,

      ...(ipv4[0] ? { ip: ipv4[0] } : {}),
      ...(ipv6[0] ? { ipv6: ipv6[0] } : {}),

      'private-key': iface.PrivateKey,
      'public-key': peer.PublicKey,

      udp: true,

      mtu: iface.MTU ? parseNumber(iface.MTU, 'MTU', 1, 65535) : 1280,
    }

    if (dns.length) {
      proxy.dns = dns
    }

    const allowedIps = splitList(peer.AllowedIPs)

    if (allowedIps.length) {
      // Mihomo only applies allowed-ips in its peers path.
      proxy.peers = [
        {
          server,
          port,
          'public-key': peer.PublicKey,
          ...(peer.PresharedKey ? { 'pre-shared-key': peer.PresharedKey } : {}),
          'allowed-ips': allowedIps,
        },
      ]
      delete proxy.server
      delete proxy.port
      delete proxy['public-key']
    }

    if (peer.PresharedKey && !allowedIps.length) {
      proxy['pre-shared-key'] = peer.PresharedKey
    }

    if (peer.PersistentKeepalive) {
      proxy['persistent-keepalive'] = parseNumber(peer.PersistentKeepalive, 'PersistentKeepalive', 0, 65535)
    }

    const amneziaOptions = createAmneziaOptions(iface, config.detectedVersion)

    if (Object.keys(amneziaOptions).length) {
      proxy['amnezia-wg-option'] = amneziaOptions
    }

    return proxy
  })

  const yaml = jsyaml.dump(proxies, {
    noRefs: true,
    lineWidth: -1,
  })

  const indentedYaml = indentYaml(yaml, 2)

  if (!iface.MTU) {
    return addMtuComment(indentedYaml)
  }

  return indentedYaml
}

export function importAmnezia(content: string, fileName: string): { yaml: string; detectedVersion: DetectedAmneziaVersion } {
  const config = parseAmneziaConfig(content)
  return { yaml: convertToMihomo(config, fileName), detectedVersion: config.detectedVersion }
}
