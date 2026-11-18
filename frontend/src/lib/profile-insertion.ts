import { listMihomoTakenNames } from './mihomoReplace'
import { isAlias, isMap, isScalar, isSeq, parseDocument, visit, YAMLMap, YAMLSeq } from 'yaml'

/** Insert generated nodes or a provider without guessing at unsupported YAML shapes. */
export function insertMihomoItem(source: string, generated: string, type: string, position: 'start' | 'end'): string {
  const document = parseDocument(source, { uniqueKeys: true })
  const addition = parseDocument(generated, { uniqueKeys: true })
  if (document.errors.length || addition.errors.length || !isMap(document.contents))
    throw new Error('Не удалось разобрать YAML как конфигурацию.')
  const root: YAMLMap = document.contents
  const key = type === 'proxy' ? 'proxies' : type === 'proxy-provider' ? 'proxy-providers' : null
  if (!key) throw new Error('Неизвестный тип элемента.')
  const unsafe = (node: unknown) => {
    let found = false
    if (node)
      visit(node as Parameters<typeof visit>[0], (_key, item) => {
        if (isAlias(item) || (item && typeof item === 'object' && 'anchor' in item && item.anchor)) found = true
      })
    return found
  }
  if (unsafe(addition.contents)) throw new Error('Импорт с YAML-якорями или ссылками не поддерживается.')
  let target = root.get(key, true)
  if (target == null || (isScalar(target) && target.value == null)) {
    root.set(key, type === 'proxy' ? new YAMLSeq() : new YAMLMap())
    target = root.get(key, true)
  }
  if (unsafe(target)) throw new Error('Вставка в коллекцию с YAML-якорями или ссылками не поддерживается.')
  if (type === 'proxy') {
    if (!isSeq(target) || !isSeq(addition.contents) || addition.contents.items.length === 0)
      throw new Error('Ожидался список proxies и хотя бы один прокси.')
    if (target.items.some((p) => !isMap(p) || typeof p.get('name') !== 'string'))
      throw new Error('Не удалось однозначно определить имена прокси.')
    const taken = new Set(listMihomoTakenNames(source))
    for (const item of addition.contents.items) {
      const name = isMap(item) ? item.get('name') : null
      if (typeof name !== 'string' || !name) throw new Error('Не удалось однозначно определить имена прокси.')
      if (taken.has(name)) throw new Error(`Имя «${name}» уже используется.`)
      taken.add(name)
    }
    if (position === 'start') target.items.unshift(...addition.contents.items)
    else target.items.push(...addition.contents.items)
  } else {
    if (!isMap(target) || !isMap(addition.contents) || addition.contents.items.length !== 1)
      throw new Error('Ожидалась таблица proxy-providers и один provider.')
    const pair = addition.contents.items[0]
    if (
      !isScalar(pair.key) ||
      typeof pair.key.value !== 'string' ||
      !pair.key.value ||
      target.items.some((p) => !isScalar(p.key) || typeof p.key.value !== 'string')
    )
      throw new Error('Не удалось однозначно определить имена providers.')
    if (target.has(pair.key.value)) throw new Error(`Provider «${pair.key.value}» уже существует.`)
    if (position === 'start') target.items.unshift(pair)
    else target.items.push(pair)
  }
  return document.toString()
}

export function importGroups(source: string): Array<{name: string; includesProviders: boolean}> {
  const doc = parseDocument(source)
  if (doc.errors.length || !isMap(doc.contents)) return []
  const groups = doc.contents.get('proxy-groups', true)
  if (!isSeq(groups)) return []
  return groups.items.flatMap(g => isMap(g) && typeof g.get('name') === 'string'
    ? [{name: g.get('name') as string, includesProviders: g.get('include-all') === true || g.get('include-all-providers') === true}] : [])
}

/** Link an imported provider atomically with its draft insertion. */
export function bindProviderToGroup(source: string, provider: string, group: string): string {
  const doc = parseDocument(source)
  if (doc.errors.length || !isMap(doc.contents)) throw new Error('Не удалось прочитать группы YAML.')
  const groups = doc.contents.get('proxy-groups', true)
  if (!isSeq(groups)) throw new Error('В черновике нет выбранной группы.')
  const matches = groups.items.filter(g => isMap(g) && g.get('name') === group)
  if (matches.length !== 1 || !isMap(matches[0])) throw new Error('Выбранная группа отсутствует или неоднозначна.')
  const target = matches[0]
  if (target.get('include-all') === true || target.get('include-all-providers') === true) return source
  const use = target.get('use', true)
  if (use !== undefined && (!isSeq(use) || use.anchor || use.items.some(isAlias))) throw new Error('Нельзя изменить use группы с YAML-ссылками или неоднозначным значением.')
  if (target.anchor) throw new Error('Нельзя изменить группу с YAML-якорем автоматически.')
  if (!use) target.set('use', doc.createNode([provider]))
  else if (isSeq(use) && !use.items.some(n => isScalar(n) && n.value === provider)) use.add(provider)
  return doc.toString()
}
