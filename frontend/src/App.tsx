import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { LoginForm } from './components/auth/Login'
import type { CodeMirrorRef } from './components/configuration/CodeMirror'
import { ConfigPanel } from './components/configuration/ConfigPanel'
import { LogPanel } from './components/log/LogPanel'
import { ImportModal } from './components/modals/AddOutbound'
import { GeoScanModal } from './components/modals/GeoScan'
import { RouteTesterModal } from './components/modals/RouteTester'
import { CoreManageModal } from './components/modals/CoreManagement'
import { ImportAmneziaModal } from './components/modals/ImportAmnezia'
import { SettingsModal } from './components/modals/Settings'
import { TemplateModal } from './components/modals/Templates'
import { UpdateModal } from './components/modals/Update'
import { CompatibilityCheck } from './components/status/CompatibilityCheck'
import { LanGatewayStatus } from './components/status/LanGatewayStatus'
import { ManagedInputs } from './components/status/ManagedInputs'
import { StatusBar } from './components/status/StatusBar'
import { Button } from './components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from './components/ui/dialog'
import { Toast } from './components/ui/toast'
import { subscriptionUrl } from './lib/uri-policy'
import { MAX_IMPORT_BYTES } from './lib/input-limits'
import { listMihomoTakenNames, replaceMihomoProvider, replaceMihomoProxy } from './lib/mihomoReplace'
import { operationKey } from './lib/operation-key'
import {
  applyProfile,
  listProfiles,
  loadProfile,
  prepareProfile,
  preparationMessages,
  refreshAppliedProvider,
  saveProfile,
  validateProfile,
  type Profile,
} from './lib/profile-adapter'
import { bindProviderToGroup, insertMihomoItem } from './lib/profile-insertion'
import { controlStatusFromReply, loadPlatformStatus, loadControlStatus, resumeAfterReinstall, type ControlStatus, type ManagedInputStatus } from './lib/runtime-adapter'
import { apiCall } from './lib/api'
import { restartManagedService, ServiceError, startLanService, stopLanService } from './lib/service-control'
import { getAppState, showToast, syncClashApiPort, useAppActions, useAppContext, useModalContext, useSettings } from './lib/store'
import { applyEmojiFont, applyTheme, THEME_MEDIA_QUERY } from './lib/theme'
import type { Config } from './lib/types'
import { nextPhase, selfReleases, takePendingUpdate, type SelfCatalog, type SelfStatus } from './lib/self-update'
import { parseDocument } from 'yaml'

type AuthState = 'loading' | 'login' | 'setup' | 'trusted' | 'error'
const UI_VERSION = '1.4.3'
const DEFAULT_PROFILE = 'mixed-port: 7890\nmode: rule\nlog-level: info\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n'

function profileIdFromFile(file: string): string {
  return file.split('/').pop()?.replace(/\.(yaml|yml)$/i, '') ?? ''
}
function profileFile(id: string): string {
  return id === 'config' ? 'config.yaml' : `${id}.yaml`
}
function toConfig(profile: Profile): Config {
  return {
    file: profileFile(profile.id),
    content: profile.source,
    savedContent: profile.source,
    isDirty: false,
    revision: profile.revision,
  }
}

function Workspace() {
  const { dispatch } = useAppActions()
  const { modals } = useModalContext()
  const theme = useSettings((s) => s.theme)
  const emojiFont = useSettings((s) => s.emojiFont)
  const store = useAppState()
  const editorRef = useRef<CodeMirrorRef | null>(null)
  const configActionsRef = useRef<{ switchTab: (index: number) => void; getActiveIndex: () => number }>({
    switchTab: () => {},
    getActiveIndex: () => 0,
  })
  const revisions = useRef<Record<string, string>>({})
  const [capabilities, setCapabilities] = useState<string[]>([])
  const [resumeRequestId, setResumeRequestId] = useState<string | null>(null)
  const [networkState, setNetworkState] = useState('unknown')
  const [recoveryNotice, setRecoveryNotice] = useState<ControlStatus['recoveryNotice']>(undefined)
  const [remoteCheck, setRemoteCheck] = useState<ControlStatus['remoteCheck']>(undefined)
  const [statusStale, setStatusStale] = useState(false)
  const [managedInputs, setManagedInputs] = useState<ManagedInputStatus | null>(null)
  const statusEpoch = useRef(0)
  const ownerAction = useRef(false)
  const lastStatus = useRef<ControlStatus | null>(null)
  const statusRequest = useRef<{ epoch: number; promise: Promise<ControlStatus | null> } | null>(null)
  const [appliedProfile, setAppliedProfile] = useState<string | null>(null)
  const [activeFile, setActiveFile] = useState('')
  const [profileRows, setProfileRows] = useState<Record<string, Profile>>({})
  const [appInfoOpen, setAppInfoOpen] = useState(false)
  const [profileNotice, setProfileNotice] = useState('')
  const [appInfo, setAppInfo] = useState<{
    ui_base_version: string
    package_version: string
    build_id: string
    upstream_commit: string
    management_scope?: string
  } | null>(null)

  useEffect(() => {
    applyTheme(theme)
    if (theme === 'auto') {
      const media = window.matchMedia(THEME_MEDIA_QUERY)
      const sync = () => applyTheme('auto')
      media.addEventListener('change', sync)
      return () => media.removeEventListener('change', sync)
    }
  }, [theme])
  useEffect(() => applyEmojiFont(emojiFont), [emojiFont])

  const refreshConfigs = useCallback(async (): Promise<Config[]> => {
    dispatch({ type: 'SET_CONFIGS_LOADING', loading: true })
    let ids = await listProfiles()
    if (ids.length === 0) {
      const created = await saveProfile('config', DEFAULT_PROFILE, null)
      ids = [created.id]
    }
    const profiles = await Promise.all(ids.map((id) => loadProfile(id)))
    const nextRows: Record<string, Profile> = {}
    const configs = profiles.map((profile) => {
      nextRows[profile.id] = profile
      const draft = getAppState().configs.find((item) => item.file === profileFile(profile.id) && item.isDirty)
      return draft ?? toConfig(profile)
    })
    revisions.current = Object.fromEntries(configs.map((config) => [profileIdFromFile(config.file), config.revision ?? nextRows[profileIdFromFile(config.file)].revision]))
    setProfileRows(nextRows)
    dispatch({ type: 'SET_CONFIGS', configs })
    return configs
  }, [dispatch])

  const publishStatus = useCallback((status: ControlStatus) => {
    lastStatus.current = status
    setManagedInputs(status.inputs ?? null)
    setStatusStale(false)
    if (!ownerAction.current) dispatch({ type: 'SET_SERVICE_STATUS', status: status.running === true ? 'running' : status.running === false ? 'stopped' : 'unknown' })
    syncClashApiPort()
    setCapabilities(status.capabilities)
    setResumeRequestId(status.resumeRequestId)
    setAppliedProfile(status.activeProfileId ?? null)
    setNetworkState(status.networkState ?? 'unknown')
    setRecoveryNotice(status.recoveryNotice)
    setRemoteCheck(status.remoteCheck)
  }, [dispatch])
  const refreshStatus = useCallback((): Promise<ControlStatus | null> => {
    const epoch = statusEpoch.current
    if (statusRequest.current?.epoch === epoch) return statusRequest.current.promise
    const restoreServiceStatus = (status: ControlStatus | null) => {
      if (!ownerAction.current) dispatch({ type: 'SET_SERVICE_STATUS', status: status?.running === true ? 'running' : status?.running === false ? 'stopped' : 'unknown' })
    }
    const promise = (async () => { try {
      const status = await loadControlStatus()
      if (epoch !== statusEpoch.current) return null
      if (status.stale || status.running === null || status.networkState === 'unknown') {
        setStatusStale(true)
        restoreServiceStatus(lastStatus.current)
        return status
      }
      publishStatus(status)
      return status
    } catch {
      if (epoch !== statusEpoch.current) return null
      setStatusStale(true)
      restoreServiceStatus(lastStatus.current)
      return null
    } finally { if (statusRequest.current?.epoch === epoch) statusRequest.current = null } })()
    statusRequest.current = { epoch, promise }
    return promise
  }, [dispatch, publishStatus])
  const beginStatusAction = useCallback(() => { statusEpoch.current++; ownerAction.current = true }, [])
  const endStatusAction = useCallback((verified?: ControlStatus) => {
    statusEpoch.current++
    ownerAction.current = false
    if (verified) publishStatus(verified)
  }, [publishStatus])
  useEffect(() => {
    let disposed = false
    let timer: ReturnType<typeof setTimeout>
    const poll = async () => {
      await refreshStatus()
      if (!disposed) timer = setTimeout(() => void poll(), 3000)
    }
    void poll()
    return () => { disposed = true; clearTimeout(timer) }
  }, [refreshStatus])

  async function serviceAction(action: 'start' | 'stop' | 'restart') {
    let verified: ControlStatus | undefined
    beginStatusAction()
    dispatch({
      type: 'SET_SERVICE_STATUS',
      status: 'pending',
      pendingText:
        action === 'stop'
          ? 'Остановка…'
          : appInfo?.management_scope === 'tailscale_admin'
            ? action === 'restart' ? 'Перезапуск и проверка через Tailscale…' : 'Запуск и проверка через Tailscale…'
            : action === 'restart' ? 'Перезапуск…' : 'Запуск…',
    })
    try {
      const status = action === 'restart' ? await restartManagedService() : action === 'stop' ? await stopLanService() : await startLanService()
      verified = controlStatusFromReply(status)
      showToast(action === 'stop' ? 'Mihomo остановлен. Прямое соединение восстановлено.' : action === 'restart' ? 'Выбранные режимы перезапущены.' : 'Шлюз LAN запущен по правилам YAML.', 'success')
    } catch (error) {
      const code = error instanceof Error ? error.message : String(error)
      const messages: Record<string, string> = {
        NETWORK_MODULES_MISSING: 'Для перехвата нужны модули kmod-nft-tproxy и kmod-nft-socket из репозитория вашей версии OpenWrt.',
        NETWORK_FIREWALL_CONFLICT: 'Действующие правила другого перехватчика конфликтуют с Mihomo. Перехват XkeenWRT не включён.',
        NETWORK_DNS_UNSUPPORTED: 'Текущая схема DNS не прошла проверку: проверьте upstream и работающие DNS-службы.',
        NETWORK_PREREQUISITES: 'Не готовы системные зависимости или служба аварийного восстановления. Перехват не включён.',
        NOT_READY: 'Перехват LAN не готов. Проверьте состояние сети и наличие модулей TPROXY.',
        UNSUPPORTED: 'Текущая схема LAN, DNS или других перехватчиков несовместима с запуском. Сеть не была переключена.',
        CONFLICT: 'Примените сохранённый профиль; если сервис уже работает с ошибкой — остановите его и запустите снова.',
        NETWORK_REMOTE_DNS: 'Проверка через Tailscale: шлюзовый DNS не ответил. Перехват снят, LAN работает напрямую.',
        NETWORK_REMOTE_EGRESS: 'Проверка через Tailscale: ни один прокси не вышел в интернет. Перехват снят, LAN работает напрямую.',
        NETWORK_MANAGEMENT: 'Tailscale-вход изменился или недоступен: обновите страницу панели.',
      }
      showToast(messages[code] || (error instanceof ServiceError ? error.serverText : undefined) || code, 'error')
    } finally {
      endStatusAction(verified)
      void refreshStatus()
    }
  }

  const refreshVersion = useCallback(async () => {
    try {
      const result = await apiCall<{ installedVersion?: string | null; integrity?: string }>('GET', 'core/catalog')
      const version = result.integrity === 'verified' ? result.installedVersion ?? '' : ''
      dispatch({
        type: 'SET_CORE_INFO',
        currentCore: 'mihomo',
        coreVersions: { mihomo: version },
        availableCores: version ? ['mihomo'] : [],
      })
    } catch {
      dispatch({ type: 'SET_CORE_INFO', currentCore: 'mihomo', coreVersions: { mihomo: '' }, availableCores: [] })
    }
  }, [dispatch])

  useEffect(() => {
    dispatch({ type: 'SET_CORE_INFO', currentCore: 'mihomo', coreVersions: { mihomo: '' }, availableCores: [] })
    void apiCall<typeof appInfo & { success: boolean }>('GET', 'app-info')
      .then((info) => {
        setAppInfo(info)
        const version = info.package_version === 'development' ? `${info.ui_base_version} preview` : info.package_version
        dispatch({ type: 'SET_VERSION', version, isOutdatedUI: false, isOutdatedCore: false })
        if (info.package_version === 'development') return
        // A newer release lights up the version button, as in XKeen UI; silence on any failure.
        void apiCall<SelfCatalog>('GET', 'self/catalog')
          .then((catalog) => {
            if (selfReleases(catalog).length) dispatch({ type: 'SET_VERSION', version, isOutdatedUI: true, isOutdatedCore: false })
          })
          .catch(() => {})
      })
      .catch(() => dispatch({ type: 'SET_VERSION', version: 'Версия недоступна', isOutdatedUI: false, isOutdatedCore: false }))
    void refreshConfigs().catch((error) => {
      dispatch({ type: 'SET_CONFIGS', configs: [] })
      showToast(error instanceof Error ? error.message : 'Не удалось загрузить профили', 'error')
    })
    void refreshVersion()
    // Result of a panel self-update whose restart required a new sign-in.
    const pendingUpdate = takePendingUpdate()
    if (pendingUpdate) {
      let attempts = 0
      const readResult = () =>
        apiCall<SelfStatus>('GET', 'self/update/status')
          .then((reply) => {
            const phase = nextPhase(pendingUpdate, reply)
            if ((phase.kind === 'running' || phase.kind === 'restarting') && ++attempts < 30) {
              window.setTimeout(readResult, 2000)
            } else if (phase.kind === 'done') {
              showToast(`XkeenWRT ${pendingUpdate} установлен. Запустите шлюз кнопкой «Запустить».`, 'success')
            } else {
              showToast(phase.kind === 'failed' ? phase.message : 'Результат обновления неизвестен', 'error')
            }
          })
          .catch(() => showToast('Не удалось прочитать результат обновления', 'error'))
      void readResult()
    }
    void loadPlatformStatus()
      .then((status) => setCapabilities(status.capabilities))
      .catch(() => setCapabilities([]))
  }, [dispatch, refreshConfigs, refreshStatus, refreshVersion])

  const saveDraft = useCallback(
    async (config: Config, content: string): Promise<Profile> => {
      const id = profileIdFromFile(config.file)
      if (!id) throw new Error('Не удалось определить файл профиля.')
      const currentRevision = revisions.current[id] ?? config.revision ?? null
      const saved = await saveProfile(id, content, currentRevision)
      revisions.current[id] = saved.revision
      setProfileRows((current) => ({ ...current, [id]: saved }))
      const configs = getAppState().configs.map((item) =>
        item.file === config.file ? { ...toConfig(saved), file: config.file } : item
      )
      dispatch({ type: 'SET_CONFIGS', configs })
      editorRef.current?.setSavedContent(content)
      return saved
    },
    [dispatch]
  )

  const onSaveConfig = useCallback(
    async (config: Config, content: string) => {
      await saveDraft(config, content)
      showToast('Черновик сохранён')
    },
    [saveDraft]
  )

  const onApplyConfig = useCallback(
    async (config: Config, content: string) => {
      const id = profileIdFromFile(config.file)
      if (!id) throw new Error('Не удалось определить профиль.')
      beginStatusAction()
      dispatch({ type: 'SET_SERVICE_STATUS', status: 'pending', pendingText: 'Проверка и применение...' })
      try {
        setProfileNotice('Сохранение черновика…')
        const saved = await saveDraft(config, content)
        setProfileNotice('Prepare: подготовка YAML без загрузки подписок…')
        const preparation = await prepareProfile(id, saved.revision)
        if (preparation.profile_id !== id || preparation.revision !== saved.revision || preparation.source !== saved.source) {
          throw new Error('Подготовленный профиль не соответствует сохранённой ревизии.')
        }
        const preparationState = preparationMessages(preparation)
        setProfileNotice(preparationState.messages.join(' '))
        if (preparationState.blocked) throw new Error('Prepare: ' + preparationState.messages.join(' '))
        if (!capabilities.includes('profile_validate')) throw new Error('Validate недоступен в этой среде. На OpenWrt установите Mihomo через кнопку «Mihomo» и проверьте состояние служб.')
        setProfileNotice('Validate: загрузка подписок и правил, проверка политики, затем mihomo -t…')
        const validation = await validateProfile(id, saved.revision)
        if (validation.status !== 'valid' || validation.profile_id !== id || validation.revision !== saved.revision) {
          throw new Error('Проверка Mihomo не подтвердила сохранённую ревизию.')
        }
        if (!capabilities.includes('profile_apply_manual')) throw new Error('Проверка пройдена, но ручное применение пока недоступно.')
        setProfileNotice('Apply: применение проверенного снимка…')
        const transaction = await applyProfile(id, saved.revision, validation.candidate_id, operationKey())
        setProfileNotice(transaction.state === 'confirmed' ? 'Профиль подтверждён. Шлюз LAN продолжает работу с выбранными входами.' : 'Профиль применён. Нажмите «Запустить» для шлюза LAN или отдельно включите HTTP/SOCKS.')
        showToast(transaction.state === 'confirmed' ? 'Новый профиль шлюза подтверждён.' : 'Профиль применён без включения остановленных режимов.')
        await refreshStatus()
        await refreshVersion()
      } catch (error) {
        setProfileNotice(error instanceof Error ? error.message : 'Ошибка применения профиля')
        throw error
      } finally {
        endStatusAction()
        await refreshStatus()
      }
    },
    [capabilities, dispatch, refreshStatus, refreshVersion, saveDraft, beginStatusAction, endStatusAction]
  )

  const activeConfig = useMemo(() => store.configs.find((config) => config.file === activeFile) ?? store.configs[0], [store.configs, activeFile])
  const activeId = activeConfig ? profileIdFromFile(activeConfig.file) : ''
  const activeProfile = activeId ? profileRows[activeId] ?? null : null
  const activeDirty = !!activeConfig?.isDirty

  const providerEditable = useCallback((kind: 'proxy' | 'rule', name: string) => {
    if (!activeProfile || activeProfile.id !== appliedProfile || activeDirty) return false
    try {
      const doc = parseDocument(activeProfile.source)
      const section = kind === 'proxy' ? 'proxy-providers' : 'rule-providers'
      return doc.getIn([section, name, 'type']) === 'file' && doc.getIn([section, name, 'format']) !== 'mrs'
    } catch { return false }
  }, [activeProfile, appliedProfile, activeDirty])

  const loadProviderContent = useCallback(async (kind: 'proxy' | 'rule', name: string) => {
    const status = await loadControlStatus()
    const id = status.activeProfileId, revision = status.activeProfileRevision
    if (!id || !revision) throw new Error('Нет применённого профиля для просмотра провайдера.')
    const query = new URLSearchParams({expected_revision: revision})
    const listed = await apiCall<{providers: Array<{id: string; name: string}>}>('GET', `profiles/${encodeURIComponent(id)}/providers?${query}`)
    const provider = listed.providers.find(p => p.name === name && p.id.startsWith(kind + '-'))
    if (!provider) throw new Error('Провайдер отсутствует в применённой ревизии.')
    const result = await apiCall<{content: string}>('GET', `profiles/${encodeURIComponent(id)}/providers/${encodeURIComponent(provider.id)}/content?${query}`)
    return result.content
  }, [])

  const addProvider = async (kind: 'proxy' | 'rule', name: string, url: string, file: File | null, behavior: string) => {
    if (!activeProfile || !activeConfig || activeDirty) throw new Error('Выберите профиль и сохраните черновик перед загрузкой источника.')
    if (!name.trim() || name.length > 128 || /[\x00-\x1f]/.test(name)) throw new Error('Укажите корректное имя источника')
    const doc = parseDocument(activeProfile.source)
    const section = kind === 'proxy' ? 'proxy-providers' : 'rule-providers'
    if (doc.hasIn([section, name])) throw new Error('Источник с таким именем уже есть')
    let source: Record<string, unknown>
    if (file) {
      if (file.size === 0 || file.size > 8 * 1024 * 1024) throw new Error('Допустим файл от 1 байта до 8 MiB')
      const bytes = new Uint8Array(await file.arrayBuffer())
      let binary = ''
      for (let at = 0; at < bytes.length; at += 8192) binary += String.fromCharCode(...bytes.subarray(at, at + 8192))
      const uploaded = await apiCall<{ resource: { id: string; format: string } }>('POST', `profiles/${encodeURIComponent(activeProfile.id)}/resources`, { expected_revision: activeProfile.revision, name: file.name, content_base64: btoa(binary) })
      source = { type: 'file', path: `resources/${uploaded.resource.id}` }
      if (kind === 'rule') source.format = uploaded.resource.format === 'txt' ? 'text' : uploaded.resource.format === 'mrs' ? 'mrs' : 'yaml'
    } else {
      const parsed = new URL(subscriptionUrl(url))
      source = { type: 'http', url: parsed.href }
      if (kind === 'rule') source.format = parsed.pathname.endsWith('.mrs') ? 'mrs' : parsed.pathname.endsWith('.txt') ? 'text' : 'yaml'
    }
    if (kind === 'rule') source.behavior = behavior
    doc.setIn([section, name], source)
    if (!editorRef.current) throw new Error('Откройте редактор конфигурации перед добавлением источника.')
    editorRef.current.replaceAll(doc.toString())
    showToast('Источник добавлен в черновик. Добавьте его в use группы или правило RULE-SET, затем примените профиль.')
  }

  const saveProviderContent = useCallback(async (kind: 'proxy' | 'rule', name: string, content: string) => {
    if (!activeProfile || !providerEditable(kind, name)) throw new Error('Удалённую подписку нельзя перезаписать. Для локального редактирования сначала сохраните профиль.')
    const bytes = new TextEncoder().encode(content)
    if (bytes.length > MAX_IMPORT_BYTES) throw new Error('Файл провайдера превышает лимит размера')
    let binary = ''
    for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192))
    const uploaded = await apiCall<{ success: boolean; resource: { id: string } }>('POST', `profiles/${encodeURIComponent(activeProfile.id)}/resources`, { expected_revision: activeProfile.revision, name: 'provider.yaml', content_base64: btoa(binary) })
    const doc = parseDocument(activeProfile.source)
    const section = kind === 'proxy' ? 'proxy-providers' : 'rule-providers'
    doc.setIn([section, name, 'path'], `resources/${uploaded.resource.id}`)
    if (kind === 'rule') doc.setIn([section, name, 'format'], 'yaml')
    if (!activeConfig) throw new Error('Профиль не выбран')
    await onSaveConfig(activeConfig, doc.toString())
    showToast(`Локальный провайдер ${name} сохранён. Нажмите «Применить» для обновления ядра.`)
  }, [activeProfile, activeConfig, providerEditable, onSaveConfig])

  const refreshProvider = useCallback(async (kind: 'proxy' | 'rule', name: string) => {
    const result = await refreshAppliedProvider(kind, name, operationKey())
    showToast(`Провайдер обновлён в применённом профиле «${result.profileId}» (${result.transaction.state}). Черновик редактора сохранён.`)
    await refreshStatus(); await refreshVersion()
  }, [refreshStatus, refreshVersion])

  const openModal = (modal: string) => dispatch({ type: 'SHOW_MODAL', modal: modal as never, show: true })
  const addToConfig = (content: string, type: string, position: 'start' | 'end', group?: string) => {
    const config = getAppState().configs[configActionsRef.current.getActiveIndex()]
    if (!config || !editorRef.current) { showToast('Откройте редактор конфигурации перед вставкой.', 'error'); return false }
    try {
      let inserted = insertMihomoItem(editorRef.current.getValue(), content, type, position)
      const name = type === 'proxy-provider' ? Object.keys(parseDocument(content).toJS())[0] : ''
      if (name && group) inserted = bindProviderToGroup(inserted, name, group)
      editorRef.current.replaceAll(inserted)
      const line = inserted.split('\n').findIndex(row => name ? row.trimStart().startsWith(name + ':') || row.includes(JSON.stringify(name) + ':') : row.includes('name:')) + 1
      editorRef.current.revealLine(Math.max(1, line))
      showToast('Добавлено в черновик. Сохранение и применение выполняются отдельно.')
      return true
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Не удалось добавить элемент.', 'error')
      return false
    }
  }
  const replaceInConfig = (kind: 'proxy' | 'provider', content: string, oldName: string, renameRefs: boolean) => {
    if (!editorRef.current) { showToast('Откройте редактор конфигурации перед заменой.', 'error'); return false }
    try {
      const result =
        kind === 'proxy'
          ? replaceMihomoProxy(editorRef.current.getValue(), oldName, content, { renameRefs })
          : replaceMihomoProvider(editorRef.current.getValue(), oldName, content, { renameRefs })
      editorRef.current.replaceAll(result.text)
      editorRef.current.revealLine(result.line)
      showToast('Элемент заменён в черновике. Сохранение и применение выполняются отдельно.')
      return true
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Не удалось заменить элемент.', 'error')
      return false
    }
  }
  const generate = (uri: string, excludeName?: string) => {
    const currentText = editorRef.current?.getValue() ?? activeConfig?.content ?? ''
    const excluded = excludeName ? listMihomoTakenNames(currentText).filter((name) => name !== excludeName) : currentText
    return (window as Window & { generateConfigForCore?: (uri: string, core: string, existing: string | string[]) => { content: string; type: string } | null })
      .generateConfigForCore?.(uri, 'mihomo', excluded) ?? null
  }
  const importTemplate = async (text: string) => {
    if (new TextEncoder().encode(text).length > MAX_IMPORT_BYTES) throw new Error('Шаблон превышает ограничение 1 MiB.')
    if (activeDirty && !confirm('Заменить несохранённые изменения?')) throw new Error('Замена отменена; черновик сохранён.')
    if (!editorRef.current) throw new Error('Откройте редактор конфигурации перед импортом.')
    editorRef.current.replaceAll(text)
  }

  const resume = async () => {
    if (!resumeRequestId || !capabilities.includes('core_control')) return
    try {
      await resumeAfterReinstall(resumeRequestId)
      showToast('Возобновлено после переустановки. Mihomo оставлен остановленным.')
      await refreshStatus()
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Не удалось возобновить runtime.', 'error')
    }
  }

  const remoteAdmin = appInfo?.management_scope === 'tailscale_admin'
  const servicePending = store.serviceStatus === 'pending' || store.serviceStatus === 'loading'

  return (
    <div className="bg-muted dark:bg-background min-h-dvh p-3">
      <main className="mx-auto flex max-w-7xl flex-col gap-3">
        <StatusBar
          remoteAdmin={remoteAdmin}
          startDisabledReason={!store.coreVersions.mihomo ? 'Сначала установите Mihomo' : resumeRequestId ? 'Сначала возобновите управление после переустановки' : !appliedProfile ? 'Сначала примените профиль в редакторе' : undefined}
          networkState={networkState}
          recoveryNotice={recoveryNotice}
          remoteCheck={remoteCheck}
          stale={statusStale}
          appliedProfile={appliedProfile}
          onOpenCoreManage={() => openModal('showCoreManageModal')}
          onOpenSettings={() => openModal('showSettingsModal')}
          onStart={() => void serviceAction('start')}
          onStop={() => void serviceAction('stop')}
          onOpenUpdate={(core) => {
            if (core === 'self') {
              setAppInfoOpen(true)
              return
            }
            dispatch({ type: 'SET_UPDATE_MODAL_CORE', core })
            openModal('showUpdateModal')
          }}
          onLogout={() => {}}
        />
        {resumeRequestId && (
          <div className="bg-card flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm">
            <span>Требуется подтверждённое возобновление после переустановки. Ядро останется остановленным.</span>
            <Button size="sm" variant="outline" onClick={() => void resume()}>
              Возобновить
            </Button>
          </div>
        )}
        {(profileNotice || !store.coreVersions.mihomo) && <div role="status" className="border-border bg-card rounded-lg border p-3 text-sm">
          {profileNotice && <p>{profileNotice}</p>}
          {!store.coreVersions.mihomo && <div className="flex items-center justify-between gap-3"><span>Mihomo не установлен или его целостность не подтверждена. Редактор и сохранение доступны; Prepare не загружает подписки и не проверяет их ядром. На Validate загрузка проверяется до запуска mihomo -t, без применения.</span><Button size="sm" onClick={() => openModal('showCoreManageModal')}>Установить Mihomo</Button></div>}
        </div>}
        <ConfigPanel
          onOpenImport={() => openModal('showImportModal')}
          onOpenImportAmnezia={() => openModal('showImportAmneziaModal')}
          onOpenTemplate={() => openModal('showTemplateModal')}
          onOpenGeoScan={() => openModal('showGeoScanModal')}
          onOpenRouteTest={() => openModal('showRouteTestModal')}
          onOpenBackups={() => openModal('showBackupsModal')}
          onRefreshConfigs={refreshConfigs}
          editorRef={editorRef}
          configActionsRef={configActionsRef}
          onSaveConfig={onSaveConfig}
          onApplyConfig={onApplyConfig}
          onRefreshProvider={refreshProvider}
          onLoadProviderContent={loadProviderContent}
          onSaveProviderContent={saveProviderContent}
          onProviderEditable={providerEditable}
          onAddProvider={addProvider}
          onActiveFileChange={setActiveFile}
          networkControls={
            <div className="bg-card shrink-0 rounded-xl border px-3 py-2 text-sm">
              <p>Все устройства LAN обрабатываются Mihomo по правилам YAML после запуска сервиса.</p>
              <p className="text-muted-foreground text-xs">Stop возвращает прямое соединение. Локальные адреса и доступ к роутеру сохраняются. Внешний IPv6 при работе перехвата блокируется.</p>
            </div>
          }
        />
        <LogPanel />
        <ImportModal
          activeDraft={activeConfig?.content ?? null}
          onGenerate={generate}
          onAddToConfig={addToConfig}
          onReplace={replaceInConfig}
        />
        <ImportAmneziaModal onAddToConfig={addToConfig} />
        <TemplateModal onImport={importTemplate} />
        {modals.showGeoScanModal && <GeoScanModal profileId={activeId} revision={activeProfile?.revision ?? ''} />}
        {modals.showRouteTestModal && <RouteTesterModal profileId={activeId} revision={activeProfile?.revision ?? ''} dirty={activeDirty} />}
        {modals.showCoreManageModal && (
          <CoreManageModal
            onSwitchCore={() => showToast('В этом порте доступно только Mihomo.', 'error')}
            onOpenUpdate={(core) => {
              dispatch({ type: 'SET_UPDATE_MODAL_CORE', core })
              openModal('showUpdateModal')
            }}
          />
        )}
        {modals.showUpdateModal && <UpdateModal onInstalled={() => { void refreshVersion(); void refreshStatus() }} />}
        {modals.showSettingsModal && (
          <SettingsModal
            advanced={
              <ManagedInputs
                inputs={managedInputs}
                stale={statusStale}
                pending={servicePending}
                running={store.serviceStatus === 'running'}
                networkState={networkState}
                applied={!!appliedProfile}
                onRefresh={() => void refreshStatus()}
                remoteAdmin={remoteAdmin}
                onOperationStart={beginStatusAction}
                onOperationEnd={endStatusAction}
                onRestart={() => void serviceAction('restart')}
              />
            }
            diagnostics={
              <div className="space-y-4 py-2">
                <section className="border-border space-y-1 rounded-lg border p-3">
                  <h3 className="font-medium">Текущее состояние шлюза</h3>
                  <LanGatewayStatus networkState={networkState} recoveryNotice={recoveryNotice} remoteCheck={remoteCheck} stale={statusStale} />
                </section>
                <CompatibilityCheck disabled={servicePending} />
              </div>
            }
          />
        )}
        <Dialog open={appInfoOpen} onOpenChange={setAppInfoOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>XKeen UI: сведения о сборке</DialogTitle>
              <DialogDescription>Панель основана на пользовательском интерфейсе XKeen UI {appInfo?.ui_base_version ?? UI_VERSION}.</DialogDescription>
            </DialogHeader>
            <div className="space-y-2 break-all text-sm">
              <p>Версия пакета: {appInfo?.package_version ?? 'Не получена'}</p>
              <p>Build ID: {appInfo?.build_id ?? 'Не получен'}</p>
              <p>Upstream commit: {appInfo?.upstream_commit ?? 'Не получен'}</p>
              <p className="break-normal">Обновление панели: используйте совместимый комплект APK XkeenWRT для OpenWrt 25.12.6, aarch64_cortex-a53. Перед обновлением сохраните бэкап профилей. Установщик Entware здесь не используется.</p>
            </div>
          </DialogContent>
        </Dialog>
        <Toast />
      </main>
    </div>
  )
}

function useAppState() {
  const { state } = useAppContext({ includeConfigs: true })
  return state
}

export default function App() {
  const [auth, setAuth] = useState<AuthState>('loading')
  useEffect(() => {
    fetch('/api/auth/login', { cache: 'no-store' })
      .then(async (response) => {
        if (!response.ok) throw new Error('Не удалось определить режим доступа.')
        return response.json()
      })
      .then((data) => setAuth(data.enabled === false ? 'trusted' : data.authenticated ? 'trusted' : data.has_password ? 'login' : 'setup'))
      .catch(() => setAuth('error'))
  }, [])
  if (auth === 'loading') return <div className="bg-background min-h-dvh p-4 text-sm">Загрузка...</div>
  if (auth === 'error') return <div className="bg-background min-h-dvh p-4 text-sm">Не удалось подключиться к панели.</div>
  if (auth === 'login' || auth === 'setup') {
    return (
      <>
        <LoginForm mode={auth} onAuth={() => setAuth('trusted')} />
        <Toast />
      </>
    )
  }
  return <Workspace />
}
