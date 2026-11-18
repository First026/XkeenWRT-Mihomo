import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Spinner } from '@/components/ui/spinner'
import { IconFileText } from '@tabler/icons-react'
import { useEffect, useState } from 'react'
import { capitalize } from '../../lib/api'
import { useAppContext, useModalContext } from '../../lib/store'
import { cn } from '../../lib/utils'
import { MAX_IMPORT_BYTES } from '../../lib/input-limits'
import { Textarea } from '../ui/textarea'
import { parseDocument } from 'yaml'

const TEMPLATES_URL = 'https://raw.githubusercontent.com/zxc-rv/assets/main/config_templates/templates.json'
let templatesCache: Record<string, { name: string; url: string }[]> | null = null

export function TemplateModal({ onImport }: { onImport: (content: string) => Promise<void> }) {
  const { state, showToast } = useAppContext()
  const { modals, dispatch } = useModalContext()
  const { currentCore } = state
  const [templates, setTemplates] = useState<{ name: string; url: string }[]>([])
  const [selectedUrl, setSelectedUrl] = useState('')
  const [preview, setPreview] = useState('')
  const [loading, setLoading] = useState(false)
  const [importing, setImporting] = useState(false)

  const close = () => dispatch({ type: 'SHOW_MODAL', modal: 'showTemplateModal', show: false })

  useEffect(() => {
    if (modals.showTemplateModal) { setPreview(''); loadTemplates() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modals.showTemplateModal, currentCore])

  async function loadTemplates() {
    if (!templatesCache) {
      setLoading(true)
      try {
        const res = await fetch(TEMPLATES_URL)
        if (!res.ok) throw new Error(res.statusText)
        templatesCache = await res.json()
      } catch {
        showToast('Не удалось загрузить шаблоны', 'error')
        setLoading(false)
        return
      }
      setLoading(false)
    }
    const list = templatesCache?.[currentCore] ?? []
    setTemplates(list)
    if (list.length > 0) setSelectedUrl(list[0].url)
  }

  async function loadPreview() {
    if (!selectedUrl) return
    setImporting(true)
    try {
      const target = new URL(selectedUrl)
      if (target.protocol !== 'https:' || target.hostname !== 'raw.githubusercontent.com' || !target.pathname.startsWith('/zxc-rv/assets/main/config_templates/mihomo/') || target.username || target.password) throw new Error('Источник шаблона не входит в каталог Mihomo')
      const response = await fetch(target, { credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15000) })
      if (!response.ok || !response.body) throw new Error('Не удалось загрузить шаблон')
      const reader = response.body.getReader()
      const chunks: Uint8Array[] = []
      let size = 0
      try {
        for (;;) {
          const { value, done } = await reader.read()
          if (done) break
          size += value.length
          if (size > MAX_IMPORT_BYTES) throw new Error('Шаблон превышает 1 MiB')
          chunks.push(value)
        }
      } finally { await reader.cancel() }
      const all = new Uint8Array(size); let offset = 0
      for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length }
      acceptPreview(new TextDecoder('utf-8', { fatal: true }).decode(all))
    } catch (error) { showToast(error instanceof Error ? error.message : 'Ошибка загрузки', 'error') }
    finally { setImporting(false) }
  }
  function acceptPreview(text: string) {
    if (!text.trim() || new TextEncoder().encode(text).length > MAX_IMPORT_BYTES) throw new Error('Пустой файл или размер больше 1 MiB')
    const doc = parseDocument(text)
    if (doc.errors.length || !doc.contents) throw new Error('Некорректный YAML')
    setPreview(text)
  }
  async function loadFile(file: File | undefined) {
    if (!file) return
    try {
      if (file.size > MAX_IMPORT_BYTES) throw new Error('Файл превышает 1 MiB')
      acceptPreview(await file.text())
    } catch (error) { showToast(error instanceof Error ? error.message : 'Ошибка чтения файла', 'error') }
  }
  async function handleImport() {
    if (!preview) return
    setImporting(true)
    try { await onImport(preview); close() }
    catch (error) { showToast(error instanceof Error ? error.message : 'Ошибка импорта', 'error') }
    finally { setImporting(false) }
  }

  return (
    <Dialog open={modals.showTemplateModal} onOpenChange={(open) => !open && close()}>
      <DialogContent className="w-full max-w-140! p-0!">
        <div className="flex max-h-[90dvh] flex-col gap-4 overflow-hidden p-6">
          <DialogHeader className="shrink-0">
            <DialogTitle className="flex items-center gap-2 pr-8 pb-3">
              <IconFileText size={24} className="text-chart-2" />
              Импорт шаблона
            </DialogTitle>
            <DialogDescription className="flex w-full items-center justify-between">
              <span>
                Выберите готовый шаблон конфигурации для <span className="text-chart-2 font-semibold">{capitalize(currentCore)}</span>
              </span>
              {!loading && <Badge className="h-6 w-6 rounded-full border-blue-500/20 bg-blue-500/10 text-blue-400">{templates.length}</Badge>}
            </DialogDescription>
          </DialogHeader>

          <label className="text-muted-foreground text-xs">Загрузить YAML с компьютера
            <input className="mt-1 block w-full" type="file" accept=".yaml,.yml" onChange={(event) => { void loadFile(event.target.files?.[0]); event.target.value = '' }} />
          </label>
          {preview && <Textarea aria-label="Предпросмотр шаблона" value={preview} readOnly className="min-h-48 font-mono text-xs" />}
          <ScrollArea className={preview ? 'h-40 min-h-0' : 'h-125 min-h-0'} hideScrollbar>
            {loading ? (
              <div className="text-muted-foreground flex min-h-125 flex-col items-center justify-center gap-3">
                <Spinner className="text-chart-2 size-10" />
                <span className="text-sm tracking-normal">Загрузка шаблонов...</span>
              </div>
            ) : templates.length === 0 ? (
              <p className="text-muted-foreground flex min-h-125 items-center justify-center text-sm">Нет доступных шаблонов</p>
            ) : (
              <RadioGroup value={selectedUrl} onValueChange={(value) => { setSelectedUrl(value); setPreview('') }} className="gap-1.5 px-0.5 py-1">
                {templates.map((template, i) => (
                  <div
                    key={i}
                    onClick={() => { setSelectedUrl(template.url); setPreview('') }}
                    className={cn(
                      'flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-3.5 transition-all',
                      selectedUrl === template.url
                        ? 'border-[#60a5fa] bg-linear-to-b from-blue-500/25 to-blue-500/15'
                        : 'border-ring/40 bg-[linear-gradient(135deg,rgba(59,130,246,0.05)_0%,transparent_50%)] from-blue-500/15 to-blue-500/5 hover:border-[#60a5fa] hover:bg-linear-to-b'
                    )}
                  >
                    <RadioGroupItem value={template.url} id={`tpl-${i}`} className="shrink-0" />
                    <span className="text-sm font-medium">{template.name}</span>
                  </div>
                ))}
              </RadioGroup>
            )}
          </ScrollArea>

          <DialogFooter className="shrink-0">
            <Button onClick={preview ? handleImport : loadPreview} disabled={(!selectedUrl && !preview) || importing} className="w-full">
              {importing ? 'Загрузка...' : preview ? 'Заменить черновик' : 'Предпросмотр'}
            </Button>
          </DialogFooter>
        </div>
      </DialogContent>
    </Dialog>
  )
}
