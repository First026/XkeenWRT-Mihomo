import { useEffect, useState } from 'react'
import type { Profile } from '../../../lib/profile-adapter'
import { listManagedProviders, type ManagedProvider } from '../../../lib/provider-adapter'
import { Button } from '../../ui/button'

type List = { key: string; items: ManagedProvider[]; error: string }
export function ManagedProviders({
  available,
  profile,
  dirty,
  busy,
  previewReady,
  onRefresh,
}: {
  available: boolean
  profile: Profile | null
  dirty: boolean
  busy: boolean
  previewReady: boolean
  onRefresh: (id: string) => Promise<void>
}) {
  const [list, setList] = useState<List | null>(null)
  const key = profile && !dirty ? JSON.stringify([profile.id, profile.revision]) : ''
  useEffect(() => {
    if (!available || !profile || dirty) return
    let active = true
    const requestedKey = JSON.stringify([profile.id, profile.revision])
    listManagedProviders(profile.id, profile.revision).then(
      (items) => {
        if (active) setList({ key: requestedKey, items, error: '' })
      },
      (e) => {
        if (active) setList({ key: requestedKey, items: [], error: e instanceof Error ? e.message : 'Список provider недоступен.' })
      }
    )
    return () => {
      active = false
    }
  }, [available, profile, dirty])
  return (
    <section className="bg-card rounded-xl border p-4" aria-label="Обновление provider">
      <h2 className="font-medium">Обновление provider</h2>
      {!available ? (
        <p className="text-muted-foreground mt-1 text-sm">Безопасное обновление provider на этой платформе недоступно.</p>
      ) : !profile || dirty ? (
        <p className="text-muted-foreground mt-1 text-sm">Выберите и сохраните профиль, чтобы увидеть provider.</p>
      ) : (
        <>
          <p className="text-muted-foreground mt-1 text-sm">
            Обновление создаёт проверенный candidate. Применение выполняется отдельно; адреса и файлы не передаются из интерфейса.
          </p>
          {list?.key !== key ? (
            <p className="mt-2 text-sm">Загрузка списка…</p>
          ) : list.error ? (
            <p role="alert" className="text-destructive mt-2 text-sm">
              {list.error}
            </p>
          ) : list.items.length === 0 ? (
            <p className="mt-2 text-sm">В профиле нет управляемых provider.</p>
          ) : (
            <ul className="mt-2 space-y-2">
              {list.items.map((p) => (
                <li key={p.id} className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm break-all">{p.name}</span>
                  <Button size="sm" variant="outline" disabled={busy || !previewReady} onClick={() => void onRefresh(p.id)}>
                    Обновить
                  </Button>
                </li>
              ))}
            </ul>
          )}
          {!previewReady && <p className="text-muted-foreground mt-2 text-sm">Сначала подготовьте YAML и проверьте профиль ядром.</p>}
        </>
      )}
    </section>
  )
}
