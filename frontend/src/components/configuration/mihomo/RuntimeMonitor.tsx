import { useCallback, useEffect, useState } from 'react'
import { Button } from '../../ui/button'

type Proxy = { name?: string; type?: string; now?: string; all?: string[] }
type Connection = { id: string; metadata?: { host?: string; destinationIP?: string }; chains?: string[] }
async function core<T>(path: string, method = 'GET', body?: object): Promise<T> {
  const r = await fetch(`/api/core/${path}`, {
    method,
    ...(body ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}),
  })
  if (!r.ok) throw new Error(`Mihomo недоступен (HTTP ${r.status}).`)
  if (r.status === 204) return {} as T
  return r.json()
}
export function RuntimeMonitor() {
  const [proxies, setProxies] = useState<Record<string, Proxy>>({})
  const [connections, setConnections] = useState<Connection[]>([])
  const [traffic, setTraffic] = useState('Ожидание данных')
  const [memory, setMemory] = useState('Ожидание данных')
  const [logs, setLogs] = useState<string[]>([])
  const [streams, setStreams] = useState<Record<string, boolean>>({})
  const [error, setError] = useState('')
  const refresh = useCallback(async () => {
    try {
      const [p, c] = await Promise.all([
        core<{ proxies: Record<string, Proxy> }>('proxies'),
        core<{ connections: Connection[] }>('connections'),
      ])
      setProxies(p.proxies ?? {})
      setConnections(c.connections ?? [])
      setError('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка мониторинга.')
    }
  }, [])
  useEffect(() => {
    void Promise.resolve().then(refresh)
    let disposed = false
    const sockets = ['logs', 'traffic', 'memory', 'connections'].map((name) => {
      const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/core/${name}`)
      ws.onopen = () => {
        if (!disposed) setStreams((s) => ({ ...s, [name]: true }))
      }
      ws.onclose = () => {
        if (!disposed) setStreams((s) => ({ ...s, [name]: false }))
      }
      ws.onerror = () => ws.close()
      ws.onmessage = (event) => {
        if (typeof event.data !== 'string' || event.data.length > 65536) return
        try {
          const data = JSON.parse(event.data)
          if (name === 'logs' && typeof data.payload === 'string') setLogs((lines) => [...lines.slice(-199), data.payload.slice(0, 4096)])
          if (name === 'traffic') setTraffic(`↑ ${Number(data.up) || 0} Б/с · ↓ ${Number(data.down) || 0} Б/с`)
          if (name === 'memory') setMemory(`${Number(data.inuse) || 0} Б`)
          if (name === 'connections' && Array.isArray(data.connections)) setConnections(data.connections.slice(0, 1000))
        } catch {
          /* malformed frames are ignored */
        }
      }
      return ws
    })
    return () => {
      disposed = true
      sockets.forEach((s) => s.close())
    }
  }, [refresh])
  const select = async (group: string, name: string) => {
    try {
      await core(`proxies/${encodeURIComponent(group)}`, 'PUT', { name })
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка выбора.')
    }
  }
  const close = async (id: string) => {
    try {
      await core(`connections/${encodeURIComponent(id)}`, 'DELETE')
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Ошибка закрытия соединения.')
    }
  }
  return (
    <section className="bg-card rounded-xl border p-4" aria-label="Мониторинг Mihomo">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-medium">Мониторинг Mihomo</h2>
        <Button variant="outline" onClick={() => void refresh()}>
          Обновить
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-destructive mt-2 text-sm">
          {error}
        </p>
      )}
      <p className="mt-2 text-sm">
        Трафик: {streams.traffic ? traffic : 'поток недоступен'} · Память: {streams.memory ? memory : 'поток недоступен'}
      </p>
      <h3 className="mt-3 font-medium">Селекторы</h3>
      <div className="grid gap-2 sm:grid-cols-2">
        {Object.entries(proxies)
          .filter(([, p]) => p.type === 'Selector' && Array.isArray(p.all))
          .map(([name, p]) => (
            <label key={name} className="text-sm">
              {name}
              <select
                className="bg-background mt-1 block w-full rounded-md border p-2"
                value={p.now ?? ''}
                onChange={(e) => void select(name, e.target.value)}
              >
                {p.all?.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
          ))}
      </div>
      <h3 className="mt-3 font-medium">Соединения ({connections.length})</h3>
      <div className="max-h-64 overflow-auto">
        {connections.map((c) => (
          <div key={c.id} className="flex items-center justify-between gap-2 border-b py-1 text-sm">
            <span className="break-all">
              {c.metadata?.host || c.metadata?.destinationIP || c.id} · {c.chains?.join(' → ')}
            </span>
            <Button size="sm" variant="outline" onClick={() => void close(c.id)}>
              Закрыть
            </Button>
          </div>
        ))}
      </div>
      <h3 className="mt-3 font-medium">Журнал {streams.logs ? '' : '· поток недоступен'}</h3>
      <pre className="bg-muted mt-1 max-h-48 overflow-auto rounded p-2 text-xs break-all whitespace-pre-wrap">{logs.join('\n')}</pre>
    </section>
  )
}
