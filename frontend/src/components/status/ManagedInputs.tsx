import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { useAppContext } from '../../lib/store'
import { confirmNetworkIfPending, disableGateway } from '../../lib/service-control'
import { retryRuntimeBusy } from '../../lib/runtime-http'
import type { ManagedInputStatus } from '../../lib/runtime-adapter'

const labels:Record<string,string>={active:'включён',inactive:'выключен',pending:'ожидает подтверждения',degraded:'ошибка проверки',recovering:'восстановление',unknown:'недоступно'}
export function ManagedInputs({
  inputs, stale, pending, running, networkState, applied, onRefresh, remoteAdmin = false,
  onOperationStart, onOperationEnd, onRestart,
}: {
  inputs: ManagedInputStatus | null
  stale: boolean
  pending: boolean
  running: boolean
  networkState: string
  applied: boolean
  onRefresh: () => void
  remoteAdmin?: boolean
  onOperationStart: () => void
  onOperationEnd: () => void
  onRestart: () => void
}) {
  const [selected,setSelected]=useState('')
  const [busy,setBusy]=useState(false)
  const {showToast,dispatch}=useAppContext()
  async function operation(action:'explicit_on'|'explicit_off'|'gateway_off') {
    onOperationStart()
    dispatch({type:'SET_SERVICE_STATUS',status:'pending',pendingText:'Изменение режима…'})
    setBusy(true)
    try {
      if(action==='gateway_off') await disableGateway()
      else {
        const binding=inputs?.trusted_bindings.find(b=>`${b.interface}/${b.address}`===selected)
        if(action==='explicit_on'&&!binding)throw new Error('Выберите доверенный адрес LAN.')
        const path='inputs/explicit'
        const body={enabled:action==='explicit_on',...(binding&&action==='explicit_on'?{binding:{interface:binding.interface,address:binding.address}}:{})}
        const response=await retryRuntimeBusy(fetch,`/api/${path}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
        const data=await response.json()
        if(!response.ok||!data.success)throw new Error(['NETWORK_FIREWALL_CONFLICT','NETWORK_PORT_CONFLICT'].includes(data.code)?data.error:data.code??'NOT_READY')
        if(data.network)await confirmNetworkIfPending(data.network)
      }
      showToast(action==='gateway_off'?'Перехват выключен. Выбранный HTTP/SOCKS сохранён.':'Выбранный режим обновлён.','success')
    } catch(error) {showToast(error instanceof Error?error.message:'Режим не изменён.','error')}
    finally{setBusy(false);onOperationEnd();onRefresh()}
  }
  return (
    <div className="space-y-4 py-2">
      <section className="border-border space-y-2 rounded-lg border p-3" aria-labelledby="explicit-heading">
        <h3 id="explicit-heading" className="font-medium">HTTP/SOCKS</h3>
        <p>Статус: <strong>{labels[inputs?.explicit ?? 'unknown'] ?? 'недоступно'}</strong>{stale && <span className="text-amber-500"> (данные устарели)</span>}</p>
        <select aria-label="Доверенный адрес HTTP/SOCKS" className="bg-background w-full rounded border px-2 py-1 sm:w-auto" value={selected} onChange={e => setSelected(e.target.value)} disabled={busy || pending}>
          <option value="">Выберите адрес LAN</option>
          {inputs?.trusted_bindings.map(b => <option key={`${b.interface}/${b.address}`} value={`${b.interface}/${b.address}`}>{b.interface} · {b.address}:{b.port}</option>)}
        </select>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" disabled={busy || pending || stale || !applied || !selected || inputs?.explicit === 'active' || remoteAdmin} onClick={() => void operation('explicit_on')}>Включить HTTP/SOCKS</Button>
          <Button size="sm" variant="outline" disabled={busy || pending || (!['active', 'degraded'].includes(inputs?.explicit ?? '') && !inputs?.explicit_selected)} onClick={() => void operation('explicit_off')}>Выключить HTTP/SOCKS</Button>
        </div>
      </section>
      <section className="border-border space-y-2 rounded-lg border p-3" aria-labelledby="interception-heading">
        <h3 id="interception-heading" className="font-medium">Перехват IPv4 LAN</h3>
        <p className="text-muted-foreground text-xs">Выключение перехвата сохраняет включённый HTTP/SOCKS. Верхняя кнопка «Остановить» останавливает Mihomo и оба режима.</p>
        <Button size="sm" variant="outline" disabled={busy || pending || !['active', 'degraded', 'pending'].includes(networkState)} onClick={() => void operation('gateway_off')}>Выключить перехват</Button>
      </section>
      {running && <Button size="sm" variant="outline" disabled={busy || pending || (remoteAdmin && !!inputs?.explicit_selected) || stale} onClick={onRestart}>Перезапустить</Button>}
      {remoteAdmin && <p className="text-muted-foreground text-xs">Панель открыта через Tailscale: запуск, перезапуск шлюза, применение и остановка доступны — роутер сам проверит DNS и выход в интернет. HTTP/SOCKS включается и перезапускается только из основной IPv4 LAN.</p>}
    </div>
  )
}
