import { operationKey } from './operation-key.ts'
import { resourceText } from './resource-messages.ts'
import { retryRuntimeBusy } from './runtime-http.ts'

/** A refused operation: `message` is the code; `serverText` the backend's own text. */
export class ServiceError extends Error {
  serverText?: string
  constructor(code: string, serverText?: string) {
    super(code)
    this.serverText = serverText
  }
}

function resourceRefusal(data: { code?: unknown; network?: { compatibility?: { issues?: unknown }; resources?: { shortages?: unknown } } }) {
  if (typeof data.code !== 'string') return null
  const issues = Array.isArray(data.network?.compatibility?.issues) ? data.network.compatibility.issues : []
  const blocker = issues.find((issue: { code?: unknown }) => issue?.code === data.code) as { detail?: object } | undefined
  const shortages = Array.isArray(data.network?.resources?.shortages) ? data.network.resources.shortages : []
  return resourceText(data.code, (blocker?.detail ?? shortages[0]) as Parameters<typeof resourceText>[1])
}

async function request(fetcher: typeof fetch, path: string, body?: unknown) {
  const response = await retryRuntimeBusy(fetcher, `/api/${path}`, {
    method: body ? 'POST' : 'GET', cache: 'no-store',
    ...(!body && path === 'control' ? { headers: { 'X-XkeenWRT-Status-Fresh': '1' } } : {}),
    ...(body ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}),
  })
  const data = await response.json()
  if (!response.ok || data.success !== true) {
    if (['NETWORK_FIREWALL_CONFLICT','NETWORK_PORT_CONFLICT'].includes(data.code) && typeof data.error === 'string' && data.error.length <= 1024) throw new Error(data.error)
    const shortage = resourceRefusal(data)
    if (shortage) throw new Error(shortage)
    throw new ServiceError(data.code || 'RUNTIME_UNAVAILABLE', typeof data.error === 'string' && data.error.length <= 1024 ? data.error : undefined)
  }
  return data
}

const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
async function verifyService(fetcher: typeof fetch, running: boolean, pause = delay) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const status = await request(fetcher, 'control')
    if (!status.stale && status.running === running && status.network?.state === (running ? 'active' : 'inactive')) return status
    // The independent recovery supervisor may briefly own the status lock.
    // An unavailable observation is not evidence of a failed operation.
    if (status.network?.state === 'inactive' && running) throw new Error('NOT_READY')
    if (attempt < 11) await pause(500)
  }
  throw new Error('NOT_READY')
}

export async function confirmNetworkIfPending(network: {state?:string;transaction_id?:string;confirm_token?:string}, fetcher:typeof fetch = fetch) {
  if (network.state !== 'pending') return
  const {transaction_id,confirm_token}=network
  if (typeof transaction_id!=='string'||typeof confirm_token!=='string') throw new Error('NOT_READY')
  const reachable=await request(fetcher,'network/status')
  if (reachable.network?.state!=='pending'||reachable.network?.transaction_id!==transaction_id) throw new Error('CONFLICT')
  await request(fetcher,'network/confirm',{transaction_id,confirm_token})
}

const REMOTE_REFUSALS = ['NETWORK_REMOTE_DNS', 'NETWORK_REMOTE_EGRESS']
/** A Tailscale confirmation refused by the router's own probes would strand
 * LAN clients until the 120 s deadline: remove capture now, keep the reason. */
async function confirmOrWithdraw(network: {state?:string;transaction_id?:string;confirm_token?:string}, fetcher: typeof fetch, pause: typeof delay) {
  try {
    await confirmNetworkIfPending(network, fetcher)
  } catch (error) {
    if (error instanceof Error && REMOTE_REFUSALS.includes(error.message)) await disableGateway(fetcher, pause).catch(() => undefined)
    throw error
  }
}

/** One user action, one guarded LAN transaction. A fresh round trip from the
 * management client precedes confirmation; lost access leaves rescue armed. */
export async function startLanService(fetcher: typeof fetch = fetch, pause = delay) {
  const started = await request(fetcher, 'control', { action: 'start' })
  if (started.network?.state === 'pending') await confirmOrWithdraw(started.network, fetcher, pause)
  else if (started.network?.state !== 'active') throw new Error('NOT_READY')
  return await verifyService(fetcher, true, pause)
}

export async function stopLanService(fetcher: typeof fetch = fetch, pause = delay) {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const stopped = await request(fetcher, 'control', { action: 'stop' })
      if (stopped.network?.state === 'stopped') {
        return await verifyService(fetcher, false, pause)
      }
      if (stopped.network?.state !== 'stopping') throw new Error('NOT_READY')
    } catch (error) {
      // Pending cancellation can briefly restart runtime under rescue. Never
      // report success on that disconnect or swallow a policy/storage failure.
      if (!(error instanceof TypeError) && !(error instanceof Error && ['BUSY', 'RUNTIME_UNAVAILABLE'].includes(error.message))) throw error
    }
    await pause(1000)
  }
  throw new Error('Остановка ещё не завершена. Проверьте состояние сервиса.')
}

export async function restartManagedService(fetcher:typeof fetch=fetch,pause=delay) {
  for(let attempt=0;attempt<60;attempt++) {
    const result=await request(fetcher,'control',{action:'restart'})
    if(result.network?.state==='pending') {await confirmOrWithdraw(result.network,fetcher,pause);return await verifyService(fetcher,true,pause)}
    if(result.network?.state==='restarted') {
      const status=await request(fetcher,'control')
      if(status.stale||status.running!==true)throw new Error('NOT_READY')
      return status
    }
    if(result.network?.state!=='stopping')throw new Error('NOT_READY')
    await pause(1000)
  }
  throw new Error('Перезапуск ещё не завершён. Проверьте состояние.')
}

/** Disable is a helper receipt/cancellation, never a new capture Confirm. */
export async function disableGateway(fetcher:typeof fetch=fetch,pause=delay) {
  await request(fetcher,'network/disable',{idempotency_key:operationKey()})
  for(let attempt=0;attempt<60;attempt++) {
    try {
      const status=await request(fetcher,'network/status')
      if(status.network?.state==='inactive')return
    } catch(error) {
      if(!(error instanceof TypeError)&&!(error instanceof Error&&['BUSY','RUNTIME_UNAVAILABLE'].includes(error.message)))throw error
    }
    await pause(500)
  }
  throw new Error('Перехват ещё снимается. Проверьте состояние.')
}
