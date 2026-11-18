/** BUSY means admission was refused before mutation. Never replay a lost
 * connection or any other failure: its result may be uncertain. */
export async function retryRuntimeBusy(fetcher: typeof fetch, input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    init?.signal?.throwIfAborted()
    const response = await fetcher(input, init)
    if (response.status !== 503 || attempt >= 2) return response
    const value = await response.clone().json().catch(() => null)
    if (value?.code !== 'BUSY') return response
    await new Promise(resolve => setTimeout(resolve, 150 * (attempt + 1)))
  }
}
