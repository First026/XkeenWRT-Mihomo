/** Web Crypto getRandomValues is available on router HTTP origins as well as HTTPS. */
export function operationKey(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
}
