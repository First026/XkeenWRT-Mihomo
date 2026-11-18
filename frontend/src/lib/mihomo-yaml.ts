import { stringify } from 'yaml'

/** Preserve URI strings exactly (Reality IDs, passwords, names, transport paths). */
export function toMihomoYaml(value: Record<string, unknown>, indent = 0): string {
  const text = stringify(value, {
    defaultStringType: 'QUOTE_DOUBLE',
    defaultKeyType: 'PLAIN',
    version: '1.1', // Also quote keys such as "off" for both Rust and Go YAML readers.
    lineWidth: 0,
  })
  return text.split('\n').map(line => line ? ' '.repeat(indent) + line : line).join('\n')
}
