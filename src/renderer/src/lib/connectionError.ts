// What actually went wrong with a connection, worked out from the text the
// failure arrived with.
//
// ssh2, node's socket layer and five database drivers each phrase the same
// handful of problems differently, and none of them phrase any of it for a
// person. Classifying in one place is what lets every surface say one short
// sentence and offer the one button that fixes it, instead of pasting a driver
// string into a toast and leaving the reader to interpret it.

export type ConnectionFault =
  | 'host-key'
  | 'port-in-use'
  | 'passphrase'
  | 'key-missing'
  | 'auth'
  | 'refused'
  | 'unreachable'
  | 'permission'
  | 'unknown'

// First match wins, so the specific patterns come before the general ones.
// "Permission denied (publickey)" is a rejected credential, not a filesystem
// refusal, and has to be tested before the bare permission pattern.
const PATTERNS: [ConnectionFault, RegExp][] = [
  ['host-key', /host key|host verification|hostkey|fingerprint/i],
  ['port-in-use', /EADDRINUSE|already in use/i],
  ['passphrase', /passphrase|encrypted private key/i],
  ['key-missing', /(ENOENT|no such file|cannot (open|read))[^]*(key|\.pem|id_)/i],
  [
    'auth',
    /authentication|permission denied \(|publickey|password rejected|access denied for user|auth failed|login failed/i
  ],
  ['refused', /ECONNREFUSED|connection refused/i],
  ['unreachable', /ENOTFOUND|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|getaddrinfo|timed out|timeout/i],
  ['permission', /permission denied|EACCES|access denied|not permitted/i]
]

export function classifyConnectionError(text: string | null | undefined): ConnectionFault {
  if (!text) return 'unknown'
  for (const [fault, re] of PATTERNS) if (re.test(text)) return fault
  return 'unknown'
}

/**
 * The message out of a thrown IPC rejection, without the transport's own
 * preamble.
 *
 * Electron prefixes a rejected handler's message with "Error invoking remote
 * method 'sftp:connect':", which describes how the failure travelled rather
 * than what failed.
 */
export function errorText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err)
  return raw
    .replace(/^Error invoking remote method '[^']*':\s*/, '')
    .replace(/^Error:\s*/, '')
    .trim()
}
