import type { VpnErrorCode } from '../../../shared/vpn'

// Every failure the VPN layer can surface carries a code, and every code maps
// to a sentence the user can act on. The raw engine line stays in the log
// drawer: an unexplained ETIMEDOUT is the worst failure mode this class of
// product has, and it is almost always avoidable.

export class VpnError extends Error {
  readonly code: VpnErrorCode
  // Extra words appended to the generic message: the endpoint that timed out,
  // the port that was taken, the file that was missing.
  readonly detail?: string

  constructor(code: VpnErrorCode, detail?: string, options?: { cause?: unknown }) {
    super(detail ? `${VPN_ERROR_MESSAGE[code]} ${detail}` : VPN_ERROR_MESSAGE[code], options)
    this.name = 'VpnError'
    this.code = code
    this.detail = detail
  }
}

export function isVpnError(e: unknown): e is VpnError {
  return e instanceof VpnError
}

// The message shown when nothing more specific is known. Kept complete: a test
// asserts every VpnErrorCode has an entry, so adding a code without a message
// fails CI rather than reaching a user as "undefined".
export const VPN_ERROR_MESSAGE: Record<VpnErrorCode, string> = {
  'binary-missing': 'The program that runs this tunnel could not be found.',
  'binary-untrusted':
    'The bundled tunnel program does not match its expected checksum, so it was not run.',
  'config-invalid': 'This profile is not valid.',
  'config-rejected': 'This configuration was rejected because it tries to run programs.',
  'auth-failed': 'The server rejected these credentials.',
  'auth-otp-required': 'A one-time code is needed to connect.',
  'tls-handshake-failed': 'The secure connection to the server could not be established.',
  'cert-expired': 'The client certificate is outside its validity period.',
  'handshake-timeout': 'No response from the server.',
  'dns-failure': 'The server address could not be resolved.',
  'port-in-use': 'The local port is already in use.',
  'permission-denied': 'Permission was denied.',
  'elevation-declined': 'The administrator prompt was dismissed, so the tunnel did not start.',
  'network-unreachable': 'The network is unreachable.',
  'server-rejected': 'The server refused the connection.',
  'crash-loop': 'The tunnel program kept exiting, so it was stopped.',
  'vault-locked': 'The vault is locked, so the credentials for this tunnel are unavailable.',
  'proxy-required': 'This network appears to require a proxy.',
  'version-mismatch': 'This client and the server are not compatible.',
  'interface-conflict': 'That network interface name is already in use.',
  'already-running': 'This tunnel is already running.',
  'clock-skew': 'The system clock is too far off for the certificate to be accepted.',
  'exposure-unacknowledged':
    'This profile exposes a local port to a remote server and has not been confirmed.',
  unsupported: 'That is not supported on this platform.',
  internal: 'Something went wrong inside ShellPilot.'
}

// What the user should do next. Empty string means "the message says it all".
export const VPN_ERROR_HINT: Record<VpnErrorCode, string> = {
  'binary-missing': 'Install it, or point ShellPilot at it in the profile settings.',
  'binary-untrusted': 'Reinstall ShellPilot. Antivirus software sometimes alters bundled files.',
  // Not "check the highlighted fields": this arrives as a toast when the
  // profile form is closed, so there is nothing highlighted to look at.
  'config-invalid': 'Open the profile to fix it.',
  'config-rejected': 'Ask whoever gave you this file for one without script directives.',
  'auth-failed': 'Check the username, password or key and try again.',
  'auth-otp-required': 'Enter the code from your authenticator.',
  'tls-handshake-failed': 'Check the certificate and that the server address is right.',
  'cert-expired': 'Ask for a new certificate.',
  'handshake-timeout':
    'Check the endpoint address, and that the port is not blocked. You may also need to sign in to this network first.',
  'dns-failure': 'Check the server address and your DNS settings.',
  'port-in-use': 'Choose another port, or leave it as 0 to pick one automatically.',
  'permission-denied': 'Try again and approve the administrator prompt.',
  'elevation-declined': 'Start it again and approve the prompt.',
  'network-unreachable': 'Check that you are online.',
  'server-rejected': 'Check the server address and port.',
  'crash-loop': 'Open the log to see why, fix it, then start the tunnel again.',
  'vault-locked': 'Unlock the vault and try again.',
  'proxy-required':
    'Set a proxy in the profile. WireGuard runs over UDP and cannot go through an HTTP proxy.',
  'version-mismatch': 'Update ShellPilot, or ask the server operator which version to use.',
  'interface-conflict': 'Stop the other tunnel using that interface first.',
  'already-running': '',
  'clock-skew': 'Correct your system clock.',
  'exposure-unacknowledged': 'Tick the confirmation on each proxy before starting.',
  unsupported: '',
  internal: 'Check the log for details.'
}

/** Full user-facing text: what happened, then what to do. */
export function describeVpnError(code: VpnErrorCode, detail?: string): string {
  const parts = [VPN_ERROR_MESSAGE[code]]
  if (detail) parts.push(detail)
  const hint = VPN_ERROR_HINT[code]
  if (hint) parts.push(hint)
  return parts.join(' ')
}

/** Turn any thrown value into the pair the IPC layer returns. */
export function toVpnResult(e: unknown): { ok: false; error: string; errorCode: VpnErrorCode } {
  if (isVpnError(e)) {
    return { ok: false, error: describeVpnError(e.code, e.detail), errorCode: e.code }
  }
  const msg = e instanceof Error ? e.message : String(e)
  return { ok: false, error: msg || VPN_ERROR_MESSAGE.internal, errorCode: 'internal' }
}

// Engine stderr is not a user interface, but it is the only place some causes
// appear. Each rule turns a known line into a code so the user gets the
// sentence above instead of the raw text. Ordered: first match wins.
const STDERR_RULES: { re: RegExp; code: VpnErrorCode }[] = [
  // --- OpenVPN ---
  { re: /AUTH_FAILED|Verification Failed|auth-failure/i, code: 'auth-failed' },
  // "not yet valid" before "expired": the two look alike and OpenVPN reports
  // them through the same VERIFY ERROR, but they send the user to different
  // people. An expired certificate needs a new one from whoever issued it; a
  // certificate that is not valid *yet* almost always means this machine's
  // clock is wrong, and telling that user to go ask for a new certificate
  // wastes everyone's afternoon.
  { re: /certificate is not yet valid|is not yet valid/i, code: 'clock-skew' },
  { re: /certificate has expired|certificate expired/i, code: 'cert-expired' },
  { re: /VERIFY ERROR|TLS handshake failed|TLS key negotiation failed/i, code: 'tls-handshake-failed' },
  { re: /Cannot resolve host address|RESOLVE: Cannot resolve/i, code: 'dns-failure' },
  { re: /Network is unreachable|No route to host/i, code: 'network-unreachable' },
  { re: /Cannot open TUN\/TAP|Operation not permitted|ERROR: Cannot ioctl TUNSETIFF/i, code: 'permission-denied' },
  { re: /Address already in use|EADDRINUSE/i, code: 'port-in-use' },
  { re: /Connection refused/i, code: 'server-rejected' },
  // --- frp ---
  { re: /authentication failed|token mismatch|invalid authentication/i, code: 'auth-failed' },
  { re: /version mismatch|incompatible version/i, code: 'version-mismatch' },
  { re: /port already used|port unavailable/i, code: 'port-in-use' },
  { re: /proxy name .* already exists/i, code: 'interface-conflict' },
  { re: /login to server failed/i, code: 'server-rejected' },
  // --- WireGuard sidecar ---
  { re: /operation not permitted|permission denied/i, code: 'permission-denied' },
  { re: /no such device|\/dev\/net\/tun/i, code: 'permission-denied' },
  { re: /invalid key|failed to parse (private|public|preshared) key/i, code: 'config-invalid' }
]

/** Best-effort code for a line of engine output. Null when nothing matches —
 *  the caller keeps whatever code it already had rather than guessing. */
export function classifyEngineLine(line: string): VpnErrorCode | null {
  for (const r of STDERR_RULES) if (r.re.test(line)) return r.code
  return null
}
