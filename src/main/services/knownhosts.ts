import { app, dialog } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { readOpenSshKnownHosts, lookupInKnownHosts, canonicalHostname } from './opensshKnownHosts'

// Trust-on-first-use host key checking. Without this, ssh2 accepts any host
// key presented, so a machine-in-the-middle on the path to a server can
// capture the session and any credentials sent over it.

const FILE = join(app.getPath('userData'), 'shellpilot-known-hosts.json')
const TMP = `${FILE}.tmp`

export interface KnownHost {
  id: string // "host:port"
  fingerprint: string
  addedAt: string
}

type HostMap = Record<string, KnownHost>

function read(): HostMap {
  try {
    if (existsSync(FILE)) return JSON.parse(readFileSync(FILE, 'utf8')) as HostMap
  } catch {
    /* ignore corrupt file */
  }
  return {}
}

function write(map: HostMap): void {
  writeFileSync(TMP, JSON.stringify(map, null, 2), { mode: 0o600 })
  renameSync(TMP, FILE)
}

// OpenSSH-style fingerprint: base64 SHA-256 of the raw key, padding stripped.
export function fingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`
}

export function knownHostList(): KnownHost[] {
  return Object.values(read()).sort((a, b) => a.id.localeCompare(b.id))
}

export function knownHostForget(id: string): void {
  const map = read()
  if (!map[id]) return
  delete map[id]
  write(map)
}

// Collapses concurrent prompts for the same host into one dialog — metrics,
// SFTP and a terminal can all connect at once on first use.
const pending = new Map<string, Promise<boolean>>()

export function verifyHostKey(
  host: string,
  port: number,
  key: Buffer,
  // Whether this caller may raise a dialog. A known-good key never prompts, and
  // a CHANGED key still refuses loudly regardless — an unattended caller only
  // loses the ability to establish trust for the first time, which is exactly
  // the decision that needs a person present.
  allowPrompt = true
): Promise<boolean> {
  const id = `${host}:${port || 22}`
  const fp = fingerprint(key)
  const map = read()
  const known = map[id]

  if (known) {
    if (known.fingerprint === fp) return Promise.resolve(true)
    // A changed key is either a rebuilt server or an interception. Never decide
    // this silently — refuse and make the user act.
    return dialog
      .showMessageBox({
        type: 'error',
        title: 'Host key changed',
        message: `The host key for ${id} does not match the one previously trusted.`,
        detail:
          `Expected: ${known.fingerprint}\nReceived: ${fp}\n\n` +
          'This happens when a server is rebuilt — but it is also what an interception looks like. ' +
          'The connection has been refused. If you are certain the server changed, forget the saved key in Settings → Security and reconnect.',
        buttons: ['OK'],
        defaultId: 0
      })
      .then(() => false)
  }

  // An unattended caller never prompts. It refuses and lets its own layer
  // report why.
  //
  // A trust-on-first-use dialog is only worth anything if it arrives at a
  // moment the person can reason about — "I am connecting to this host right
  // now, is that its fingerprint?" A background sweep raising one spontaneously,
  // with no action to correlate it to, teaches click-through on the single
  // dialog where click-through is how a machine-in-the-middle succeeds. Worse,
  // nothing cancels the pending promise, so five never-connected servers meant
  // five stacked modals nobody asked for.
  //
  // Deliberately decided in main and never taken from the renderer: a
  // renderer-settable "do not prompt" would let a compromised renderer suppress
  // host verification for real connections, which is the opposite of the point.
  if (!allowPrompt) return Promise.resolve(false)

  const inFlight = pending.get(id)
  if (inFlight) return inFlight

  // What OpenSSH already thinks of this host. This never grants trust by
  // itself — see opensshKnownHosts.ts for why — it only changes what the
  // prompt says, so a host you use daily in your terminal is not announced as
  // a total stranger. Revocation is the exception: it is a negative signal.
  const openssh = lookupInKnownHosts(readOpenSshKnownHosts(), host, port, fingerprint, fp)

  if (openssh.revoked) {
    return dialog
      .showMessageBox({
        type: 'error',
        title: 'Host key revoked',
        message: `The host key for ${id} is marked @revoked in your ~/.ssh/known_hosts.`,
        detail: `Fingerprint: ${fp}\n\nThe connection has been refused. Remove the @revoked line if this was a mistake.`,
        buttons: ['OK'],
        defaultId: 0
      })
      .then(() => false)
  }

  const recognised = openssh.trusted
  const prompt = dialog
    .showMessageBox({
      type: recognised ? 'question' : 'warning',
      title: recognised ? 'Confirm server' : 'Unknown server',
      message: recognised
        ? `${id} is already trusted in your ~/.ssh/known_hosts.`
        : `The authenticity of ${id} cannot be established.`,
      detail: recognised
        ? `Fingerprint: ${fp}\n\nThis is the same key OpenSSH has for ${canonicalHostname(host, port)}. ` +
          'ShellPilot keeps its own list of trusted servers, so it has to be added here once too.'
        : openssh.knownUnderAnotherKey
          ? `Fingerprint: ${fp}\n\nWarning: ~/.ssh/known_hosts has an entry for this server under a different key. ` +
            'That can mean the server was rebuilt, or that this connection is being intercepted. ' +
            'Check the fingerprint before trusting it.'
          : `Fingerprint: ${fp}\n\nTrust this server and remember it for future connections?`,
      buttons: ['Trust and connect', 'Cancel'],
      // Pre-selecting Trust is only defensible when we have independent
      // evidence for this exact key; anything else keeps Cancel as the default.
      defaultId: recognised ? 0 : 1,
      cancelId: 1
    })
    .then((r) => {
      if (r.response !== 0) return false
      const current = read()
      current[id] = { id, fingerprint: fp, addedAt: new Date().toISOString() }
      write(current)
      return true
    })
    .finally(() => pending.delete(id))

  pending.set(id, prompt)
  return prompt
}
