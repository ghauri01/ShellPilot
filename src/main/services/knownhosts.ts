import { app, dialog } from 'electron'
import { join } from 'node:path'
import { existsSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { createHash } from 'node:crypto'

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

export function verifyHostKey(host: string, port: number, key: Buffer): Promise<boolean> {
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

  const inFlight = pending.get(id)
  if (inFlight) return inFlight

  const prompt = dialog
    .showMessageBox({
      type: 'warning',
      title: 'Unknown host',
      message: `The authenticity of ${id} cannot be established.`,
      detail: `Fingerprint: ${fp}\n\nTrust this host and remember it for future connections?`,
      buttons: ['Trust and connect', 'Cancel'],
      defaultId: 1,
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
