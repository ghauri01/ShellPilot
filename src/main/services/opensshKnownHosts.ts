import { homedir } from 'node:os'
import { join } from 'node:path'
import { existsSync, readFileSync } from 'node:fs'
import { createHmac } from 'node:crypto'

// Reads OpenSSH's own ~/.ssh/known_hosts.
//
// ShellPilot keeps a separate trust store, which is deliberate: importing
// someone's accumulated known_hosts wholesale would silently adopt years of
// trust decisions, including everything an `accept-new` ever waved through.
// But not looking at it at all produces the opposite problem, and that is the
// one users actually hit — a host you connect to from your terminal every day
// is announced as an unknown host the first time ShellPilot sees it.
//
// So this module only ever *informs* the prompt. It never grants trust on its
// own. The one exception is @revoked, which is a negative signal and is
// therefore safe to act on without asking.

export type Marker = 'cert-authority' | 'revoked' | null

export interface OpenSshHostEntry {
  marker: Marker
  // Comma-separated host patterns, verbatim. Empty when the line is hashed.
  patterns: string[]
  // OpenSSH's HashKnownHosts form: |1|<base64 salt>|<base64 HMAC-SHA1>.
  hashed: { salt: string; hash: string } | null
  keyType: string
  // The raw key blob, base64-decoded. Fingerprinting this gives exactly the
  // same bytes ssh2 hands us for the key the server presented, so entries are
  // compared by key identity rather than by key type.
  key: Buffer
}

export function parseKnownHosts(text: string): OpenSshHostEntry[] {
  const out: OpenSshHostEntry[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue

    let rest = line
    let marker: Marker = null
    if (rest.startsWith('@')) {
      const [tag, ...tail] = rest.split(/\s+/)
      if (tag === '@cert-authority') marker = 'cert-authority'
      else if (tag === '@revoked') marker = 'revoked'
      else continue // An unknown marker means an unknown format; do not guess.
      rest = tail.join(' ')
    }

    const parts = rest.split(/\s+/)
    if (parts.length < 3) continue
    const [hosts, keyType, keyB64] = parts

    let key: Buffer
    try {
      key = Buffer.from(keyB64, 'base64')
      if (key.length === 0) continue
    } catch {
      continue
    }

    if (hosts.startsWith('|1|')) {
      const [, , salt, hash] = hosts.split('|')
      if (!salt || !hash) continue
      out.push({ marker, patterns: [], hashed: { salt, hash }, keyType, key })
    } else {
      out.push({ marker, patterns: hosts.split(','), hashed: null, keyType, key })
    }
  }
  return out
}

// OpenSSH writes a non-default port as "[host]:port" and a default one as the
// bare host, and hashes that same canonical string. Getting this wrong is how
// a trusted host on port 22000 reads as unknown.
export function canonicalHostname(host: string, port: number): string {
  const p = port || 22
  return p === 22 ? host : `[${host}]:${p}`
}

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`^${escaped.replace(/\*/g, '.*').replace(/\?/g, '.')}$`)
}

function patternsMatch(patterns: string[], name: string): boolean {
  let matched = false
  for (const pattern of patterns) {
    if (pattern.startsWith('!')) {
      // A negation anywhere in the list overrides every positive match.
      if (globToRegExp(pattern.slice(1)).test(name)) return false
    } else if (globToRegExp(pattern).test(name)) {
      matched = true
    }
  }
  return matched
}

export function entryMatchesHost(entry: OpenSshHostEntry, name: string): boolean {
  if (entry.hashed) {
    const mac = createHmac('sha1', Buffer.from(entry.hashed.salt, 'base64')).update(name).digest('base64')
    return mac === entry.hashed.hash
  }
  return patternsMatch(entry.patterns, name)
}

export interface OpenSshLookup {
  // The exact key the server presented is trusted in OpenSSH for this host.
  trusted: boolean
  // The host is in known_hosts, but under a different key.
  knownUnderAnotherKey: boolean
  // The key is explicitly revoked for this host. Overrides everything else.
  revoked: boolean
}

export function lookupInKnownHosts(
  entries: OpenSshHostEntry[],
  host: string,
  port: number,
  fingerprintOf: (key: Buffer) => string,
  presentedFingerprint: string
): OpenSshLookup {
  const name = canonicalHostname(host, port)
  const result: OpenSshLookup = { trusted: false, knownUnderAnotherKey: false, revoked: false }

  for (const entry of entries) {
    if (!entryMatchesHost(entry, name)) continue
    const sameKey = fingerprintOf(entry.key) === presentedFingerprint
    if (entry.marker === 'revoked') {
      if (sameKey) result.revoked = true
      continue
    }
    // A CA entry authorises certificates rather than naming a host key, and
    // validating a certificate chain is not something this can do. Treat it as
    // no evidence either way rather than as trust.
    if (entry.marker === 'cert-authority') continue
    if (sameKey) result.trusted = true
    else result.knownUnderAnotherKey = true
  }
  return result
}

export function knownHostsPaths(): string[] {
  const dir = join(homedir(), '.ssh')
  return ['known_hosts', 'known_hosts2'].map((f) => join(dir, f)).filter((p) => existsSync(p))
}

export function readOpenSshKnownHosts(paths = knownHostsPaths()): OpenSshHostEntry[] {
  const entries: OpenSshHostEntry[] = []
  for (const path of paths) {
    try {
      entries.push(...parseKnownHosts(readFileSync(path, 'utf8')))
    } catch {
      // An unreadable known_hosts is not fatal — it only means we fall back to
      // prompting exactly as before.
    }
  }
  return entries
}
