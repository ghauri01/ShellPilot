import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { generateKeyPairSync } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'
import { Client, Server, utils } from 'ssh2'
import type { SshHop } from '../src/shared/ssh'
import { fingerprint } from '../src/main/services/knownhosts'
import {
  poolClose,
  poolDisposeAll,
  poolList,
  pooledConnectionIds,
  sshExec,
  sshOpenFresh
} from '../src/main/services/ssh'

// Roadmap item 23, rule 2 — "never commit without a second, INDEPENDENT
// session".
//
// The word that matters is independent, and it cannot be checked by counting
// calls. `sshExec` and `sshOpenFresh` both run a command and both come back
// with output; the difference is entirely in whether sshd was asked to
// authenticate anybody, and only sshd knows that. So this file stands up a real
// SSH server — ssh2 is already a dependency and ships one — and asks it.
//
// What is asserted is what the SERVER saw: how many connections completed
// authentication, and with which key. A test that asserted "openChain was
// called" or "acquire was not called" would pass against an implementation that
// reused the pooled socket by another route, which is precisely the bug rule 2
// exists to prevent.

const HOST = '127.0.0.1'

/** Every connection this server has authenticated, oldest first. */
interface Seen {
  username: string
  method: string
}

let server: Server
let port = 0
let authenticated: Seen[] = []
let clientKey = ''
let hostKey = ''

/**
 * The host key exactly as ssh2 hands it to `hostVerifier`.
 *
 * Read from a throwaway connection rather than derived from the PEM, so this
 * file does not encode an assumption about ssh2's wire encoding that a version
 * bump could quietly break. Trust-on-first-use would otherwise refuse every
 * connection below and every assertion would be about the wrong thing.
 */
function learnHostKey(): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const probe = new Client()
    let seen: Buffer | null = null
    probe.on('ready', () => {
      probe.end()
      if (seen) resolve(seen)
      else reject(new Error('connected without a host key'))
    })
    probe.on('error', (e) => reject(e))
    probe.connect({
      host: HOST,
      port,
      username: 'ops',
      privateKey: clientKey,
      hostVerifier: ((key: Buffer, cb: (ok: boolean) => void) => {
        seen = Buffer.from(key)
        cb(true)
      }) as never
    })
  })
}

beforeAll(async () => {
  // RSA in PKCS#1 PEM: the one private-key encoding ssh2's parser accepts from
  // node's crypto without an OpenSSH-format conversion step.
  const host = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' }
  })
  const user = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' }
  })

  hostKey = host.privateKey
  clientKey = user.privateKey
  // Parsed from the PRIVATE half: ssh2 reads PKCS#1 private PEM and will hand
  // back the public half, where it does not read a PKCS#1 *public* PEM at all.
  const allowed = utils.parseKey(user.privateKey)
  if (allowed instanceof Error) throw allowed

  server = new Server({ hostKeys: [hostKey] }, (conn) => {
    let method = ''
    conn.on('authentication', (ctx) => {
      if (ctx.method !== 'publickey') {
        ctx.reject(['publickey'])
        return
      }
      if (ctx.key.algo !== allowed.type || !ctx.key.data.equals(allowed.getPublicSSH())) {
        ctx.reject(['publickey'])
        return
      }
      // ssh2 asks twice: once to find out whether the key would be accepted at
      // all, then again carrying a signature over the session id. Only the
      // second one is an authentication, and only the second one is counted.
      if (ctx.signature) {
        if (!allowed.verify(ctx.blob as Buffer, ctx.signature, ctx.hashAlgo)) {
          ctx.reject(['publickey'])
          return
        }
      }
      method = ctx.method
      ctx.accept()
    })
    conn.on('ready', () => {
      authenticated.push({ username: 'ops', method })
      conn.on('session', (accept) => {
        const session = accept()
        session.on('exec', (acceptExec, _reject, info) => {
          const stream = acceptExec()
          stream.write(`${info.command}\n`)
          stream.exit(0)
          stream.end()
        })
      })
    })
  })

  await new Promise<void>((resolve) => server.listen(0, HOST, resolve))
  port = (server.address() as { port: number }).port

  const key = await learnHostKey()
  // Trusted before anything under test connects, so the trust-on-first-use
  // dialog never enters the picture.
  writeFileSync(
    join(app.getPath('userData'), 'shellpilot-known-hosts.json'),
    JSON.stringify({
      [`${HOST}:${port}`]: {
        id: `${HOST}:${port}`,
        fingerprint: fingerprint(key),
        addedAt: new Date().toISOString()
      }
    })
  )
  // The probe above authenticated too; the assertions below count from zero.
  authenticated = []
})

afterAll(async () => {
  poolDisposeAll()
  await new Promise<void>((resolve) => server.close(() => resolve()))
})

const cfg = (): SshHop & { serverId: string } => ({
  serverId: 'fresh-session-test',
  host: HOST,
  port,
  username: 'ops',
  auth: 'key',
  privateKey: clientKey
})

describe('an independent session, against a server that can say whether it authenticated one', () => {
  it('pools the ordinary exec path: the second command asks sshd for nothing', async () => {
    // The baseline the whole rule rests on. If this passed for the wrong
    // reason — if `sshExec` re-authenticated every time — the pool would not be
    // a problem and rule 2 would already be satisfied by any second command.
    const first = await sshExec(cfg(), 'echo one', 10_000, false)
    const second = await sshExec(cfg(), 'echo two', 10_000, false)
    expect(first.stdout.trim()).toBe('echo one')
    expect(second.stdout.trim()).toBe('echo two')
    expect(authenticated).toHaveLength(1)
    expect(poolList().map((p) => p.key)).toEqual(['srv:fresh-session-test'])
  })

  it('authenticates again — the server sees a second login, not a second channel', async () => {
    const before = authenticated.length
    const session = await sshOpenFresh(cfg(), 10_000)
    try {
      // The assertion rule 2 actually needs, and the only one sshd can make:
      // its authentication layer ran a second time. A channel opened on the
      // pooled connection would leave this at zero new logins.
      expect(authenticated.length - before).toBe(1)
      expect(authenticated[authenticated.length - 1].method).toBe('publickey')

      const r = await session.exec('echo verified')
      expect(r.stdout.trim()).toBe('echo verified')
      expect(r.code).toBe(0)
    } finally {
      session.close()
    }
  })

  it('leaves the pooled connection alone — every open pane survives the check', async () => {
    // The alternative implementation is `poolClose()`, which forces a new
    // authentication by tearing down the connection every terminal pane and the
    // metrics sampler are riding on, at the moment the operator is watching a
    // key change land.
    const pooledBefore = pooledConnectionIds()
    expect(pooledBefore).toHaveLength(1)
    const session = await sshOpenFresh(cfg(), 10_000)
    session.close()
    expect(pooledConnectionIds()).toEqual(pooledBefore)

    const before = authenticated.length
    const after = await sshExec(cfg(), 'echo still here', 10_000, false)
    expect(after.stdout.trim()).toBe('echo still here')
    // The pooled connection did not have to log in again, which is what "left
    // alone" means.
    expect(authenticated.length - before).toBe(0)
  })

  it('is not the pooled connection — proved by killing the pool and surviving it', async () => {
    // The ids alone would be satisfied by an implementation that reused the
    // pooled socket and stamped a `fresh#` label on it: the label is minted
    // here either way. So the socket itself is tested. `poolClose` destroys the
    // pooled client outright; a session sharing it would die with it, and this
    // one goes on answering.
    const session = await sshOpenFresh(cfg(), 10_000)
    try {
      expect(session.pooledConnectionIds).toEqual(pooledConnectionIds())
      expect(session.pooledConnectionIds).not.toContain(session.connectionId)
      expect(session.connectionId).toMatch(/^fresh#\d+$/)

      poolClose('srv:fresh-session-test')
      expect(pooledConnectionIds()).toEqual([])
      const r = await session.exec('echo still mine')
      expect(r.stdout.trim()).toBe('echo still mine')
      expect(r.code).toBe(0)
    } finally {
      session.close()
    }
  })

  it('closes its own connection, so a confirmation does not leak an authenticated session', async () => {
    const session = await sshOpenFresh(cfg(), 10_000)
    session.close()
    // Closing twice is what a `finally` next to an early return does.
    session.close()
    // And a command after that ANSWERS rather than throwing: ssh2 raises
    // `Not connected` synchronously, and a confirmation whose session died
    // mid-check has to read as a failed verification rather than as an
    // exception on the way to deciding whether a key change is permanent.
    const r = await session.exec('echo after close', 2_000)
    expect(r.ok).toBe(false)
    expect(r.error).toContain('Not connected')
  })
})
