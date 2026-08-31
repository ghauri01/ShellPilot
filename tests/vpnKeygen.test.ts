import { afterEach, describe, expect, it } from 'vitest'
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { redactOutput } from '../src/main/services/secretRedaction'
import { isWireGuardKey } from '../src/shared/vpn'
import { wireguardDriver, wireguardTuning } from '../src/main/services/vpn/drivers/wireguard'

// `wg.keygen` is the one thing the WireGuard driver does that has nothing to do
// with running a profile, and the one place ShellPilot mints key material
// rather than being handed it. Two properties matter enough to test:
//
//   1. The keys are real. A keypair that is well formed but whose halves do not
//      match is the worst possible outcome — the profile saves, the public key
//      looks right on screen, the user pastes it into their server, and the
//      handshake silently never completes with nothing to point at. The
//      real-binary block at the bottom checks the arithmetic end to end.
//   2. The private key goes to the caller and nowhere else. No log line, no
//      error message quoting it, no supervisor ring buffer.

const dirs: string[] = []

afterEach(() => {
  wireguardTuning.resolveEngine = null
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

/** A stand-in netd: reads one NDJSON request from stdin, writes whatever the
 *  test told it to, and records what it was asked. A shell shim rather than a
 *  Node module because the driver spawns the engine path with no arguments,
 *  exactly as it does in production. */
function fakeNetd(script: string): { requests: () => unknown[] } {
  const dir = mkdtempSync(join(tmpdir(), 'sp-keygen-'))
  dirs.push(dir)
  const log = join(dir, 'requests.ndjson')
  const body = join(dir, 'netd.mjs')
  writeFileSync(
    body,
    `import { appendFileSync } from 'node:fs'
let buf = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (c) => {
  buf += c
  let nl
  while ((nl = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, nl)
    buf = buf.slice(nl + 1)
    if (!line.trim()) continue
    appendFileSync(${JSON.stringify(log)}, line + '\\n')
    const req = JSON.parse(line)
    ${script}
  }
})
`
  )
  const bin = join(dir, 'shellpilot-netd')
  writeFileSync(bin, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(body)}\n`)
  chmodSync(bin, 0o755)
  wireguardTuning.resolveEngine = async () => ({
    kind: 'wireguard',
    available: true,
    bundled: true,
    path: bin
  })
  return {
    requests: () =>
      existsSync(log)
        ? readFileSync(log, 'utf8')
            .split('\n')
            .filter(Boolean)
            .map((l) => JSON.parse(l) as unknown)
        : []
  }
}

// A real X25519 pair, so the shapes under test are the shapes production sees.
const PRIV = 'YCRaNcQHehwD4MhQ9W+jeZj5Px4ShRTMXm/kHjd0omA='
const PUB = 'pkPvgzKnI5aurLXke0Gm5mrEX12B/I025l5wMfdPolI='

const respond = (result: string): string =>
  `process.stdout.write(JSON.stringify({ id: req.id, ok: true, result: ${result} }) + '\\n')`

// The shell shim is a POSIX construct; the driver itself is not, and the real
// binary block below covers Windows when it is run there.
const posix = process.platform !== 'win32'

describe.skipIf(!posix)('wireguardDriver.keygen', () => {
  it('asks for a fresh pair with no params at all', async () => {
    const fake = fakeNetd(respond(`{ privateKey: ${JSON.stringify(PRIV)}, publicKey: ${JSON.stringify(PUB)} }`))

    const pair = await wireguardDriver.keygen()

    expect(pair).toEqual({ privateKey: PRIV, publicKey: PUB })
    // `wg.keygen` is the only method whose params are optional, and the driver
    // has to actually use that: sending `{}` would be harmless today and a
    // divergence from the documented protocol tomorrow.
    expect(fake.requests()).toEqual([{ id: '1', method: 'wg.keygen' }])
  })

  it('passes a pasted key through as publicKeyFor, trimmed', async () => {
    const fake = fakeNetd(respond(`{ publicKey: ${JSON.stringify(PUB)} }`))

    const pair = await wireguardDriver.keygen({ publicKeyFor: `  ${PRIV}\n` })

    expect(pair).toEqual({ publicKey: PUB })
    expect(fake.requests()).toEqual([
      { id: '1', method: 'wg.keygen', params: { publicKeyFor: PRIV } }
    ])
  })

  it('surfaces the sidecar’s own error code rather than a generic failure', async () => {
    fakeNetd(
      `process.stdout.write(JSON.stringify({ id: req.id, ok: false, error: { code: 'config-invalid', message: 'publicKeyFor is not valid base64' } }) + '\\n')`
    )

    await expect(wireguardDriver.keygen({ publicKeyFor: 'nope' })).rejects.toMatchObject({
      code: 'config-invalid'
    })
  })

  it('does not hang when the sidecar exits without answering', async () => {
    fakeNetd(`process.exit(0)`)

    await expect(wireguardDriver.keygen()).rejects.toMatchObject({ code: 'internal' })
  })

  it('refuses an answer that carries no public key', async () => {
    // A keypair with a private half and no public one is unusable, and letting
    // it through would put an empty string in front of the user where the value
    // they have to authorise belongs.
    fakeNetd(respond(`{ privateKey: ${JSON.stringify(PRIV)} }`))

    await expect(wireguardDriver.keygen()).rejects.toMatchObject({ code: 'internal' })
  })

  it('ignores log events and unrelated ids while waiting for its own answer', async () => {
    fakeNetd(
      `process.stdout.write(JSON.stringify({ event: 'log', data: { level: 'info', msg: 'hello' } }) + '\\n')
     process.stdout.write(JSON.stringify({ id: '99', ok: true, result: { publicKey: 'wrong' } }) + '\\n')
     ${respond(`{ privateKey: ${JSON.stringify(PRIV)}, publicKey: ${JSON.stringify(PUB)} }`)}`
    )

    await expect(wireguardDriver.keygen()).resolves.toEqual({ privateKey: PRIV, publicKey: PUB })
  })

  it('times out rather than leaving a form on a spinner forever', async () => {
    const previous = wireguardTuning.keygenTimeoutMs
    wireguardTuning.keygenTimeoutMs = 200
    try {
      fakeNetd(`/* answers nothing, ever */`)
      await expect(wireguardDriver.keygen()).rejects.toMatchObject({ code: 'internal' })
    } finally {
      wireguardTuning.keygenTimeoutMs = previous
    }
  })
})

// --------------------------------------------------------------- real binary

// Runs whenever the sidecar has actually been built. Unlike the WireGuard
// handshake e2e it needs no network, no elevation and no seconds — it is two
// spawns — so gating it behind VPN_E2E as well would mean the arithmetic that
// matters most here went unchecked on every developer machine.
const platformDir = `${process.platform}-${process.arch}`
const exe = process.platform === 'win32' ? '.exe' : ''
const NETD = resolve(__dirname, '..', 'resources', 'bin', platformDir, `shellpilot-netd${exe}`)

describe.skipIf(!existsSync(NETD))('keygen against the built sidecar', () => {
  const useRealNetd = (): void => {
    wireguardTuning.resolveEngine = async () => ({
      kind: 'wireguard',
      available: true,
      bundled: true,
      path: NETD
    })
  }

  it('generates a pair whose public half it derives back from the private one', async () => {
    useRealNetd()
    const pair = await wireguardDriver.keygen()

    expect(pair.privateKey && isWireGuardKey(pair.privateKey)).toBe(true)
    expect(isWireGuardKey(pair.publicKey)).toBe(true)

    // The property that matters: the two halves belong to each other. Derived
    // in a second process from the private key alone, so nothing but the maths
    // can make these agree.
    const derived = await wireguardDriver.keygen({ publicKeyFor: pair.privateKey as string })
    expect(derived.publicKey).toBe(pair.publicKey)
    // The caller already has the private key; sending it back would put it on
    // the wire twice for nothing.
    expect(derived.privateKey).toBeUndefined()
  })

  // The belt, not the braces. Nothing on the keygen path writes the key to a
  // log, which is the actual protection — but if a future change ever did, the
  // redactor has to be able to catch a key this generator produced, and a
  // generator whose output the redactor's shape rule misses would defeat it
  // silently. Checked over enough keys to catch the encoding edge cases.
  it('produces keys the log redactor would blank if one ever escaped', async () => {
    useRealNetd()
    const pairs = await Promise.all(Array.from({ length: 16 }, () => wireguardDriver.keygen()))
    for (const pair of pairs) {
      const line = `configuring peer private_key ${pair.privateKey} on utun4`
      expect(redactOutput(line)).not.toContain(pair.privateKey as string)
    }
  })

  it('does not generate the same key twice', async () => {
    useRealNetd()
    const a = await wireguardDriver.keygen()
    const b = await wireguardDriver.keygen()
    expect(a.privateKey).not.toBe(b.privateKey)
  })

  it('rejects a malformed private key without quoting it back', async () => {
    useRealNetd()
    // The rejected value is a private key most of the time. An error message
    // is the easiest place for one to escape, because the message is what the
    // log drawer shows.
    const secret = 'sVvUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    const failure = await wireguardDriver.keygen({ publicKeyFor: `${secret}extra` }).catch((e) => e)
    expect(failure).toMatchObject({ code: 'config-invalid' })
    expect(JSON.stringify(failure)).not.toContain(secret)
    expect(String((failure as { detail?: string }).detail ?? '')).not.toContain(secret)
  })
})
