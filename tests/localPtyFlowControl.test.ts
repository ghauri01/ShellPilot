import { describe, it, expect, vi, afterEach } from 'vitest'
import type { WebContents } from 'electron'
import {
  coalescer,
  FLOW_HIGH_WATER,
  FLOW_LOW_WATER,
  flowWindow,
  localConnect,
  outputPipe
} from '../src/main/services/localPty'

/** Records everything the main process would push down an IPC channel. */
function fakeWebContents(): { wc: WebContents; sent: { channel: string; args: unknown[] }[] } {
  const sent: { channel: string; args: unknown[] }[] = []
  const wc = {
    isDestroyed: () => false,
    send: (channel: string, ...args: unknown[]) => sent.push({ channel, args })
  } as unknown as WebContents
  return { wc, sent }
}

describe('output coalescer', () => {
  it('batches everything that arrives in one tick into a single send', async () => {
    const sent: string[] = []
    const c = coalescer((payload) => sent.push(payload))
    c.push(Buffer.from('a'))
    c.push(Buffer.from('b'))
    c.push(Buffer.from('c'))
    expect(sent).toEqual([])
    await new Promise((r) => setTimeout(r, 5))
    expect(sent).toEqual(['abc'])
  })

  it('flushes what is pending when the session closes', () => {
    const sent: string[] = []
    const c = coalescer((payload) => sent.push(payload))
    c.push(Buffer.from('tail'))
    c.dispose()
    expect(sent).toEqual(['tail'])
  })
})

describe('backpressure window', () => {
  it('pauses above the high-water mark and resumes below the low-water mark', () => {
    const events: string[] = []
    const w = { pause: () => events.push('pause'), resume: () => events.push('resume') }
    const { onSent, onAck } = flowWindow(w)
    onSent(FLOW_HIGH_WATER + 1)
    expect(events).toEqual(['pause'])
    onAck(FLOW_HIGH_WATER + 1 - FLOW_LOW_WATER + 1)
    expect(events).toEqual(['pause', 'resume'])
  })

  it('does not pause twice or resume without having paused', () => {
    const events: string[] = []
    const w = { pause: () => events.push('pause'), resume: () => events.push('resume') }
    const { onSent, onAck } = flowWindow(w)
    onAck(10)
    expect(events).toEqual([])
    onSent(FLOW_HIGH_WATER + 1)
    onSent(1)
    expect(events).toEqual(['pause'])
    onAck(FLOW_HIGH_WATER + 2)
    expect(events).toEqual(['pause', 'resume'])
  })

  it('clamps an over-ack to zero rather than going negative', () => {
    const w = { pause: () => {}, resume: () => {} }
    const { onSent, onAck, outstanding } = flowWindow(w)
    onSent(100)
    onAck(10_000)
    expect(outstanding()).toBe(0)
  })
})

// Finding #3. The window used to be driven with Buffer.byteLength(payload) on
// the send side while the renderer acks with the received string's `.length`
// (UTF-16 code units). Every multi-byte character left an unrepayable deficit,
// and once it crossed FLOW_HIGH_WATER the pty stayed paused forever.
//
// These tests go through the real production wiring — outputPipe is what
// localConnect builds — so they fail if the counting unit is ever changed back.
describe('flow window accounting across the real coalescer', () => {
  // Emoji (surrogate pair, 4 bytes / 2 units), CJK (3 bytes / 1 unit),
  // box-drawing (3 bytes / 1 unit), combining accent, and plain ASCII.
  const MULTIBYTE = '🚀 箱 ─│┌┐ café ✓'

  it('returns the window to zero when the renderer acks the string it received', () => {
    const received: string[] = []
    const pipe = outputPipe({ pause: () => {}, resume: () => {} }, (p) => received.push(p))

    pipe.push(Buffer.from(MULTIBYTE, 'utf8'))
    pipe.dispose() // synchronous flush

    expect(received).toEqual([MULTIBYTE])
    // The renderer's ack is `d.length` on the string it got off the IPC channel.
    for (const d of received) pipe.onAck(d.length)

    // Byte counting on the send side leaves MULTIBYTE's byte/unit deficit here.
    expect(Buffer.byteLength(MULTIBYTE, 'utf8')).toBeGreaterThan(MULTIBYTE.length)
    expect(pipe.outstanding()).toBe(0)
  })

  it('reopens the window after a multi-byte burst past the high-water mark', () => {
    const events: string[] = []
    const received: string[] = []
    const pipe = outputPipe(
      { pause: () => events.push('pause'), resume: () => events.push('resume') },
      (p) => received.push(p)
    )

    // Enough code units to cross the high-water mark on its own.
    const unit = '🚀' // 2 UTF-16 code units, 4 UTF-8 bytes
    const burst = unit.repeat(FLOW_HIGH_WATER)
    expect(burst.length).toBeGreaterThan(FLOW_HIGH_WATER)

    pipe.push(Buffer.from(burst, 'utf8'))
    pipe.dispose()
    expect(events).toEqual(['pause'])

    for (const d of received) pipe.onAck(d.length)

    // Under byte counting the leftover deficit is burst.length (one byte per
    // code unit), far above FLOW_LOW_WATER, so 'resume' would never fire.
    expect(events).toEqual(['pause', 'resume'])
    expect(pipe.outstanding()).toBe(0)
  })

  it('ignores a non-finite ack instead of poisoning the window', () => {
    const events: string[] = []
    const pipe = outputPipe(
      { pause: () => events.push('pause'), resume: () => events.push('resume') },
      () => {}
    )
    pipe.onAck(Number.NaN)
    pipe.push(Buffer.from('x'.repeat(FLOW_HIGH_WATER + 1)))
    pipe.dispose()
    expect(events).toEqual(['pause'])
    expect(Number.isFinite(pipe.outstanding())).toBe(true)
  })
})

// The module must stay importable on a machine where @lydell/node-pty cannot
// load at all — that is the entire reason loadPty() is lazy. If any of the
// pure exports above ever moves behind a static import of the native binding,
// this file stops importing and every test here fails, which is the signal.
describe('module load', () => {
  it('exposes its pure exports without touching the native binding', async () => {
    const mod = await import('../src/main/services/localPty')
    expect(typeof mod.coalescer).toBe('function')
    expect(typeof mod.flowWindow).toBe('function')
    expect(typeof mod.outputPipe).toBe('function')
    expect(mod.FLOW_HIGH_WATER).toBeGreaterThan(mod.FLOW_LOW_WATER)
  })
})

describe('localConnect refuses before it ever loads the binding', () => {
  afterEach(() => {
    delete process.env.ELECTRON_DISABLE_LOCAL_TERMINAL
    vi.resetModules()
  })

  // Finding #25: findShell is exact-match-or-null, so this error path is now
  // reachable rather than dead code behind a silent fallback to the default
  // shell. An unknown or attacker-chosen shellId must fail, not spawn.
  it('reports an error for an unknown shellId instead of falling back', async () => {
    const { wc, sent } = fakeWebContents()
    await localConnect(wc, {
      sessionId: 'test-unknown-shell',
      shellId: 'definitely-not-a-real-shell-id',
      cols: 80,
      rows: 24
    })
    const phases = sent
      .filter((s) => s.channel === 'local:status:test-unknown-shell')
      .map((s) => s.args[0] as { phase: string; message?: string })
    expect(phases.map((p) => p.phase)).toEqual(['spawning', 'error'])
    expect(phases[1].message).toContain('definitely-not-a-real-shell-id')
  })

  // Finding #6: the rollback rows promise this env var actually disables the
  // feature. It must short-circuit loadPty() *before* the native import, so a
  // machine the binding wedges can still start the app.
  it('honours ELECTRON_DISABLE_LOCAL_TERMINAL=1 for a shell that does exist', async () => {
    const { listShells } = await import('../src/main/services/shellDiscovery')
    const shells = await listShells(true)
    if (shells.length === 0) return // nothing discoverable on this runner

    process.env.ELECTRON_DISABLE_LOCAL_TERMINAL = '1'
    // Fresh module instance: loadPty caches its failure in a module-level
    // variable, and poisoning the shared instance would leak into other tests.
    vi.resetModules()
    const fresh = await import('../src/main/services/localPty')

    const { wc, sent } = fakeWebContents()
    await fresh.localConnect(wc, {
      sessionId: 'test-disabled',
      shellId: shells[0].id,
      cols: 80,
      rows: 24
    })
    const last = sent
      .filter((s) => s.channel === 'local:status:test-disabled')
      .map((s) => s.args[0] as { phase: string; message?: string })
      .at(-1)
    expect(last?.phase).toBe('error')
    expect(last?.message).toContain('ELECTRON_DISABLE_LOCAL_TERMINAL')
  })
})
