import { describe, it, expect } from 'vitest'
import { LogTailer } from '../src/main/services/logTail'
import type { LogLine, LogTailState } from '../src/shared/logtail'
import { LOG_RATE_PER_SEC } from '../src/shared/logtail'

// A following log never completes on its own, so everything here is about
// ending cleanly and not flooding. A tail holding a channel open after the pane
// closed is a leak that looks like nothing until an estate wonders why its sshd
// is busy.

function harness(over: { failFor?: string[] } = {}) {
  const lines: LogLine[] = []
  const states: LogTailState[] = []
  const stopped: string[] = []
  const feeds = new Map<string, { out: (s: string) => void; err: (s: string) => void; close: () => void }>()
  let clock = 0

  const tailer = new LogTailer({
    now: () => clock,
    emitLine: (l) => lines.push(l),
    emitState: (s) => states.push(s),
    execStream: async (cfg, _cmd, h) => {
      const id = (cfg as { id: string }).id
      if (over.failFor?.includes(id)) throw new Error(`refused by ${id}`)
      feeds.set(id, { out: h.onStdout, err: h.onStderr, close: () => h.onClose(0) })
      return () => stopped.push(id)
    }
  })
  return {
    tailer, lines, states, stopped, feeds,
    tick: (ms: number) => { clock += ms },
    targets: (ids: string[]) => ids.map((id) => ({ serverId: id, serverName: `host-${id}`, cfg: { id } }))
  }
}

const unit = { kind: 'unit' as const, target: 'nginx.service' }

describe('tailing a log across hosts', () => {
  it('streams lines tagged with the host that produced them', async () => {
    // An interleaved stream where you cannot tell which machine said what is
    // worse than separate tails, because it looks authoritative.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a', 'b']))
    h.feeds.get('a')!.out('one\ntwo\n')
    h.feeds.get('b')!.out('three\n')
    expect(h.lines.map((l) => `${l.serverId}:${l.text}`)).toEqual(['a:one', 'a:two', 'b:three'])
  })

  it('joins a line split across chunks', async () => {
    // Chunk boundaries land mid-line constantly; emitting halves separately
    // makes a log unreadable in exactly the moments it matters.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('hel')
    h.feeds.get('a')!.out('lo\n')
    expect(h.lines.map((l) => l.text)).toEqual(['hello'])
  })

  it('flushes a trailing partial line when the stream ends', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('last line with no newline')
    h.feeds.get('a')!.close()
    expect(h.lines.map((l) => l.text)).toEqual(['last line with no newline'])
  })

  it('marks stderr so a denied read is visible', async () => {
    // Otherwise "permission denied" vanishes and an empty pane reads as "this
    // log has nothing in it".
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.err('permission denied\n')
    expect(h.lines[0]).toMatchObject({ text: 'permission denied', isError: true })
  })

  it('keeps the other hosts when one refuses', async () => {
    // Comparing a failing host against a working one is most of why this reads
    // several at once.
    const h = harness({ failFor: ['a'] })
    const r = await h.tailer.start('t1', unit, h.targets(['a', 'b']))
    expect(r.ok).toBe(true)
    expect(h.states.find((s) => s.serverId === 'a' && s.state === 'failed')?.error).toMatch(/refused/)
    expect(h.states.some((s) => s.serverId === 'b' && s.state === 'streaming')).toBe(true)
  })

  it('reports failure when no host accepts', async () => {
    const h = harness({ failFor: ['a'] })
    expect(await h.tailer.start('t1', unit, h.targets(['a']))).toMatchObject({ ok: false })
    expect(h.tailer.isActive('t1')).toBe(false)
  })

  it('refuses a source it would have to escape', async () => {
    // Validated in main too, not only in the renderer: main is where the
    // command is built, and a boundary that trusts its caller is one refactor
    // from not being checked.
    const h = harness()
    const r = await h.tailer.start('t1', { kind: 'unit', target: 'x; reboot' }, h.targets(['a']))
    expect(r.ok).toBe(false)
    expect(h.feeds.size).toBe(0)
  })
})

describe('stopping', () => {
  it('stops every host and forgets the tail', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a', 'b']))
    h.tailer.stop('t1')
    expect(h.stopped.sort()).toEqual(['a', 'b'])
    expect(h.tailer.isActive('t1')).toBe(false)
  })

  it('stops the previous run when the same tail is started again', async () => {
    // Otherwise every line arrives twice and the pane looks like the host is
    // logging double.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    await h.tailer.start('t1', unit, h.targets(['a']))
    expect(h.stopped).toEqual(['a'])
  })

  it('stops everything on dispose', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    await h.tailer.start('t2', unit, h.targets(['b']))
    h.tailer.disposeAll()
    expect(h.stopped.sort()).toEqual(['a', 'b'])
  })
})

describe('a host that will not stop logging', () => {
  it('caps the rate and says how many it dropped', async () => {
    // A misconfigured service emitting tens of thousands of lines a second
    // becomes an IPC flood, and the user's conclusion is "ShellPilot froze"
    // rather than "that service is screaming".
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('x\n'.repeat(LOG_RATE_PER_SEC + 50))
    expect(h.lines).toHaveLength(LOG_RATE_PER_SEC)

    h.tick(1_100)
    h.feeds.get('a')!.out('later\n')
    const notice = h.lines.find((l) => l.text.includes('dropped'))
    expect(notice?.text).toMatch(/50 lines dropped/)
    expect(notice?.isError).toBe(true)
  })
})
