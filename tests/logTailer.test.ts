import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { LogTailer } from '../src/main/services/logTail'
import type { LogLine, LogTailState } from '../src/shared/logtail'
import { LOG_LINE_CAP, LOG_RATE_PER_SEC } from '../src/shared/logtail'

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

// A start that is still opening channels. execStream is awaited per host, so
// everything the user can do in that window — press Stop, restart the tail —
// lands while the loop is mid-await.
function deferredHarness() {
  const lines: LogLine[] = []
  const states: LogTailState[] = []
  const stopped: string[] = []
  const opening = new Map<string, () => void>()
  const feeds = new Map<string, (s: string) => void>()

  const tailer = new LogTailer({
    now: () => 0,
    emitLine: (l) => lines.push(l),
    emitState: (s) => states.push(s),
    execStream: async (cfg, _cmd, h) =>
      new Promise<() => void>((resolve) => {
        const id = (cfg as { id: string }).id
        opening.set(id, () => {
          feeds.set(id, h.onStdout)
          resolve(() => stopped.push(id))
        })
      })
  })
  return {
    tailer, lines, states, stopped, feeds,
    /** True once start() has reached the await for this host. */
    isOpening: (id: string) => opening.has(id),
    /** Let this host's channel finish opening. */
    open: async (id: string) => {
      opening.get(id)!()
      opening.delete(id)
      await Promise.resolve()
      await Promise.resolve()
    },
    settle: () => new Promise((r) => setTimeout(r, 0)),
    targets: (ids: string[]) => ids.map((id) => ({ serverId: id, serverName: `host-${id}`, cfg: { id } }))
  }
}

describe('stopping or restarting a tail that is still starting', () => {
  it('stops a channel that finishes opening after the stop', async () => {
    // The tail was registered in the map up front but each host's handle only
    // afterwards, so a stop landing in that window found nothing to stop and
    // then deleted the entry — and the channel that opened a moment later was
    // pushed onto an array no stop, restart or dispose could ever reach.
    const h = deferredHarness()
    const p = h.tailer.start('t1', unit, h.targets(['a', 'b']))
    await h.settle()
    h.tailer.stop('t1')
    await h.open('a')
    await p
    expect(h.stopped).toEqual(['a'])
    // And it does not go on to open the hosts behind it.
    expect(h.isOpening('b')).toBe(false)
    expect(h.tailer.isActive('t1')).toBe(false)
  })

  it('stops the superseded channel and keeps its lines out of the pane', async () => {
    // Two starts under one id: the first must not go on streaming into a tail
    // the second now owns, which is the doubled stream the restart guard
    // exists to prevent.
    const h = deferredHarness()
    const first = h.tailer.start('t1', unit, h.targets(['a']))
    await h.settle()
    const second = h.tailer.start('t1', unit, h.targets(['b']))
    await h.settle()
    await h.open('a')
    expect(await first).toMatchObject({ ok: false })
    await h.open('b')
    expect(await second).toMatchObject({ ok: true })

    expect(h.stopped).toEqual(['a'])
    h.feeds.get('a')!('ghost\n')
    h.feeds.get('b')!('real\n')
    expect(h.lines.map((l) => l.text)).toEqual(['real'])
  })
})

describe('a host that never sends a newline', () => {
  it('emits the buffer in pieces rather than growing it forever', async () => {
    // The partial-line buffer is memory in main sized by whatever the remote
    // host feels like sending: a binary file under `tail -F`, a progress bar,
    // one JSON object per event.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('x'.repeat(LOG_LINE_CAP * 2 + 5))
    expect(h.lines).toHaveLength(2)
    expect(h.lines.every((l) => l.text.length === LOG_LINE_CAP)).toBe(true)
    // What is left is under the cap, and still arrives when the line ends.
    h.feeds.get('a')!.out('\n')
    expect(h.lines).toHaveLength(3)
    expect(h.lines[2].text).toHaveLength(5)
  })

  it('splits an over-long complete line too', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out(`${'y'.repeat(LOG_LINE_CAP + 3)}\n`)
    expect(h.lines).toHaveLength(2)
    expect(h.lines[1].text).toHaveLength(3)
  })

  it("keeps each host's buffer to itself", async () => {
    // Partial lines are per host; merging them would splice one machine's
    // sentence onto another's.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a', 'b']))
    h.feeds.get('a')!.out('from-a-')
    h.feeds.get('b')!.out('from-b-')
    h.feeds.get('a')!.out('one\n')
    h.feeds.get('b')!.out('two\n')
    expect(h.lines.map((l) => `${l.serverId}:${l.text}`)).toEqual(['a:from-a-one', 'b:from-b-two'])
  })
})

describe('the last thing a throttled host said', () => {
  it('reports the drops when the stream ends', async () => {
    // The count was only flushed by a later line arriving, so the final window
    // had nowhere to report: a host that screamed and then died left the pane
    // showing exactly the cap and no explanation, which reads as "it stopped
    // logging" rather than "we stopped showing it".
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('x\n'.repeat(LOG_RATE_PER_SEC + 7))
    h.feeds.get('a')!.close()
    expect(h.lines.find((l) => l.text.includes('dropped'))?.text).toMatch(/7 lines dropped/)
  })

  it('reports the drops when the user presses Stop', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('x\n'.repeat(LOG_RATE_PER_SEC + 3))
    h.tailer.stop('t1')
    expect(h.lines.find((l) => l.text.includes('dropped'))?.text).toMatch(/3 lines dropped/)
  })

  it('says nothing when nothing was dropped', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('quiet\n')
    h.tailer.stop('t1')
    expect(h.lines.some((l) => l.text.includes('dropped'))).toBe(false)
  })
})

describe('the panel that drives it', () => {
  const panel = readFileSync(resolve(__dirname, '../src/renderer/src/components/monitor/LogTailPanel.tsx'), 'utf8')

  it('does not stay showing Stop for a tail that ended on its own', () => {
    // `tail -F` on a path that never appears exits; journalctl dies with the
    // connection. `running` was only ever cleared by pressing Stop.
    expect(panel).toMatch(/state === 'ended' \|\| s\.state === 'failed'/)
  })

  it('treats a missing bridge as a tail that did not start', () => {
    expect(panel).toMatch(/if \(!res \|\| !res\.ok\)/)
  })

  it('leaves the panel usable if the start or stop call throws', () => {
    expect(panel).toMatch(/catch \(e\)[\s\S]{0,200}setRunning\(false\)/)
    expect(panel).toMatch(/} finally \{[\s\S]{0,300}setRunning\(false\)/)
  })
})
