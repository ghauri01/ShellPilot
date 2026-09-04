import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { LogTailer } from '../src/main/services/logTail'
import type { LogLine, LogTailState } from '../src/shared/logtail'
import { LOG_LINE_CAP, LOG_MARK, LOG_PAUSE_BUFFER, LOG_RATE_PER_SEC } from '../src/shared/logtail'

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

// ---------------------------------------------------------------------------
// The preflight's facts and the log arrive on the same channel. They are told
// apart by ORDER: markers count only before `begin`, and the tail is not exec'd
// until `begin` has been printed, so nothing a remote log says can be in a
// position to claim, for instance, that it was read as root.

const M = LOG_MARK

describe('what the preflight says, and where it says it', () => {
  it('keeps its facts out of the pane', async () => {
    // They used to be indistinguishable from log content, because they did not
    // exist: the pane simply showed `sh: journalctl: not found` as a log line.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out(`${M}journal=present\n${M}entries=1\n${M}begin=1\nreal log line\n`)
    expect(h.lines.map((l) => l.text)).toEqual(['real log line'])
  })

  it('puts the diagnosis on the host state, where it can be shown all tail long', async () => {
    // Not into the stream. A tail is long-lived and a notice written once as a
    // log line has scrolled away within the second.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out(`${M}unit-load=loaded\n${M}entries=0\n${M}priv=0\n${M}sudo=0\n${M}begin=1\n`)
    const s = h.states.filter((x) => x.diagnosis).pop()
    expect(s?.diagnosis?.issue).toBe('journal-unreadable')
  })

  it('says root was used for as long as the tail runs, not once at the start', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out(`${M}sudo=1\n${M}entries=0\n${M}priv=0\n${M}begin=1\n`)
    h.feeds.get('a')!.out('a line\n')
    h.feeds.get('a')!.close()
    // Every state emitted after the preflight carries it, including the last.
    expect(h.states[h.states.length - 1]).toMatchObject({ state: 'ended', diagnosis: { usedSudo: true } })
  })

  it('will not let a log line forge a fact once the tail has started', async () => {
    // A remote host can print anything, including our own marker bytes. It
    // cannot print them BEFORE the preflight has handed over, which is the only
    // window in which they mean anything.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out(`${M}sudo=0\n${M}begin=1\n`)
    h.feeds.get('a')!.out(`${M}sudo=1\n`)
    expect(h.lines.map((l) => l.text)).toEqual([`${M}sudo=1`])
    expect(h.states.filter((s) => s.diagnosis).pop()?.diagnosis?.usedSudo).toBe(false)
  })

  it('still reports a preflight that never got as far as tailing', async () => {
    // No journalctl on the host: the command prints one fact and exits, so
    // `begin` never arrives. Without settling the diagnosis at close, the one
    // case the preflight exists to catch is the one case it says nothing about.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out(`${M}journal=missing\n`)
    h.feeds.get('a')!.close()
    expect(h.states[h.states.length - 1]).toMatchObject({ state: 'ended', diagnosis: { issue: 'no-journal' } })
    expect(h.lines).toHaveLength(0)
  })
})

describe('pausing a tail rather than killing it', () => {
  it('holds the lines and leaves the channel open', async () => {
    // Stop used to be the only way to make the pane sit still, and it closed
    // journalctl on every host and threw the buffer away.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.feeds.get('a')!.out('before\n')
    h.tailer.pause('t1')
    h.feeds.get('a')!.out('during-one\nduring-two\n')
    expect(h.lines.map((l) => l.text)).toEqual(['before'])
    expect(h.stopped).toEqual([])
    expect(h.tailer.isActive('t1')).toBe(true)

    h.tailer.resume('t1')
    expect(h.lines.map((l) => l.text)).toEqual(['before', 'during-one', 'during-two'])
  })

  it('reports what it had to drop rather than leaving a silent gap', async () => {
    // Same rule as the rate limiter: a gap nobody mentions is how someone
    // concludes a service stopped logging.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.tailer.pause('t1')
    // Past the per-second cap, so the clock is wound on between bursts.
    for (let i = 0; i < LOG_PAUSE_BUFFER + 40; i++) {
      h.tick(10)
      h.feeds.get('a')!.out(`line-${i}\n`)
    }
    h.tailer.resume('t1')
    expect(h.lines).toHaveLength(LOG_PAUSE_BUFFER + 1)
    // The newest are what someone waiting on an incident wants, so the oldest go.
    expect(h.lines[0].text).toBe('line-40')
    expect(h.lines[h.lines.length - 1].text).toMatch(/40 lines dropped while paused/)
  })

  it('does not lose the held lines if the user stops instead of resuming', async () => {
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.tailer.pause('t1')
    h.feeds.get('a')!.out('held\n')
    h.tailer.stop('t1')
    expect(h.lines.map((l) => l.text)).toEqual(['held'])
    expect(h.stopped).toEqual(['a'])
    expect(h.tailer.isPaused('t1')).toBe(false)
  })

  it('does not start a new tail into an old hold', async () => {
    // Nothing on screen would say why the new stream was empty.
    const h = harness()
    await h.tailer.start('t1', unit, h.targets(['a']))
    h.tailer.pause('t1')
    await h.tailer.start('t1', unit, h.targets(['b']))
    expect(h.tailer.isPaused('t1')).toBe(false)
    h.feeds.get('b')!.out('fresh\n')
    expect(h.lines.map((l) => l.text)).toEqual(['fresh'])
  })

  it('refuses to pause something that is not running', async () => {
    const h = harness()
    expect(h.tailer.pause('nope')).toBe(false)
    expect(h.tailer.resume('nope')).toBe(false)
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

  it('says what a filtered count is a count of', () => {
    // "12 lines" under a filter reads as a quiet host. The denominator is what
    // makes it a filter rather than a claim about the log.
    expect(panel).toMatch(/of \$\{lines\.length\} lines match/)
  })

  it('draws the diagnosis and the root badge outside the scrolling stream', () => {
    // Inside it, both scroll away — which for "reading as root" means a
    // privileged tail becomes indistinguishable from an ordinary one after a
    // second of traffic.
    const stream = panel.indexOf('className="bc-out log-stream"')
    expect(panel.indexOf('reading as root')).toBeLessThan(stream)
    expect(panel.indexOf('LOG_ISSUE_HELP[d.issue]')).toBeLessThan(stream)
  })

  it('does not dress a pane that may yet fill as a failure', () => {
    // A file tail -F is waiting for, or a unit that genuinely has not spoken,
    // is not the same kind of thing as a masked unit or a denied read.
    //
    // The two roles were renamed when the panels were given a shared visual
    // language: `s-desc` had no rule outside a settings row, so neither branch
    // of this was rendering in any colour at all, and `danger` as a bare class
    // has never had a rule either. What this test guards is unchanged — that
    // waiting and failing are drawn differently — so it now names the roles
    // that actually paint.
    expect(panel).toMatch(/clsx\('panel-note', d\.waiting \? 'is-unknown' : 'is-alarm'\)/)
  })

  it('offers root only when it would help and cannot prompt', () => {
    // Same discipline as docker: `sudo -n` never asks, so the button cannot
    // produce a password prompt on a host that would want one.
    expect(panel).toMatch(
      /!d\.usedSudo && d\.sudoAvailable && \(d\.issue === 'journal-unreadable' \|\| d\.issue === 'file-denied'\)/
    )
    expect(panel).toMatch(/sudo: 'always'/)
  })

  it('says so rather than pretending, when the pause bridge is not wired', () => {
    // A Pause button that flips its own label over a stream nobody paused is
    // worse than no button.
    expect(panel).toMatch(/typeof call !== 'function'/)
  })

  it('sends journalctl-only flags only for a unit', () => {
    expect(panel).toMatch(/kind === 'unit' && priority !== '' \? \{ priority \}/)
    expect(panel).toMatch(/kind === 'unit' && since\.trim\(\) !== '' \? \{ since/)
  })
})
