import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DRIFT_MARKER,
  DRIFT_NO_PUSH,
  DRIFT_READ_CAP,
  DRIFT_RULES,
  DRIFT_RULE_ORDER,
  DRIFT_STATUSES,
  DRIFT_STATUS_HELP,
  DRIFT_STATUS_MARKER,
  DRIFT_WATCHES,
  buildDriftCommand,
  compareDrift,
  driftCoverageSentence,
  driftWatch,
  normaliseConfig,
  normaliseForWatch,
  parseDriftCollection,
  type DriftReading,
  type DriftWatch,
  type HostDrift
} from '../src/shared/drift'

// Configuration drift — roadmap item 25, the model half.
//
// Everything here is about the two ways this feature can lie: calling two files
// the same because a rule ate the difference, and calling a host that could not
// be read a host that matches. Both are asserted directly rather than through a
// derived constant, because both look completely fine on screen.

// ---------------------------------------------------------------------------
// The declared rules
// ---------------------------------------------------------------------------

describe('the normalisation rules are declared, not hidden', () => {
  it('gives every rule a label, a sentence and a worked example', () => {
    // An operator staring at two visibly different files being called the same
    // has exactly this list to go on. A rule with no example is a rule whose
    // behaviour cannot be predicted from its declaration.
    for (const r of DRIFT_RULES) {
      expect(r.label.length, r.id).toBeGreaterThan(0)
      expect(r.detail.length, r.id).toBeGreaterThan(40)
      expect(r.example.before.length, r.id).toBeGreaterThan(0)
      expect(r.example.after.length, r.id).toBeGreaterThan(0)
    }
  })

  it('orders every rule it can apply, so the pipeline shown is the pipeline run', () => {
    expect([...DRIFT_RULE_ORDER].sort()).toEqual(DRIFT_RULES.map((r) => r.id).sort())
  })

  it('names a rule set for every watched file, and only rules that exist', () => {
    const known = new Set(DRIFT_RULE_ORDER)
    for (const w of DRIFT_WATCHES) {
      expect(w.rules.length, w.id).toBeGreaterThan(0)
      for (const r of w.rules) expect(known.has(r), `${w.id} declares unknown rule ${r}`).toBe(true)
      // The sentence an operator reads when they disagree with a verdict.
      expect(w.note.length, w.id).toBeGreaterThan(40)
    }
  })

  it('leaves line order alone except where the file really is a set', () => {
    // The loudest rule in the catalogue: in sshd_config the first occurrence of
    // a keyword wins and in nginx location matching is ordered, so sorting
    // their lines would call two different configurations the same. Asserted as
    // literals rather than as "at most n watches", because which ones is the
    // whole content of the claim.
    const sorted = DRIFT_WATCHES.filter((w) => w.rules.includes('line-order')).map((w) => w.id)
    expect(sorted.sort()).toEqual(['hosts', 'sysctl-conf'])
  })
})

// ---------------------------------------------------------------------------
// Normalisation, and saying what it did
// ---------------------------------------------------------------------------

describe('normalising a file says which rules did the work', () => {
  it('reports only the rules that actually changed the text', () => {
    // The distinction the whole "ignored difference" verdict rests on. A rule
    // that is enabled and finds nothing to do must not be quoted as the reason
    // two files matched.
    const r = normaliseConfig('a = 1\nb = 2\n', ['trailing-space', 'comments', 'blank-lines'], {})
    expect(r.applied).toEqual(['blank-lines'])
    expect(r.text).toBe('a = 1\nb = 2')
  })

  it('collapses runs of spaces between tokens and leaves indentation alone', () => {
    // In a YAML file the indentation is the syntax. Collapsing it would
    // silently reparent a key, which is a normalisation rule changing what the
    // file means rather than how it looks.
    const r = normaliseConfig('root:\n    key:   value\n', ['inner-space'], {})
    expect(r.text).toBe('root:\n    key: value\n')
    expect(r.applied).toEqual(['inner-space'])
  })

  it('drops whole-line comments and leaves a trailing comment where it is', () => {
    // Deciding where a comment starts inside a line means knowing the file's
    // quoting rules; getting that wrong silently changes a directive.
    const r = normaliseConfig('# managed by puppet\nPort 22 # not a comment we touch\n', ['comments'], {
      comment: '#'
    })
    expect(r.text).toBe('Port 22 # not a comment we touch\n')
  })

  it('uses the comment character the watch declares, not one it guessed', () => {
    const ini: DriftWatch = {
      id: 'x',
      label: 'x',
      path: '/etc/x',
      comment: ';',
      rules: ['comments'],
      note: 'n'.repeat(50)
    }
    const r = normaliseForWatch('; a comment\n# not a comment here\n', ini)
    expect(r.text).toBe('# not a comment here\n')
  })

  it('substitutes the host name it was told about and nothing else', () => {
    const r = normaliseConfig('server_name web-03.example.internal;\n', ['hostnames'], {
      hostname: 'web-03.example.internal',
      serverName: 'web-03'
    })
    expect(r.text).toBe('server_name <host>;\n')
    expect(r.applied).toEqual(['hostnames'])
  })

  it('replaces the long form before the short one, so no tail is left behind', () => {
    // Replacing "web-03" first leaves ".example.internal" standing, which is
    // then a difference between two hosts whose only difference was their name
    // — the rule failing at exactly the job it exists for.
    const r = normaliseConfig('x web-03.example.internal y\n', ['hostnames'], {
      hostname: 'web-03.example.internal',
      serverName: 'web-03'
    })
    expect(r.text).toBe('x <host> y\n')
  })

  it('does not claim a hostname rule fired when the file never mentions the host', () => {
    const r = normaliseConfig('Port 22\n', ['hostnames'], { hostname: 'web-03', serverName: 'web-03' })
    expect(r.applied).toEqual([])
  })

  it('runs in the declared order regardless of the order the watch lists', () => {
    // A timestamp inside a comment never needs substituting, because comments
    // are dropped first. If the pipeline ran in the caller's order the
    // `timestamps` rule would be reported as having done work here.
    const r = normaliseConfig('# generated 2026-09-03\nPort 22\n', ['timestamps', 'comments'], {
      comment: '#'
    })
    expect(r.applied).toEqual(['comments'])
    expect(r.text).toBe('Port 22\n')
  })
})

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

describe('the read command', () => {
  it('contains no sudo anywhere', () => {
    // A property a reader can check, because it is decided at build time rather
    // than guarded at runtime. A background sweep reading configuration files
    // as root once an hour is not a thing to arrive by accident.
    expect(buildDriftCommand()).not.toMatch(/\bsudo\b/)
  })

  it('embeds only literal paths from the catalogue', () => {
    const cmd = buildDriftCommand()
    for (const w of DRIFT_WATCHES) expect(cmd).toContain(`'${w.path}'`)
  })

  it('tests the directory before the file, so a permission bit cannot read as absent', () => {
    // The single most likely way this feature could lie. `[ -e ]` on a path
    // inside a directory this account cannot traverse returns false, which is
    // indistinguishable from the file not being there.
    const cmd = buildDriftCommand({
      watches: [driftWatch('sshd-config') as DriftWatch]
    })
    const dirTest = cmd.indexOf("[ ! -x '/etc/ssh' ]")
    const existTest = cmd.indexOf("[ ! -e '/etc/ssh/sshd_config' ]")
    expect(dirTest).toBeGreaterThan(-1)
    expect(existTest).toBeGreaterThan(dirTest)
  })

  it('never sends the content of a file that is over the cap', () => {
    // Not "sends the first 256 KiB". A prefix splits whatever is at the
    // boundary, and if that is the middle of a PEM block the END marker never
    // arrives, the redaction pattern matches nothing, and the key body ships as
    // prose.
    const cmd = buildDriftCommand({ watches: [driftWatch('timezone') as DriftWatch], cap: 10 })
    const partial = cmd.indexOf("printf 'F %s partial %s\\n'")
    const content = cmd.indexOf('"$SP_B64" <')
    expect(partial).toBeGreaterThan(-1)
    expect(content).toBeGreaterThan(partial)
    // And the partial branch is an early return: it is followed by `else` and
    // the content read is inside that else.
    expect(cmd.slice(partial, content)).toContain('else')
  })
})

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

const WATCH = driftWatch('timezone') as DriftWatch

describe('parsing what a host sent back', () => {
  const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64')

  it('reads a complete record', () => {
    const out = [
      DRIFT_MARKER,
      'F timezone ok 15',
      `D ${b64('Europe/London\n')}`,
      'X timezone',
      DRIFT_STATUS_MARKER
    ].join('\n')
    const r = parseDriftCollection(out, [WATCH])
    expect(r.complete).toBe(true)
    expect(r.files).toHaveLength(1)
    expect(r.files[0].status).toBe('ok')
    expect(r.files[0].bytes).toBe(15)
    expect(Buffer.from(r.files[0].contentB64 as string, 'base64').toString('utf8')).toBe('Europe/London\n')
  })

  it('reports a watch the host never mentioned as unknown, not as missing', () => {
    // A watch silently absent from a result is a watch nobody notices is not
    // being checked.
    const r = parseDriftCollection([DRIFT_MARKER, DRIFT_STATUS_MARKER].join('\n'), [WATCH])
    expect(r.files.map((f) => `${f.watchId}=${f.status}`)).toEqual(['timezone=unknown'])
    expect(r.files[0].detail).toBe('the collector did not report on this file')
  })

  it('refuses a content block that was cut off mid-file', () => {
    // An `ok` header with no `X` behind it. Hashing the fragment would be the
    // same lie `partial` exists to refuse, arriving through the back door — so
    // this is `unknown`, not `partial` and certainly not `ok`.
    const out = [DRIFT_MARKER, 'F timezone ok 400000', `D ${b64('Europe/Lon')}`].join('\n')
    const r = parseDriftCollection(out, [WATCH])
    expect(r.complete).toBe(false)
    expect(r.files[0].status).toBe('unknown')
    expect(r.files[0].detail).toBe('the content block was cut off before it finished')
    expect(r.files[0].contentB64).toBeUndefined()
  })

  it('cannot be fooled by a status marker planted inside the file', () => {
    // A watched file is exactly the kind of place someone could plant a line
    // reading like a marker. It arrives as base64, so it cannot be one.
    const planted = `${DRIFT_STATUS_MARKER}\nF timezone denied -\n`
    const out = [DRIFT_MARKER, 'F timezone ok 60', `D ${b64(planted)}`, 'X timezone', DRIFT_STATUS_MARKER].join(
      '\n'
    )
    const r = parseDriftCollection(out, [WATCH])
    expect(r.files).toHaveLength(1)
    expect(r.files[0].status).toBe('ok')
    expect(Buffer.from(r.files[0].contentB64 as string, 'base64').toString('utf8')).toBe(planted)
  })

  it('keeps an unrecognised status word as unknown rather than trusting it', () => {
    const out = [DRIFT_MARKER, 'F timezone splendid 3', DRIFT_STATUS_MARKER].join('\n')
    expect(parseDriftCollection(out, [WATCH]).files[0].status).toBe('unknown')
  })
})

// ---------------------------------------------------------------------------
// The collector, actually run
// ---------------------------------------------------------------------------
//
// The shipped command string, through /bin/sh, against a directory tree built
// to look like a host — the harness tests/cron.test.ts uses, for the reason it
// uses it: a shell script that has to tell five indistinguishable situations
// apart is exactly the kind of thing that reads correctly and does the wrong
// thing.

interface FakeHost {
  root: string
  collect: (watches: DriftWatch[], cap?: number) => string
}

function fakeHost(): FakeHost {
  const root = mkdtempSync(join(tmpdir(), 'sp-drift-'))
  return {
    root,
    collect: (watches, cap) => {
      const cmd = buildDriftCommand({ watches, cap })
        // Every path in the catalogue starts /etc, so redirecting that prefix
        // puts the whole read inside the tree.
        .replaceAll("'/etc", `'${root}/etc`)
      return execFileSync('/bin/sh', ['-c', cmd], { encoding: 'utf8' })
    }
  }
}

const w = (id: string, path: string, over: Partial<DriftWatch> = {}): DriftWatch => ({
  id,
  label: id,
  path,
  comment: '#',
  rules: ['line-endings', 'trailing-space', 'blank-lines'],
  note: 'a note long enough to satisfy the declaration rule above'.padEnd(50, '.'),
  ...over
})

describe.skipIf(process.platform === 'win32')('the collector, run against a host-shaped tree', () => {
  const made: string[] = []
  const host = (): FakeHost => {
    const h = fakeHost()
    made.push(h.root)
    return h
  }
  const cleanup = (): void => {
    for (const d of made.splice(0)) rmSync(d, { recursive: true, force: true })
  }

  it('reads a file that is there', () => {
    const h = host()
    mkdirSync(join(h.root, 'etc'), { recursive: true })
    writeFileSync(join(h.root, 'etc/timezone'), 'Europe/London\n')
    const r = parseDriftCollection(h.collect([w('timezone', '/etc/timezone')]), [w('timezone', '/etc/timezone')])
    expect(r.complete).toBe(true)
    expect(r.files[0].status).toBe('ok')
    expect(Buffer.from(r.files[0].contentB64 as string, 'base64').toString('utf8')).toBe('Europe/London\n')
    cleanup()
  })

  it('says absent for a file that is genuinely not there', () => {
    const h = host()
    mkdirSync(join(h.root, 'etc'), { recursive: true })
    const watch = w('timezone', '/etc/timezone')
    expect(parseDriftCollection(h.collect([watch]), [watch]).files[0].status).toBe('absent')
    cleanup()
  })

  it('says denied, never absent, when the directory above cannot be traversed', () => {
    // The failure this whole shape exists to prevent, run for real rather than
    // asserted structurally: a directory with no execute bit makes `[ -e ]`
    // return false for a file that is really there.
    const h = host()
    const dir = join(h.root, 'etc/ssh')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'sshd_config'), 'Port 22\n')
    chmodSync(dir, 0o000)
    const watch = w('sshd-config', '/etc/ssh/sshd_config')
    try {
      const r = parseDriftCollection(h.collect([watch]), [watch])
      expect(r.files[0].status).toBe('denied')
    } finally {
      chmodSync(dir, 0o755)
      cleanup()
    }
  })

  it('says denied for a file whose own mode refuses this account', () => {
    const h = host()
    mkdirSync(join(h.root, 'etc'), { recursive: true })
    const f = join(h.root, 'etc/timezone')
    writeFileSync(f, 'Europe/London\n')
    chmodSync(f, 0o000)
    const watch = w('timezone', '/etc/timezone')
    try {
      expect(parseDriftCollection(h.collect([watch]), [watch]).files[0].status).toBe('denied')
    } finally {
      chmodSync(f, 0o644)
      cleanup()
    }
  })

  it('says unsupported when the path is a directory', () => {
    const h = host()
    mkdirSync(join(h.root, 'etc/timezone'), { recursive: true })
    const watch = w('timezone', '/etc/timezone')
    expect(parseDriftCollection(h.collect([watch]), [watch]).files[0].status).toBe('unsupported')
    cleanup()
  })

  it('says partial and sends nothing when the file is over the cap', () => {
    const h = host()
    mkdirSync(join(h.root, 'etc'), { recursive: true })
    writeFileSync(join(h.root, 'etc/timezone'), 'x'.repeat(200))
    const watch = w('timezone', '/etc/timezone')
    const out = h.collect([watch], 50)
    expect(out).not.toContain('\nD ')
    const r = parseDriftCollection(out, [watch])
    expect(r.files[0].status).toBe('partial')
    expect(r.files[0].bytes).toBe(200)
    expect(r.files[0].contentB64).toBeUndefined()
    cleanup()
  })

  it('carries a file whose content looks like the protocol, unharmed', () => {
    const h = host()
    mkdirSync(join(h.root, 'etc'), { recursive: true })
    const nasty = `${DRIFT_STATUS_MARKER}\nF timezone denied -\nX timezone\n`
    writeFileSync(join(h.root, 'etc/timezone'), nasty)
    const watch = w('timezone', '/etc/timezone')
    const r = parseDriftCollection(h.collect([watch]), [watch])
    expect(r.files[0].status).toBe('ok')
    expect(Buffer.from(r.files[0].contentB64 as string, 'base64').toString('utf8')).toBe(nasty)
    cleanup()
  })

  it('reports each watched file independently, so one failure does not take the read', () => {
    const h = host()
    mkdirSync(join(h.root, 'etc'), { recursive: true })
    writeFileSync(join(h.root, 'etc/timezone'), 'Europe/London\n')
    const watches = [w('timezone', '/etc/timezone'), w('hosts', '/etc/hosts')]
    const r = parseDriftCollection(h.collect(watches), watches)
    expect(r.files.map((f) => `${f.watchId}=${f.status}`)).toEqual(['timezone=ok', 'hosts=absent'])
    cleanup()
  })
})

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

const reading = (over: Partial<DriftReading> = {}): DriftReading => ({
  watchId: 'timezone',
  status: 'ok',
  hash: 'h-same',
  normalisedHash: 'n-same',
  applied: [],
  ...over
})

const drift = (r: DriftReading, at = 1_000): HostDrift => ({ at, readings: [r] })

describe('comparing a watched file across the fleet', () => {
  it('never calls a host that could not be read a host that matches', () => {
    // The failure this codebase has been bitten by repeatedly, in its most
    // direct form. A denied read is not a match, is not counted in `matching`,
    // and is named in coverage.
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        { serverId: 'b', serverName: 'web-02', drift: drift(reading()) },
        { serverId: 'c', serverName: 'web-03', drift: drift(reading({ status: 'denied', hash: undefined, normalisedHash: undefined })) }
      ]
    })
    const byName = Object.fromEntries(c.results.map((r) => [r.serverName, r.verdict]))
    expect(byName).toEqual({ 'web-01': 'baseline', 'web-02': 'identical', 'web-03': 'unread' })
    expect(c.matching).toBe(2)
    expect(c.coverage.denied).toEqual(['web-03'])
    expect(c.coverage.compared).toEqual(['web-01', 'web-02'])
  })

  it('never calls a host nobody has collected a host that matches', () => {
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        { serverId: 'b', serverName: 'web-02' }
      ]
    })
    expect(c.results[1].verdict).toBe('unread')
    expect(c.matching).toBe(1)
    expect(c.coverage.notCollected).toEqual(['web-02'])
  })

  it('refuses to compare a file too large to read whole', () => {
    // A prefix hash calls two files with different tails the same. `partial` is
    // its own bucket and is not `compared`.
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        {
          serverId: 'b',
          serverName: 'web-02',
          drift: drift(reading({ status: 'partial', bytes: 900_000, hash: undefined, normalisedHash: undefined }))
        }
      ]
    })
    expect(c.results[1].verdict).toBe('unread')
    expect(c.results[1].status).toBe('partial')
    expect(c.coverage.tooLarge).toEqual(['web-02'])
    expect(c.coverage.compared).toEqual(['web-01'])
  })

  it('calls a difference a rule ate an ignored difference, not identical', () => {
    // The verdict the whole item turns on. The bytes differ; the normalised
    // forms do not; and the answer says so and names the rules that were doing
    // work, rather than quietly reporting "the same".
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading({ hash: 'h-a', applied: ['comments'] })) },
        {
          serverId: 'b',
          serverName: 'web-02',
          drift: drift(reading({ hash: 'h-b', applied: ['comments', 'trailing-space'] }))
        }
      ]
    })
    expect(c.results[1].verdict).toBe('ignored-difference')
    expect(c.results[1].ignoredBy).toEqual(['comments', 'trailing-space'])
    // Still counted as matching — it does match the declared comparison — but
    // it is never reported under the same word as a byte-identical host.
    expect(c.matching).toBe(2)
    expect(c.results.filter((r) => r.verdict === 'identical')).toHaveLength(0)
  })

  it('names ignored-by rules in the declared pipeline order', () => {
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading({ hash: 'h-a', applied: ['blank-lines'] })) },
        {
          serverId: 'b',
          serverName: 'web-02',
          drift: drift(reading({ hash: 'h-b', applied: ['line-endings', 'comments'] }))
        }
      ]
    })
    expect(c.results[1].ignoredBy).toEqual(['line-endings', 'comments', 'blank-lines'])
  })

  it('reports a host that does not have the file at all as absent, not as differing', () => {
    // "All twelve web servers have this nginx.conf. Three do not." Absent is
    // the answer, and it is neither a match nor a read failure.
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        { serverId: 'b', serverName: 'web-02', drift: drift(reading({ status: 'absent', hash: undefined, normalisedHash: undefined })) }
      ]
    })
    expect(c.results[1].verdict).toBe('absent')
    expect(c.matching).toBe(1)
    expect(c.diverging).toBe(0)
    expect(c.coverage.absent).toEqual(['web-02'])
  })

  it('picks the majority when nobody pinned a baseline, and says that it did', () => {
    const c = compareDrift({
      watch: WATCH,
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        { serverId: 'b', serverName: 'web-02', drift: drift(reading()) },
        { serverId: 'c', serverName: 'web-03', drift: drift(reading({ hash: 'h-x', normalisedHash: 'n-x' })) }
      ]
    })
    expect(c.baselineChosen).toBe(true)
    expect(c.baselineServerId).toBe('a')
    expect(c.results.map((r) => r.verdict)).toEqual(['baseline', 'identical', 'differs'])
    expect(c.diverging).toBe(1)
  })

  it('does not quietly substitute a majority when the pinned baseline is unreadable', () => {
    // Comparing against somebody else without saying so would put a whole
    // column of verdicts on screen against a reference the operator did not
    // choose.
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'c',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        { serverId: 'b', serverName: 'web-02', drift: drift(reading()) },
        { serverId: 'c', serverName: 'web-03', drift: drift(reading({ status: 'denied', hash: undefined, normalisedHash: undefined })) }
      ]
    })
    expect(c.baselineServerId).toBeNull()
    expect(c.baselineChosen).toBe(false)
    expect(c.results.map((r) => r.verdict)).toEqual(['unread', 'unread', 'unread'])
    expect(c.matching).toBe(0)
  })

  it('says that a redacted comparison is a redacted comparison', () => {
    // Redaction is a comparison hazard as well as a safety measure: two hosts
    // whose only difference is inside a redacted span hash the same.
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading({ redacted: true })) },
        { serverId: 'b', serverName: 'web-02', drift: drift(reading({ redacted: true })) }
      ]
    })
    expect(c.coverage.redacted).toEqual(['web-01', 'web-02'])
    expect(driftCoverageSentence(c.coverage)).toBe(
      'Compared on 2 hosts — secret-shaped text was replaced before comparing on web-01, web-02, so a ' +
        'difference inside it is invisible here.'
    )
  })
})

describe('the coverage sentence', () => {
  it('is silent only when everything was read and compared', () => {
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        { serverId: 'b', serverName: 'web-02', drift: drift(reading()) }
      ]
    })
    expect(driftCoverageSentence(c.coverage)).toBeNull()
  })

  it('names hosts rather than counting them', () => {
    const c = compareDrift({
      watch: WATCH,
      baselineServerId: 'a',
      hosts: [
        { serverId: 'a', serverName: 'web-01', drift: drift(reading()) },
        { serverId: 'b', serverName: 'web-02', drift: drift(reading({ status: 'denied', hash: undefined, normalisedHash: undefined })) }
      ]
    })
    expect(driftCoverageSentence(c.coverage)).toBe(
      'Compared on 1 host — web-02 would not let this account read it — that is not the same as matching.'
    )
  })
})

// ---------------------------------------------------------------------------
// Statuses and the refusal
// ---------------------------------------------------------------------------

describe('the status vocabulary', () => {
  it('is the one this codebase already uses, with no additions', () => {
    // A parallel vocabulary would mean a fourth table of near-synonyms for a
    // reader to hold in their head.
    expect(DRIFT_STATUSES).toEqual(['ok', 'partial', 'absent', 'denied', 'no-tool', 'unsupported', 'unknown'])
  })

  it('explains every one of them', () => {
    for (const s of DRIFT_STATUSES) expect(DRIFT_STATUS_HELP[s].length, s).toBeGreaterThan(40)
  })
})

describe('what this will not do', () => {
  it('states the refusal to push a file, in words a panel can show', () => {
    // The shape src/shared/docker.ts uses for `docker system prune`: the
    // refusal is a string in the module, not a comment, so the UI can say it
    // and this test can check it is still said.
    expect(DRIFT_NO_PUSH).toContain('never writes a file to a host')
    expect(DRIFT_NO_PUSH).toContain('that is a job')
  })

  it('exports no writer of any kind', async () => {
    // The other direction: the refusal is worth nothing if a `pushConfig` shows
    // up beside it. Read off the module's own exports rather than the source
    // text, so a helper reached through a re-export is caught too.
    const mod = await import('../src/shared/drift')
    const writers = Object.entries(mod)
      .filter(([, v]) => typeof v === 'function')
      .map(([k]) => k)
      .filter((k) => /push|apply|write|remediate|enforce|converge|repair/i.test(k))
    expect(writers).toEqual([])
  })

  it('keeps the read cap where a whole config fits without truncation', () => {
    expect(DRIFT_READ_CAP).toBe(262_144)
  })
})
