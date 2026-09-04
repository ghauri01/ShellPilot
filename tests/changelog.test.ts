import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  AUDIT_FILE,
  APPROVAL_FILE,
  LOCAL_SESSION_FILE,
  readChangeLog,
  tailFile,
  type ChangeLogDeps,
  type ChangeLogHistoryReader
} from '../src/main/services/changelog'
import {
  CHANGELOG_SOURCES,
  CHANGELOG_SOURCE_LIMIT,
  CHANGELOG_SWITCH_OFF,
  changeLogCoverageText,
  compareChangeLogEntries,
  mergeChangeLog,
  type ChangeLogCoverage,
  type ChangeLogEntry,
  type ChangeLogPage,
  type ChangeLogSource
} from '../src/shared/changelog'

// Roadmap item 14 — the change log.
//
// What these assert, and why each one exists rather than being a shape check:
// a timeline that silently omits a source reads as "nothing happened"; a merge
// of four files collides on a millisecond routinely; one corrupt line must not
// cost the rest of a file, because all three existing readers already promise
// that; and the switch must stop the READ rather than hide the tab.

const T0 = 1_700_000_000_000
const ROOT = resolve(__dirname, '..')

let dir: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'shellpilot-changelog-'))
})
afterEach(() => {
  try {
    chmodSync(join(dir, LOCAL_SESSION_FILE), 0o600)
  } catch {
    /* the file may not exist in most tests */
  }
  rmSync(dir, { recursive: true, force: true })
})

const iso = (ms: number): string => new Date(ms).toISOString()

function writeJsonl(name: string, rows: unknown[]): void {
  writeFileSync(join(dir, name), rows.map((r) => `${JSON.stringify(r)}\n`).join(''))
}

function localRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'local-1',
    timestamp: iso(T0),
    event: 'started',
    sessionId: 's1',
    shellId: 'zsh',
    shellLabel: 'zsh (default)',
    shellPath: '/bin/zsh',
    cwd: '/home/ops',
    pid: 4242,
    ...over
  }
}

function approvalRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'appr-1',
    timestamp: iso(T0),
    surface: 'job',
    event: 'granted',
    jobId: 'job-1',
    title: 'Restart nginx',
    risk: 'high',
    confirmation: 'type-to-confirm',
    phrase: 'RESTART',
    confirmedAt: T0,
    hosts: ['web-01'],
    commands: ['systemctl restart nginx'],
    ...over
  }
}

function auditRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'audit-1',
    timestamp: iso(T0),
    agentName: 'Claude Code',
    sessionId: 'sess-1',
    workspaceId: 'ws-1',
    workspaceName: 'Production',
    serverId: 'srv-1',
    serverName: 'db-01',
    action: 'systemctl status postgresql',
    capability: 'terminal',
    approval: 'approved',
    result: 'success',
    exitCode: 0,
    ...over
  }
}

function historyOf(
  rows: { ts: number; kind: string; hostId?: string | null; payload?: unknown; id: number }[]
): ChangeLogHistoryReader {
  return {
    readEvents: (f) =>
      rows
        .filter((r) => (f?.from === undefined || r.ts >= f.from) && (f?.to === undefined || r.ts <= f.to))
        .slice(0, f?.limit ?? rows.length)
        .map((r) => ({
          ts: r.ts,
          kind: r.kind,
          hostId: r.hostId ?? null,
          payload: r.payload,
          cursor: { ts: r.ts, id: r.id }
        }))
  }
}

function deps(over: Partial<ChangeLogDeps> = {}): ChangeLogDeps {
  return { enabled: () => true, dir, history: () => null, ...over }
}

/**
 * The coverage row for one source, or a failure naming the source that is
 * missing.
 *
 * Typed against `ChangeLogPage` rather than a structural `{ coverage: { source
 * }[] }`: the narrow shape erased every field but `source`, so the assertions
 * below reached for `.state`, `.entries`, `.skipped`, `.bytesUnread` and
 * `.rowsDropped` on a type that had none of them, and a rename of any one of
 * those would have gone unnoticed. `source` being `ChangeLogSource` also turns
 * a typo in a source name into a compile error rather than a `!` on undefined.
 */
const coverageFor = (page: ChangeLogPage, source: ChangeLogSource): ChangeLogCoverage => {
  const row = page.coverage.find((c) => c.source === source)
  if (!row) throw new Error(`no coverage row for ${source}; got ${page.coverage.map((c) => c.source).join(', ')}`)
  return row
}

// ---------------------------------------------------------------------------

describe('the change log switch', () => {
  it('opens nothing at all when it is off, rather than hiding what it read', () => {
    // The whole point of gating the READ rather than the tab. Asserting on the
    // empty coverage alone cannot tell the two apart: a version that reads all
    // four sources and then blanks the page produces exactly the same object.
    // What separates them is which files were opened, so that is what is
    // asserted — the list of paths touched, not how many times.
    writeJsonl(LOCAL_SESSION_FILE, [localRow()])
    writeJsonl(AUDIT_FILE, [auditRow()])
    const opened: string[] = []
    const page = readChangeLog(
      deps({
        enabled: () => false,
        tail: (path) => {
          opened.push(path)
          return null
        },
        history: () => {
          opened.push('<durable store>')
          return historyOf([{ ts: T0, kind: 'host-recovered', id: 1 }])
        }
      })
    )
    expect(opened).toEqual([])
    expect(page.enabled).toBe(false)
    expect(page.entries).toEqual([])
    expect(page.coverage.map((c) => c.state)).toEqual(['off', 'off', 'off', 'off'])
  })

  it('says what it does not turn off', () => {
    // A switch over a VIEW of four records nobody else stops writing. Somebody
    // who turns this off has not stopped the recording, and is entitled to
    // read that here rather than infer it.
    expect(CHANGELOG_SWITCH_OFF).toContain('does NOT stop anything being recorded')
    expect(CHANGELOG_SWITCH_OFF).toContain('the agent audit log, the local session log')
    expect(CHANGELOG_SWITCH_OFF).toContain('Switching this off removes the timeline, not the records behind it.')
  })
})

describe('coverage: a source that is not there is named, not skipped', () => {
  it('reports every one of the four sources on every read', () => {
    const page = readChangeLog(deps())
    expect(page.coverage.map((c) => c.source)).toEqual([...CHANGELOG_SOURCES])
  })

  it('calls a missing file absent rather than empty', () => {
    writeJsonl(LOCAL_SESSION_FILE, [localRow()])
    const page = readChangeLog(deps())
    expect(coverageFor(page, 'local-shell').state).toBe('read')
    expect(coverageFor(page, 'agent-audit').state).toBe('absent')
    expect(changeLogCoverageText(coverageFor(page, 'agent-audit'))).toContain(
      'this record does not exist on this machine'
    )
  })

  it('calls a store that is not open absent, not a quiet week', () => {
    const page = readChangeLog(deps({ history: () => null }))
    expect(coverageFor(page, 'history').state).toBe('absent')
    expect(changeLogCoverageText(coverageFor(page, 'history'))).toContain(
      'alerts raised and resolved, jobs'
    )
  })

  it('names an unreadable file and still renders the other three', () => {
    writeJsonl(LOCAL_SESSION_FILE, [localRow()])
    writeJsonl(AUDIT_FILE, [auditRow()])
    const page = readChangeLog(
      deps({
        tail: (path, max) => {
          if (path.endsWith(LOCAL_SESSION_FILE)) throw new Error('EACCES: permission denied')
          return tailFile(path, max)
        }
      })
    )
    expect(coverageFor(page, 'local-shell').state).toBe('unreadable')
    expect(changeLogCoverageText(coverageFor(page, 'local-shell'))).toContain(
      'Could NOT be read, so anything it holds is missing from the timeline below.'
    )
    expect(changeLogCoverageText(coverageFor(page, 'local-shell'))).toContain('EACCES')
    // The other file still made it in — one bad source must not cost the page.
    expect(page.entries.map((e) => e.source)).toEqual(['agent-audit'])
  })

  it('counts a source at zero only when it was actually read', () => {
    writeJsonl(AUDIT_FILE, [])
    const page = readChangeLog(deps())
    expect(coverageFor(page, 'agent-audit').state).toBe('read')
    expect(coverageFor(page, 'agent-audit').entries).toBe(0)
    expect(changeLogCoverageText(coverageFor(page, 'agent-audit'))).toContain('Read in full for this window.')
  })
})

describe('a corrupt line costs that line and nothing else', () => {
  it('keeps the records either side of a line that will not parse', () => {
    // Both existing readers already promise this. It is asserted here because
    // this view parses the files itself rather than calling them.
    writeFileSync(
      join(dir, LOCAL_SESSION_FILE),
      [
        JSON.stringify(localRow({ id: 'local-a', timestamp: iso(T0) })),
        '{"id": "local-b", broken',
        JSON.stringify(localRow({ id: 'local-c', timestamp: iso(T0 + 2000) })),
        ''
      ].join('\n')
    )
    const page = readChangeLog(deps())
    expect(page.entries.map((e) => e.id)).toEqual(['local:local-c', 'local:local-a'])
    expect(coverageFor(page, 'local-shell').state).toBe('partial')
    expect(coverageFor(page, 'local-shell').skipped).toBe(1)
    expect(changeLogCoverageText(coverageFor(page, 'local-shell'))).toContain(
      '1 unreadable line was skipped.'
    )
  })

  it('pluralises the skipped-line sentence', () => {
    writeFileSync(
      join(dir, LOCAL_SESSION_FILE),
      ['{oops', '{also oops', JSON.stringify(localRow()), ''].join('\n')
    )
    const page = readChangeLog(deps())
    expect(changeLogCoverageText(coverageFor(page, 'local-shell'))).toContain(
      '2 unreadable lines were skipped.'
    )
  })
})

describe('ordering', () => {
  const entry = (over: Partial<ChangeLogEntry>): ChangeLogEntry => ({
    id: 'x',
    source: 'history',
    ts: T0,
    actor: 'system',
    kind: 'store',
    summary: 's',
    detail: [],
    hostId: null,
    hosts: [],
    ...over
  })

  it('puts the newest first', () => {
    const out = mergeChangeLog([
      entry({ id: 'old', ts: T0 }),
      entry({ id: 'new', ts: T0 + 1000 })
    ])
    expect(out.map((e) => e.id)).toEqual(['new', 'old'])
  })

  it('orders two records sharing a timestamp the same way whatever order they arrive in', () => {
    // A job approval and the job event it caused round to the same ISO
    // millisecond routinely. Sorting on ts alone leaves them in concatenation
    // order, so the page reshuffles itself between reads for no visible reason.
    const a = entry({ id: 'approval:a', source: 'approvals', ts: T0 })
    const b = entry({ id: 'history:1', source: 'history', ts: T0 })
    const c = entry({ id: 'local:z', source: 'local-shell', ts: T0 })
    expect(mergeChangeLog([a, b, c]).map((e) => e.id)).toEqual(['local:z', 'approval:a', 'history:1'])
    expect(mergeChangeLog([b, c, a]).map((e) => e.id)).toEqual(['local:z', 'approval:a', 'history:1'])
    expect(mergeChangeLog([c, a, b]).map((e) => e.id)).toEqual(['local:z', 'approval:a', 'history:1'])
  })

  it('breaks a same-source tie on the id', () => {
    const a = entry({ id: 'local:aaa', source: 'local-shell', ts: T0 })
    const b = entry({ id: 'local:bbb', source: 'local-shell', ts: T0 })
    expect(compareChangeLogEntries(a, b)).toBeLessThan(0)
    expect(compareChangeLogEntries(b, a)).toBeGreaterThan(0)
    expect(compareChangeLogEntries(a, a)).toBe(0)
  })

  it('interleaves four sources by time rather than by source', () => {
    writeJsonl(LOCAL_SESSION_FILE, [localRow({ id: 'l1', timestamp: iso(T0 + 3000) })])
    writeJsonl(APPROVAL_FILE, [approvalRow({ id: 'a1', timestamp: iso(T0 + 1000) })])
    writeJsonl(AUDIT_FILE, [auditRow({ id: 'g1', timestamp: iso(T0 + 4000) })])
    const page = readChangeLog(
      deps({ history: () => historyOf([{ ts: T0 + 2000, kind: 'host-unreachable', id: 7 }]) })
    )
    expect(page.entries.map((e) => e.source)).toEqual([
      'agent-audit',
      'local-shell',
      'history',
      'approvals'
    ])
  })
})

describe('metadata, never content', () => {
  it('never carries a secret out of a local session row', () => {
    // localSessionLog.ts does NOT redact at write — nothing it stores is
    // normally secret-shaped. "Normally" is not a category this view has, so
    // it redacts at read.
    writeJsonl(LOCAL_SESSION_FILE, [
      localRow({ error: 'spawn failed: MYSQL_PASSWORD=hunter2 not exported' })
    ])
    const page = readChangeLog(deps())
    const text = JSON.stringify(page)
    expect(text).not.toContain('hunter2')
    expect(text).toContain('MYSQL_PASSWORD=[REDACTED]')
  })

  it('never carries a secret out of a history payload', () => {
    const page = readChangeLog(
      deps({
        history: () =>
          historyOf([
            {
              ts: T0,
              kind: 'host-unreachable',
              id: 1,
              payload: { error: 'ssh: connect using postgres://ops:hunter2@db-01:5432/app' }
            }
          ])
      })
    )
    expect(JSON.stringify(page)).not.toContain('hunter2')
  })

  it('reads only the whitelisted payload keys, so a new payload field cannot leak', () => {
    // The alternative — stringifying the payload — means every future
    // recordEvent call site decides what this screen shows, which is the
    // failure direction that cannot be taken back.
    const page = readChangeLog(
      deps({
        history: () =>
          historyOf([
            {
              ts: T0,
              kind: 'job-ended',
              id: 1,
              payload: { jobId: 'job-9', stdout: 'root:x:0:0:root:/root:/bin/bash' }
            }
          ])
      })
    )
    expect(page.entries[0].detail).toEqual(['jobId: job-9'])
    expect(JSON.stringify(page)).not.toContain('root:x:0:0')
  })

  it('caps a long field instead of putting a wall of text on the timeline', () => {
    writeJsonl(APPROVAL_FILE, [approvalRow({ commands: ['echo '.repeat(400)] })])
    const page = readChangeLog(deps())
    expect(page.entries[0].detail[0].length).toBe(201)
    expect(page.entries[0].detail[0].endsWith('…')).toBe(true)
  })

  it('redacts before it caps, so the cap cannot rescue a secret from the redactor', () => {
    // The order is load-bearing and the PEM rule is where it shows. That rule
    // matches BEGIN...END as one block; a cap applied first cuts the END marker
    // off, the pattern then matches nothing, and the key body reaches the
    // screen as ordinary prose. Redacting first collapses the whole block to a
    // placeholder that is comfortably under the cap.
    const key =
      '-----BEGIN RSA PRIVATE KEY-----\n' +
      'MIIEowIBAAKCAQEAsecretkeymaterialthatmustneverreachthetimelinewhatsoever\n' +
      '-----END RSA PRIVATE KEY-----'
    // Long enough that the cap lands inside the key body rather than past the
    // END marker — which is the only arrangement in which the order matters.
    const prefix = `ssh-add - <<'EOF' ${'#'.repeat(82)} `
    writeJsonl(APPROVAL_FILE, [approvalRow({ commands: [`${prefix}${key}`] })])
    const page = readChangeLog(deps())
    expect(page.entries[0].detail[0]).not.toContain('secretkeymaterial')
    expect(page.entries[0].detail[0]).toContain('[REDACTED]')
  })

  it('carries the command and the target, because that is the question being asked', () => {
    writeJsonl(APPROVAL_FILE, [approvalRow()])
    const page = readChangeLog(deps())
    expect(page.entries[0].summary).toBe('Job granted — Restart nginx')
    expect(page.entries[0].detail).toContain('systemctl restart nginx')
    expect(page.entries[0].hosts).toEqual(['web-01'])
  })

  it('describes a local shell without describing what was typed into it', () => {
    writeJsonl(LOCAL_SESSION_FILE, [localRow({ event: 'exited', exitCode: 130 })])
    const page = readChangeLog(deps())
    expect(page.entries[0].summary).toBe('zsh (default) exited on this machine')
    expect(page.entries[0].detail).toEqual(['/bin/zsh', 'in /home/ops', 'pid 4242', 'exit 130'])
  })
})

describe('actors', () => {
  it('files an agent row as an agent and a job row as a human', () => {
    writeJsonl(AUDIT_FILE, [auditRow()])
    writeJsonl(APPROVAL_FILE, [approvalRow({ timestamp: iso(T0 - 1000) })])
    const page = readChangeLog(
      deps({ history: () => historyOf([{ ts: T0 - 2000, kind: 'job-ended', id: 3 }]) })
    )
    expect(page.entries.map((e) => e.actor)).toEqual(['agent', 'human', 'human'])
  })

  it('files a server going unreachable as neither, because nobody did it', () => {
    const page = readChangeLog(
      deps({ history: () => historyOf([{ ts: T0, kind: 'host-unreachable', hostId: 'srv-1', id: 1 }]) })
    )
    expect(page.entries[0].actor).toBe('system')
  })

  it('files an event kind this build has never heard of as system', () => {
    const page = readChangeLog(deps({ history: () => historyOf([{ ts: T0, kind: 'invented-later', id: 1 }]) }))
    expect(page.entries[0].actor).toBe('system')
    expect(page.entries[0].kind).toBe('store')
  })
})

describe('filters', () => {
  function seeded(): ReturnType<typeof readChangeLog> {
    writeJsonl(LOCAL_SESSION_FILE, [localRow({ id: 'l1', timestamp: iso(T0) })])
    writeJsonl(APPROVAL_FILE, [approvalRow({ id: 'a1', timestamp: iso(T0 + 1000) })])
    writeJsonl(AUDIT_FILE, [auditRow({ id: 'g1', timestamp: iso(T0 + 2000) })])
    return readChangeLog(deps({ history: () => historyOf([{ ts: T0 + 3000, kind: 'host-recovered', hostId: 'srv-1', id: 5 }]) }))
  }

  it('filters by time', () => {
    writeJsonl(LOCAL_SESSION_FILE, [
      localRow({ id: 'l-old', timestamp: iso(T0 - 86_400_000) }),
      localRow({ id: 'l-now', timestamp: iso(T0) })
    ])
    const page = readChangeLog(deps(), { from: T0 - 1000, to: T0 + 1000 })
    expect(page.entries.map((e) => e.id)).toEqual(['local:l-now'])
  })

  it('filters by actor', () => {
    const all = seeded()
    expect(all.entries.length).toBe(4)
    writeJsonl(LOCAL_SESSION_FILE, [localRow({ id: 'l1', timestamp: iso(T0) })])
    writeJsonl(APPROVAL_FILE, [approvalRow({ id: 'a1', timestamp: iso(T0 + 1000) })])
    writeJsonl(AUDIT_FILE, [auditRow({ id: 'g1', timestamp: iso(T0 + 2000) })])
    const humans = readChangeLog(deps(), { actors: ['human'] })
    expect(humans.entries.map((e) => e.id)).toEqual(['approval:a1', 'local:l1'])
  })

  it('filters by kind', () => {
    seeded()
    const page = readChangeLog(deps(), { kinds: ['shell'] })
    expect(page.entries.map((e) => e.kind)).toEqual(['shell'])
  })

  it('filters by server id or by server name, because the sources disagree about which they keep', () => {
    writeJsonl(APPROVAL_FILE, [approvalRow({ id: 'a1', hosts: ['web-01'] })])
    writeJsonl(AUDIT_FILE, [auditRow({ id: 'g1', serverId: 'srv-1', serverName: 'db-01' })])
    const byName = readChangeLog(deps(), { hosts: ['web-01'] })
    expect(byName.entries.map((e) => e.id)).toEqual(['approval:a1'])
    const byId = readChangeLog(deps(), { hosts: ['srv-1'] })
    expect(byId.entries.map((e) => e.id)).toEqual(['audit:g1'])
  })

  it('says how many unattributed rows a server filter hid', () => {
    // A local shell names no host. Dropping it from a host-filtered page
    // without a word is how a filtered timeline claims a quiet afternoon.
    writeJsonl(LOCAL_SESSION_FILE, [localRow({ id: 'l1' }), localRow({ id: 'l2' })])
    writeJsonl(AUDIT_FILE, [auditRow({ id: 'g1', serverId: 'srv-1' })])
    const page = readChangeLog(deps(), { hosts: ['srv-1'] })
    expect(page.entries.map((e) => e.id)).toEqual(['audit:g1'])
    expect(page.hostFilterHidUnattributed).toBe(2)
  })

  it('does not count a row the time filter already excluded as hidden by the server filter', () => {
    writeJsonl(LOCAL_SESSION_FILE, [localRow({ id: 'l1', timestamp: iso(T0 - 86_400_000) })])
    const page = readChangeLog(deps(), { hosts: ['srv-1'], from: T0 - 1000 })
    expect(page.hostFilterHidUnattributed).toBeUndefined()
  })

  it('names a server by its display name when the store only kept an id', () => {
    const page = readChangeLog(
      deps({
        history: () => historyOf([{ ts: T0, kind: 'host-unreachable', hostId: 'srv-1', id: 1 }]),
        hostName: (id) => (id === 'srv-1' ? 'db-01' : null)
      })
    )
    expect(page.entries[0].hosts).toEqual(['db-01'])
  })
})

describe('volume and retention', () => {
  it('reads only the tail of a file and says how much it did not read', () => {
    const rows = Array.from({ length: 4000 }, (_, i) =>
      JSON.stringify(localRow({ id: `l${i}`, timestamp: iso(T0 + i) }))
    )
    writeFileSync(join(dir, LOCAL_SESSION_FILE), `${rows.join('\n')}\n`)
    const page = readChangeLog(deps())
    const cov = coverageFor(page, 'local-shell')
    expect(cov.state).toBe('truncated')
    expect(cov.bytesUnread).toBeGreaterThan(0)
    expect(changeLogCoverageText(cov)).toContain(
      'Only the most recent part was read. Older entries exist and are NOT in the timeline below.'
    )
    // The very oldest row is not in the page, and the newest is.
    expect(page.entries.some((e) => e.id === 'local:l3999')).toBe(true)
    expect(page.entries.some((e) => e.id === 'local:l0')).toBe(false)
  })

  it('never lets one source contribute more than its row budget', () => {
    const rows = Array.from({ length: CHANGELOG_SOURCE_LIMIT + 10 }, (_, i) =>
      localRow({ id: `l${i}`, timestamp: iso(T0 + i) })
    )
    writeJsonl(LOCAL_SESSION_FILE, rows)
    const page = readChangeLog(deps(), { limit: 10_000 })
    expect(page.entries.length).toBe(CHANGELOG_SOURCE_LIMIT)
    expect(coverageFor(page, 'local-shell').rowsDropped).toBe(10)
    expect(changeLogCoverageText(coverageFor(page, 'local-shell'))).toContain(
      "10 older entries were past this page's budget for one source."
    )
  })

  it('calls the store truncated when it returned a full page of events', () => {
    const rows = Array.from({ length: CHANGELOG_SOURCE_LIMIT }, (_, i) => ({
      ts: T0 + i,
      kind: 'host-recovered',
      id: i
    }))
    const page = readChangeLog(deps({ history: () => historyOf(rows) }), { limit: 10_000 })
    expect(coverageFor(page, 'history').state).toBe('truncated')
  })

  it('reports more when the page was cut', () => {
    writeJsonl(LOCAL_SESSION_FILE, [
      localRow({ id: 'l1', timestamp: iso(T0) }),
      localRow({ id: 'l2', timestamp: iso(T0 + 1000) })
    ])
    const page = readChangeLog(deps(), { limit: 1 })
    expect(page.entries.map((e) => e.id)).toEqual(['local:l2'])
    expect(page.more).toBe(true)
    expect(page.oldest).toBe(T0 + 1000)
  })

  it('drops the partial first line of a tail window rather than counting it corrupt', () => {
    // The window starts mid-line by construction. Counting our own cut as a
    // corrupt record would put a permanent "1 line skipped" on every large file.
    const path = join(dir, 'tail.jsonl')
    writeFileSync(path, 'aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc\n')
    expect(tailFile(path, 16)).toEqual({ text: 'cccccccccc\n', bytesUnread: 17 })
    expect(tailFile(path, 1000)).toEqual({
      text: 'aaaaaaaaaa\nbbbbbbbbbb\ncccccccccc\n',
      bytesUnread: 0
    })
    expect(tailFile(join(dir, 'nope.jsonl'), 16)).toBe(null)
  })
})

describe('the filenames this reader duplicates', () => {
  // This view parses the three JSONL files itself rather than calling their
  // readers — see the note at the top of changelog.ts. The cost is a second
  // place that knows the names, and this is the guard against that drifting.
  const owners: [string, string][] = [
    [AUDIT_FILE, 'src/main/services/auditLog.ts'],
    [LOCAL_SESSION_FILE, 'src/main/services/localSessionLog.ts'],
    [APPROVAL_FILE, 'src/main/services/approvalLog.ts']
  ]
  for (const [file, owner] of owners) {
    it(`${file} is still the name ${owner} writes`, () => {
      expect(readFileSync(join(ROOT, owner), 'utf8')).toContain(`'${file}'`)
    })
  }
})
