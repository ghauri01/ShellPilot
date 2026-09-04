// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { DbOpsPanel } from '../src/renderer/src/components/databases/DbOpsPanel'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import {
  judgeMongoOplog,
  judgeMongoReplication,
  judgeMysqlReplication,
  judgePgStatements,
  judgeRedisMemory,
  judgeRedisReplication,
  parseMongoOplog,
  parseMongoReplication,
  parseMysqlReplication,
  parsePgStatements,
  parseRedisInfo,
  parseRedisMemory,
  parseRedisReplication,
  type DbAnswer,
  type DbOpsEngine,
  type DbOpsReport
} from '../src/shared/dbOps'
import type { DbConnectConfig } from '../src/shared/db'

// Rendered, not read.
//
// The three defects this suite exists to catch are all defects of PRESENTATION,
// and each one is a number or an absence that looks fine in a table:
//
//  1. A missing pg_stat_statements rendering as an empty slow-query list —
//     "there are no slow statements" where the truth is "nothing was recorded".
//  2. Seconds_Behind_Source = NULL rendering as 0, or as a blank cell that a
//     reader fills in as 0.
//  3. A permission-denied answer rendering as a clean, healthy card.
//
// A source-regex test can see that the words exist somewhere in the file. It
// cannot see whether they reach the screen for the case that matters.

const CFG: DbConnectConfig = {
  id: 'db-1',
  kind: 'postgres',
  host: 'db.example.internal',
  port: 5432,
  username: 'ops'
}

function report(engine: DbOpsEngine, answers: DbAnswer<unknown>[]): DbOpsReport {
  return { ok: true, engine, connectionId: 'db-1', at: 0, elapsedMs: 12, answers }
}

const FIXTURES = resolve(__dirname, 'fixtures/dbops')
function fixture(engine: 'mongodb' | 'redis', file: string): Record<string, { ok: boolean; result?: Record<string, unknown>; reply?: unknown }> {
  return JSON.parse(readFileSync(join(FIXTURES, engine, `${file}.json`), 'utf8'))
}
function redisInfo(cap: { reply?: unknown } | undefined): ReturnType<typeof parseRedisInfo> {
  return parseRedisInfo(typeof cap?.reply === 'string' ? cap.reply : '')
}

/** The real answer the collector builds when the extension is not installed. */
const NO_STATEMENTS: DbAnswer<unknown> = {
  id: 'statements',
  status: 'absent',
  value: { extensionVersion: null, redactedText: false, redactedCount: 0, statements: [] },
  verdict: {
    level: 'unknown',
    headline: 'pg_stat_statements is not installed in this database.',
    because:
      'It is an extension, not a built-in view, and it is absent far more often than not. Without it Postgres keeps no per-statement history at all, so there is nothing to show — which is different from there being no slow statements.'
  }
}

/** Built from the same parser and judge the product uses, on the row a real
 *  MySQL replica returned after STOP REPLICA IO_THREAD. */
const BROKEN_ROW = {
  Source_Host: 'sp-my',
  Replica_IO_Running: 'No',
  Replica_SQL_Running: 'Yes',
  Seconds_Behind_Source: null,
  Last_IO_Errno: 0,
  Last_IO_Error: '',
  Last_SQL_Errno: 0,
  Last_SQL_Error: '',
  Channel_Name: ''
}

function brokenReplication(): DbAnswer<unknown> {
  const channels = parseMysqlReplication([BROKEN_ROW])
  return { id: 'replication', status: 'ok', value: channels, verdict: judgeMysqlReplication(channels) }
}

const DENIED_REPLICATION: DbAnswer<unknown> = {
  id: 'replication',
  status: 'denied',
  detail: 'Access denied; you need (at least one of) the SUPER, REPLICATION CLIENT privilege(s) for this operation',
  verdict: {
    level: 'unknown',
    headline: 'Replication: not permitted. Reading it needs pg_monitor on PostgreSQL, or REPLICATION CLIENT on MySQL — this is NOT "replication is fine".',
    because: 'This exists and the account ShellPilot connected as was not allowed to read it.'
  }
}

let opsImpl: (cfg: DbConnectConfig) => Promise<DbOpsReport>

beforeEach(() => {
  opsImpl = () => Promise.resolve(report('postgres', [NO_STATEMENTS]))
  stubBridge({ db: { ops: (cfg: DbConnectConfig) => opsImpl(cfg) } })
})

const readButton = (): HTMLElement => screen.getByRole('button', { name: /Read server state/ })

describe('DbOpsPanel — a missing pg_stat_statements', () => {
  it('says it is not installed rather than showing an empty slow-query list', async () => {
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    await user.click(readButton())

    await screen.findByText(/pg_stat_statements is not installed/)
    // The absence is explained, not merely absent.
    expect(document.body.textContent).toMatch(/different from there being no slow statements/)
    // And the card is labelled with the status, so it cannot read as a clean pass.
    expect(screen.getByTitle(/not enabled on this server/)).toBeTruthy()
    // No table at all — an empty table is the failure mode being prevented.
    expect(document.querySelector('table')).toBeNull()
  })

  it('does not present it as a healthy answer', async () => {
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    await user.click(readButton())
    await screen.findByText(/pg_stat_statements is not installed/)
    // The clean-read icon belongs to `ok` and must not be on this card.
    expect(document.body.textContent).not.toMatch(/statements by total time/)
  })

  it('an installed extension WITH statements does render the list', async () => {
    const value = parsePgStatements(
      [{ query: 'SELECT * FROM orders WHERE id = $1', calls: '4210', total_exec_time: 91234.5, mean_exec_time: 21.7, rows: '4210' }],
      '1.10'
    )
    opsImpl = () =>
      Promise.resolve(report('postgres', [{ id: 'statements', status: 'ok', value, verdict: judgePgStatements(value) }]))
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    await user.click(readButton())

    await screen.findByText(/SELECT \* FROM orders/)
    expect(document.querySelector('table')).not.toBeNull()
  })
})

describe('DbOpsPanel — Seconds_Behind_Source = NULL', () => {
  beforeEach(() => {
    opsImpl = () => Promise.resolve(report('mysql', [brokenReplication()]))
  })

  it('renders as broken, and the cell never says 0', async () => {
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mysql' }} kind="mysql" />)
    await user.click(readButton())

    await screen.findByText(/BROKEN/)
    // The detail cell. Both halves matter: the word NULL must be on screen, and
    // no cell in the "behind" column may contain a zero.
    const cells = [...document.querySelectorAll('td')].map((td) => td.textContent?.trim())
    expect(cells).toContain('NULL — broken')
    expect(cells).not.toContain('0s')
    expect(cells).not.toContain('0')
  })

  it('is not rendered with the ok styling', async () => {
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mysql' }} kind="mysql" />)
    await user.click(readButton())
    await screen.findByText(/BROKEN/)
    expect(document.querySelector('.danger')).not.toBeNull()
    expect(document.body.textContent).not.toMatch(/is running, 0s behind/)
  })

  it('a healthy replica at 0 seconds looks different from a broken one at NULL', async () => {
    const healthy = parseMysqlReplication([{ ...BROKEN_ROW, Replica_IO_Running: 'Yes', Seconds_Behind_Source: 0 }])
    opsImpl = () =>
      Promise.resolve(
        report('mysql', [{ id: 'replication', status: 'ok', value: healthy, verdict: judgeMysqlReplication(healthy) }])
      )
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mysql' }} kind="mysql" />)
    await user.click(readButton())

    await screen.findByText(/is running, 0s behind/)
    expect(document.body.textContent).not.toMatch(/BROKEN/)
    const cells = [...document.querySelectorAll('td')].map((td) => td.textContent?.trim())
    expect(cells).toContain('0s')
    expect(cells).not.toContain('NULL — broken')
  })
})

describe('DbOpsPanel — a denied answer', () => {
  it('renders as "not permitted" with the engine\'s own words, not as healthy', async () => {
    opsImpl = () => Promise.resolve(report('postgres', [DENIED_REPLICATION]))
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    await user.click(readButton())

    await screen.findByText(/not permitted/)
    expect(document.body.textContent).toMatch(/NOT "replication is fine"/)
    // The engine's own sentence survives to the screen.
    expect(document.body.textContent).toMatch(/REPLICATION CLIENT privilege/)
    // Marked as a guarded read rather than a plain one.
    expect(screen.getByTitle(/was not allowed to read it/)).toBeTruthy()
  })
})

describe('DbOpsPanel — the read itself', () => {
  it('shows nothing until asked, so a stale answer cannot be mistaken for a fresh one', () => {
    render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    expect(document.body.textContent).toMatch(/Nothing has been read yet/)
  })

  it('states that it is read-only, on the page rather than only in the source', () => {
    render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    expect(document.body.textContent).toMatch(/Read-only/)
    expect(document.body.textContent).toMatch(/no control that kills a session/)
  })

  it('offers no control that changes the server', async () => {
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mysql' }} kind="mysql" />)
    opsImpl = () => Promise.resolve(report('mysql', [brokenReplication()]))
    await user.click(readButton())
    await screen.findByText(/BROKEN/)

    // Every button on the page re-reads. The tempting one — "kill the blocking
    // session" — is deliberately absent; see the refusal in src/shared/dbOps.ts.
    const labels = [...document.querySelectorAll('button')].map((b) => b.textContent ?? '')
    expect(labels).toHaveLength(1)
    expect(labels[0]).toMatch(/Read server state/)
    for (const l of labels) expect(l).not.toMatch(/kill|terminate|vacuum|purge|reset|drop/i)
  })

  it('surfaces a connection failure rather than an empty page', async () => {
    opsImpl = () =>
      Promise.resolve({
        ok: false,
        error: 'connect ECONNREFUSED 10.0.0.5:5432',
        engine: 'postgres',
        connectionId: 'db-1',
        at: 0,
        elapsedMs: 3,
        answers: []
      })
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    await user.click(readButton())
    await screen.findByText(/ECONNREFUSED/)
  })

  /** The cross-connection leak dockerPanel.test.tsx was written for, in the
   *  shape this panel can have it: one database's answers under another's name. */
  it('drops a read that lands after the operator changed connection', async () => {
    let resolveFirst!: (r: DbOpsReport) => void
    opsImpl = () => new Promise<DbOpsReport>((r) => (resolveFirst = r))

    const user = userEvent.setup()
    const { rerender } = render(<DbOpsPanel cfg={CFG} kind="postgres" />)
    await user.click(readButton())

    rerender(<DbOpsPanel cfg={{ ...CFG, id: 'db-2', host: 'other.example.internal' }} kind="postgres" />)

    await waitFor(() => expect(document.body.textContent).toMatch(/Nothing has been read yet/))
    resolveFirst(report('postgres', [DENIED_REPLICATION]))

    await new Promise((r) => setTimeout(r, 10))
    expect(document.body.textContent).not.toMatch(/not permitted/)
    expect(document.body.textContent).toMatch(/Nothing has been read yet/)
  })
})

// ===========================================================================
// The badge on the tab nobody has open
// ===========================================================================

describe('DbOpsPanel — reporting the worst verdict upward', () => {
  it('hands the caller the level the tab badge shows', async () => {
    const levels: string[] = []
    opsImpl = () => Promise.resolve(report('mysql', [brokenReplication()]))
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mysql' }} kind="mysql" onVerdict={(l) => levels.push(l)} />)
    await user.click(readButton())
    await screen.findByText(/BROKEN/)
    expect(levels).toEqual(['alarm'])
  })

  it('an answer nobody was allowed to read still marks the tab', async () => {
    // worstVerdict ranks `unknown` above `ok` on purpose, and until this was
    // wired that ranking had no effect on anything anybody could see: the
    // Operations tab was a plain button and no renderer imported the function.
    const levels: string[] = []
    opsImpl = () =>
      Promise.resolve(
        report('postgres', [
          {
            id: 'sizes',
            status: 'ok',
            value: { databases: [{ name: 'shop', totalBytes: 1024 }], tables: [] },
            verdict: { level: 'ok', headline: '1 KB across 1 database.' }
          },
          NO_STATEMENTS
        ])
      )
    const user = userEvent.setup()
    render(<DbOpsPanel cfg={CFG} kind="postgres" onVerdict={(l) => levels.push(l)} />)
    await user.click(readButton())
    await screen.findByText(/pg_stat_statements is not installed/)
    expect(levels).toEqual(['unknown'])
  })
})

// ===========================================================================
// MongoDB and Redis, where the number that looks fine is a different number
// ===========================================================================

describe('DbOpsPanel — a MongoDB member that is down', () => {
  /** Built by the real parser and judge, from the real capture. */
  function downMembers(): DbAnswer<unknown> {
    const value = parseMongoReplication(fixture('mongodb', 'secondary-down').replSetGetStatus.result)
    return { id: 'replication', status: 'ok', value, verdict: judgeMongoReplication(value) }
  }

  /** The rendered cells of one member's row, so a healthy member's genuine
   *  zero is not mistaken for the dead one's. */
  async function rowFor(name: string): Promise<string[]> {
    const cell = await screen.findByText(name)
    const tr = cell.closest('tr')
    if (!tr) throw new Error(`no row for ${name}`)
    return [...tr.querySelectorAll('td')].map((td) => td.textContent ?? '')
  }

  it('writes "did not report" in the lag cell rather than 1970, a dash, or a zero', async () => {
    // The cell this test exists for. The server sent optimeDate
    // 1970-01-01T00:00:00.000Z; a blank cell is one a reader fills in as zero,
    // and a rendered 1970 is a date nobody reads as "no measurement".
    //
    // FAILS FIRST, with the epoch guard removed from the parser, as:
    //   expected [ 'sp-mongo2:27017', …(4) ] to include 'did not report'
    // and the cell it renders instead is a lag computed from 1970. The sibling
    // rows in the same table are legitimately at 0s, which is why only THIS row
    // may be asked and why the assertion below checks that one keeps its zero.
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('mongodb', [downMembers()]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mongodb' }} kind="mongodb" />)
    await user.click(readButton())
    const row = await rowFor('sp-mongo2:27017')
    expect(row).toContain('did not report')
    expect(row).not.toContain('0s')
    expect(row.join(' ')).not.toContain('1970')

    // And the healthy member beside it keeps its real zero.
    expect(await rowFor('sp-mongo1:27017')).toContain('0s')
  })

  it('shows the member as DOWN and does not show a zero-millisecond ping for it', async () => {
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('mongodb', [downMembers()]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mongodb' }} kind="mongodb" />)
    await user.click(readButton())
    // FAILS FIRST, with `pingMs: num(r.pingMs)` unconditional, as:
    //   expected [ 'sp-mongo2:27017', …(4) ] to not include '0 ms'
    const row = await rowFor('sp-mongo2:27017')
    expect(row).toContain('DOWN')
    // pingMs is literally 0 in the capture, and 0 ms reads as a perfect round
    // trip. The healthy member three rows down really is at 0 ms.
    expect(row).not.toContain('0 ms')
    expect(await rowFor('sp-mongo3:27017')).toContain('0 ms')
  })

  it('leads with the judgement, not with the table', async () => {
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('mongodb', [downMembers()]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mongodb' }} kind="mongodb" />)
    await user.click(readButton())
    await waitFor(() => expect(screen.getByText(/not carrying the set/)).toBeTruthy())
  })
})

describe('DbOpsPanel — an oplog window', () => {
  function oplog(file: string, uptime: number): DbAnswer<unknown> {
    const fx = fixture('mongodb', file)
    const b = (cap: { result?: Record<string, unknown> }): Record<string, unknown>[] =>
      ((cap.result?.cursor as { firstBatch?: Record<string, unknown>[] })?.firstBatch ?? [])
    const value = parseMongoOplog(b(fx.oplogFirst), b(fx.oplogLast), b(fx.oplogStats)[0], uptime)
    return { id: 'oplog', status: 'ok', value, verdict: judgeMongoOplog(value) }
  }

  it('says on screen whether the window has rolled, because the number alone cannot', async () => {
    // FAILS FIRST, with the cell rendered as the raw boolean, as:
    //   Unable to find an element with the text:
    //   /not yet — the window is still growing/
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('mongodb', [oplog('replica-set-primary', 493)]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mongodb' }} kind="mongodb" />)
    await user.click(readButton())
    await waitFor(() => expect(screen.getByText(/not yet — the window is still growing/)).toBeTruthy())
  })

  it('says the opposite for the same small number when the oplog is rolling', async () => {
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('mongodb', [oplog('oplog-saturated', 478)]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'mongodb' }} kind="mongodb" />)
    await user.click(readButton())
    await waitFor(() => expect(screen.getByText(/yes — this is the real window/)).toBeTruthy())
  })
})

describe('DbOpsPanel — Redis maxmemory', () => {
  function memory(file: string): DbAnswer<unknown> {
    const value = parseRedisMemory(redisInfo(fixture('redis', file).infoMemory))
    return { id: 'memory', status: 'ok', value, verdict: judgeRedisMemory(value) }
  }

  it('renders maxmemory 0 as "none — unlimited", never as 0 B and never as blank', async () => {
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('redis', [memory('replica')]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'redis' }} kind="redis" />)
    await user.click(readButton())
    await waitFor(() => expect(screen.getByText('none — unlimited')).toBeTruthy())
    expect(screen.queryByText('0 B')).toBeNull()
  })

  it('renders an ABSENT maxmemory as "not reported", which is a different cell', async () => {
    // FAILS FIRST, with the two cases collapsed into one cell, as:
    //   Unable to find an element with the text: not reported.
    const value = parseRedisMemory(parseRedisInfo('# Memory\r\nused_memory:2384024\r\n'))
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('redis', [{ id: 'memory', status: 'unsupported', value, verdict: judgeRedisMemory(value) }]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'redis' }} kind="redis" />)
    await user.click(readButton())
    await waitFor(() => expect(screen.getByText('not reported')).toBeTruthy())
    expect(screen.queryByText('none — unlimited')).toBeNull()
  })
})

describe('DbOpsPanel — a Redis replica that has lost its master', () => {
  it('writes "no measurement" where Redis sent -1', async () => {
    // FAILS FIRST, with the sentinel rendered as a duration, as:
    //   Unable to find an element with the text: no measurement.
    const value = parseRedisReplication(redisInfo(fixture('redis', 'replica-link-down').infoReplication))
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('redis', [{ id: 'replication', status: 'ok', value, verdict: judgeRedisReplication(value) }]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'redis' }} kind="redis" />)
    await user.click(readButton())
    await waitFor(() => expect(screen.getByText('no measurement')).toBeTruthy())
    // Neither the sentinel nor the zero it clamps to.
    expect(screen.queryByText('-1s ago')).toBeNull()
    expect(screen.queryByText('0s ago')).toBeNull()
  })
})

describe('DbOpsPanel — the engine the tables are drawn for', () => {
  it('comes from the report, so a MongoDB report is never drawn with MySQL columns', async () => {
    // The panel used to derive it from `kind`, which is the connection's kind
    // and not the report's. They agree today; they would stop agreeing the
    // first time a report was rendered while the selection had already moved.
    // FAILS FIRST, with the derivation put back, as:
    //   Unable to find an element with the text: behind primary.
    const value = parseMongoReplication(fixture('mongodb', 'replica-set-primary').replSetGetStatus.result)
    const user = userEvent.setup()
    opsImpl = () => Promise.resolve(report('mongodb', [{ id: 'replication', status: 'ok', value, verdict: judgeMongoReplication(value) }]))
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'postgres' }} kind="postgres" />)
    await user.click(readButton())
    await waitFor(() => expect(screen.getByText('behind primary')).toBeTruthy())
    // MySQL's replication table header, which must not appear.
    expect(screen.queryByText('channel')).toBeNull()
  })

  it('names the questions it is about to ask before anything has been read', () => {
    render(<DbOpsPanel cfg={{ ...CFG, kind: 'redis' }} kind="redis" />)
    expect(screen.getByText(/9 questions will be asked/)).toBeTruthy()
    expect(screen.getByText(/memory and eviction/)).toBeTruthy()
  })
})
