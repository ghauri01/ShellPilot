// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { DbOpsPanel } from '../src/renderer/src/components/databases/DbOpsPanel'
import {
  judgeMysqlReplication,
  judgePgStatements,
  parseMysqlReplication,
  parsePgStatements,
  type DbAnswer,
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

function report(engine: 'postgres' | 'mysql', answers: DbAnswer<unknown>[]): DbOpsReport {
  return { ok: true, engine, connectionId: 'db-1', at: 0, elapsedMs: 12, answers }
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
