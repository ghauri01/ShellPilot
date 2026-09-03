// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { ChangeLogPanel } from '../src/renderer/src/components/monitor/ChangeLogPanel'
import type { ChangeLogEntry, ChangeLogFilter, ChangeLogPage } from '../src/shared/changelog'
import type { Server } from '../src/renderer/src/types'

// The panel half of roadmap item 14.
//
// These assert what an operator SEES, because everything this item can get
// wrong looks fine on screen: a timeline missing a source it could not read, a
// filtered page that hides unattributed rows without a word, and a switched-off
// view that renders as an uneventful week.

const T0 = 1_700_000_000_000

function server(id: string, name: string): Server {
  return {
    id,
    workspaceId: 'ws-default',
    folderId: null,
    name,
    host: `${id}.example.internal`,
    port: 22,
    username: 'ops',
    auth: 'key',
    status: 'online',
    tags: [],
    favorite: false,
    os: 'linux',
    route: [],
    vpnProfileId: null
  }
}

const SERVERS = [server('srv-1', 'web-01'), server('srv-2', 'db-01')]

function entry(over: Partial<ChangeLogEntry> = {}): ChangeLogEntry {
  return {
    id: 'local:l1',
    source: 'local-shell',
    ts: T0,
    actor: 'human',
    kind: 'shell',
    summary: 'zsh (default) exited on this machine',
    detail: ['/bin/zsh', 'exit 0'],
    hostId: null,
    hosts: [],
    ...over
  }
}

function page(over: Partial<ChangeLogPage> = {}): ChangeLogPage {
  return {
    enabled: true,
    entries: [],
    coverage: [
      { source: 'local-shell', state: 'read', entries: 0 },
      { source: 'approvals', state: 'read', entries: 0 },
      { source: 'agent-audit', state: 'read', entries: 0 },
      { source: 'history', state: 'read', entries: 0 }
    ],
    oldest: null,
    more: false,
    ...over
  }
}

/** The stub records the filter it was asked for, so a test can assert what the
 *  controls actually requested rather than that a call happened. */
function stub(reply: (f: ChangeLogFilter) => ChangeLogPage): { asked: ChangeLogFilter[] } {
  const asked: ChangeLogFilter[] = []
  stubBridge({
    changelog: {
      read: async (f: ChangeLogFilter = {}) => {
        asked.push(f)
        return reply(f)
      }
    }
  })
  return { asked }
}

describe('what the change log says it could not read', () => {
  it('names an unreadable source above the timeline rather than dropping it', async () => {
    stub(() =>
      page({
        entries: [entry()],
        coverage: [
          { source: 'local-shell', state: 'read', entries: 1 },
          { source: 'approvals', state: 'unreadable', entries: 0, error: 'EACCES: permission denied' },
          { source: 'agent-audit', state: 'absent', entries: 0 },
          { source: 'history', state: 'truncated', entries: 0, bytesUnread: 4096 }
        ]
      })
    )
    render(<ChangeLogPanel servers={SERVERS} />)

    const approvals = await screen.findByTestId('changelog-coverage-approvals')
    expect(approvals.textContent).toContain(
      'Could NOT be read, so anything it holds is missing from the timeline below.'
    )
    expect(approvals.textContent).toContain('EACCES: permission denied')

    expect(screen.getByTestId('changelog-coverage-agent-audit').textContent).toContain(
      'this record does not exist on this machine'
    )
    expect(screen.getByTestId('changelog-coverage-history').textContent).toContain(
      'Older entries exist and are NOT in the timeline below.'
    )
    // And the one source that did read still renders its row.
    expect(screen.getByTestId('changelog-entries').textContent).toContain(
      'zsh (default) exited on this machine'
    )
  })

  it('says what each source is a record of, whatever state it is in', async () => {
    stub(() => page())
    render(<ChangeLogPanel servers={SERVERS} />)
    expect((await screen.findByTestId('changelog-coverage-agent-audit')).textContent).toContain(
      'what an agent did through the MCP bridge'
    )
    expect(screen.getByTestId('changelog-coverage-local-shell').textContent).toContain(
      'never keystrokes, and never what a shell printed'
    )
  })

  it('does not let an empty page read as a quiet period on its own', async () => {
    stub(() => page())
    render(<ChangeLogPanel servers={SERVERS} />)
    expect((await screen.findByTestId('changelog-empty')).textContent).toContain(
      'read the coverage above before reading that as a quiet period'
    )
  })
})

describe('the switch', () => {
  it('shows what being off does and does not turn off, and no timeline', async () => {
    stub(() =>
      page({
        enabled: false,
        coverage: [
          { source: 'local-shell', state: 'off', entries: 0 },
          { source: 'approvals', state: 'off', entries: 0 },
          { source: 'agent-audit', state: 'off', entries: 0 },
          { source: 'history', state: 'off', entries: 0 }
        ]
      })
    )
    render(<ChangeLogPanel servers={SERVERS} />)

    const off = await screen.findByTestId('changelog-off')
    expect(off.textContent).toContain('does NOT stop anything being recorded')
    expect(off.textContent).toContain(
      'Switching this off removes the timeline, not the records behind it.'
    )
    // The tab is reachable and says why it is empty. It does not render a
    // coverage table or an empty timeline, either of which would invite the
    // reading that the sources were consulted and had nothing.
    expect(screen.queryByTestId('changelog-entries')).toBe(null)
    expect(screen.queryByTestId('changelog-empty')).toBe(null)
    expect(screen.queryByTestId('changelog-coverage-history')).toBe(null)
  })

  it('says so when the bridge cannot be reached at all', async () => {
    stubBridge({})
    render(<ChangeLogPanel servers={SERVERS} />)
    expect((await screen.findByTestId('changelog-unavailable')).textContent).toContain(
      'Nothing below is a statement about what happened.'
    )
  })
})

describe('the timeline', () => {
  it('renders the order it was given rather than re-sorting it', async () => {
    // The ordering is total and lives in shared/changelog.ts. A second opinion
    // here is how two screens end up disagreeing about what happened when.
    stub(() =>
      page({
        entries: [
          entry({ id: 'a', ts: T0, summary: 'newest' }),
          entry({ id: 'b', ts: T0 + 5000, summary: 'arrived second' }),
          entry({ id: 'c', ts: T0 - 5000, summary: 'oldest' })
        ]
      })
    )
    render(<ChangeLogPanel servers={SERVERS} />)
    const text = (await screen.findByTestId('changelog-entries')).textContent ?? ''
    expect(text.indexOf('newest')).toBeLessThan(text.indexOf('arrived second'))
    expect(text.indexOf('arrived second')).toBeLessThan(text.indexOf('oldest'))
  })

  it('labels an agent row as an agent and a system row as neither of the two', async () => {
    stub(() =>
      page({
        entries: [
          entry({ id: 'g', actor: 'agent', summary: 'ran a terminal call', hosts: ['db-01'] }),
          entry({ id: 's', actor: 'system', summary: 'host-unreachable' })
        ]
      })
    )
    render(<ChangeLogPanel servers={SERVERS} />)
    const text = (await screen.findByTestId('changelog-entries')).textContent ?? ''
    expect(text).toContain('An agent · ran a terminal call · db-01')
    expect(text).toContain('ShellPilot itself · host-unreachable')
  })

  it('shows the commands and targets it was given', async () => {
    stub(() =>
      page({
        entries: [
          entry({
            id: 'a',
            actor: 'human',
            kind: 'approval',
            summary: 'Job granted — Restart nginx',
            detail: ['systemctl restart nginx'],
            hosts: ['web-01']
          })
        ]
      })
    )
    render(<ChangeLogPanel servers={SERVERS} />)
    const text = (await screen.findByTestId('changelog-entries')).textContent ?? ''
    expect(text).toContain('You · Job granted — Restart nginx · web-01')
    expect(text).toContain('systemctl restart nginx')
  })

  it('says when a host filter hid rows that name no host', async () => {
    stub(() => page({ entries: [entry()], hostFilterHidUnattributed: 3 }))
    render(<ChangeLogPanel servers={SERVERS} />)
    expect((await screen.findByTestId('changelog-host-filter-note')).textContent).toContain(
      '3 entries in this window name no host at all'
    )
  })

  it('says when the page was cut rather than showing its last row as the end', async () => {
    stub(() => page({ entries: [entry()], more: true, oldest: T0 }))
    render(<ChangeLogPanel servers={SERVERS} />)
    expect((await screen.findByTestId('changelog-more')).textContent).toContain(
      'More entries matched than fit on one page'
    )
  })
})

describe('filters', () => {
  it('asks for a window rather than reading everything by default', async () => {
    const { asked } = stub(() => page())
    render(<ChangeLogPanel servers={SERVERS} />)
    await waitFor(() => expect(asked.length).toBeGreaterThan(0))
    // Seven days is the default, so the first read is bounded.
    expect(asked[0].from).toBeGreaterThan(Date.now() - 7 * 86_400_000 - 5000)
    expect(asked[0].from).toBeLessThanOrEqual(Date.now() - 7 * 86_400_000 + 5000)
    expect(asked[0].actors).toBeUndefined()
    expect(asked[0].kinds).toBeUndefined()
    expect(asked[0].hosts).toBeUndefined()
  })

  it('asks main for the narrowed read rather than narrowing what it already has', async () => {
    // Filtering in the renderer would silently break the per-source budget:
    // main would still return the newest 200 of everything and the panel would
    // show whichever few of them matched, which is not the same answer.
    const { asked } = stub(() => page())
    render(<ChangeLogPanel servers={SERVERS} />)
    await waitFor(() => expect(asked.length).toBeGreaterThan(0))

    await userEvent.selectOptions(screen.getByLabelText('Who'), 'agent')
    await waitFor(() => expect(asked[asked.length - 1].actors).toEqual(['agent']))

    await userEvent.selectOptions(screen.getByLabelText('What'), 'approval')
    await waitFor(() => expect(asked[asked.length - 1].kinds).toEqual(['approval']))

    await userEvent.selectOptions(screen.getByLabelText('Host'), 'srv-2')
    await waitFor(() => expect(asked[asked.length - 1].hosts).toEqual(['srv-2']))

    await userEvent.selectOptions(screen.getByLabelText('Time range'), 'all')
    await waitFor(() => expect(asked[asked.length - 1].from).toBeUndefined())
    // The other three survive the fourth change.
    const last = asked[asked.length - 1]
    expect(last.actors).toEqual(['agent'])
    expect(last.kinds).toEqual(['approval'])
    expect(last.hosts).toEqual(['srv-2'])
  })
})
