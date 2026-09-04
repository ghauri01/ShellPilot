// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { DockerPanel } from '../src/renderer/src/components/docker/DockerPanel'
import { InventoryPanel } from '../src/renderer/src/components/monitor/InventoryPanel'
import { RulesPanel } from '../src/renderer/src/components/monitor/RulesPanel'
import { BroadcastPanel } from '../src/renderer/src/components/monitor/BroadcastPanel'
import { ChangeLogPanel } from '../src/renderer/src/components/monitor/ChangeLogPanel'
import type { Server } from '../src/renderer/src/types'

// The complaint these panels were redesigned for, turned into assertions.
//
// Verbatim: "font size for information architecture, colors to highlight next
// actions, sort of self guiding design principles so the user is not confused
// on any page on what to do next". Two of those three are things a test can
// hold: whether a panel that has nothing to show says what to do about it, and
// whether the one thing to press is singular and reachable.
//
// So every test here is about a panel with NOTHING IN IT. That is the state the
// complaint was about — the Docker tab named in it is a heading, a sentence, a
// dropdown and a button — and it is the state no previous test covered, because
// every existing panel suite stubs a populated bridge and asserts on rows.
//
// Two deliberate choices about what is asserted:
//
//  * Visible text, not class names, for the guidance. What matters is that the
//    empty panel names its next step in words a person can act on.
//
//  * ONE structural assertion, `primaryActions`, which does read a class. There
//    is no way around it: "exactly one control is highlighted" is a claim about
//    what the eye lands on, jsdom loads no stylesheet, and the regression it
//    guards is precisely the one that shipped — eleven panels where the primary
//    action was drawn as a secondary, and two where the ONLY primary was a
//    destructive action. Asserting the count rather than the identity keeps it
//    about the property and not about the markup.

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

const ALPHA = server('srv-a', 'alpha')
const SERVERS = [ALPHA]

/** Buttons drawn as the panel's call to action. */
function primaryActions(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll('button.btn.primary')] as HTMLElement[]
}

describe('the panel the complaint named: Docker with nothing read', () => {
  // "The Docker tab is a card with a heading, one sentence of explanation, a
  // host dropdown and a Read containers button — and nothing tells the user
  // that pressing the button is the thing to do."
  const stub = (): { list: ReturnType<typeof vi.fn> } => {
    const list = vi.fn(async () => ({
      ok: true,
      version: '24.0.7',
      composeLabels: 'read',
      containers: []
    }))
    stubBridge({ docker: { list } })
    return { list }
  }

  it('marks Read containers as the one thing to press', () => {
    stub()
    const { container } = render(<DockerPanel servers={SERVERS} />)

    const actions = primaryActions(container as HTMLElement)
    expect(actions).toHaveLength(1)
    expect(actions[0].textContent).toContain('Read containers')
  })

  it('says what pressing it will do, before it has been pressed', () => {
    stub()
    render(<DockerPanel servers={SERVERS} />)

    // The panel used to describe the mechanism and never name the step. Both
    // halves have to be there: what it runs, and that YOU are the one to start
    // it.
    expect(screen.getByText(/Nothing has been read yet/)).toBeTruthy()
    expect(screen.getByText(/Press/).textContent).toContain('Read containers')
    expect(screen.getByText(/docker ps/)).toBeTruthy()
  })

  it('leaves the button reachable, and it reads the selected server', async () => {
    const { list } = stub()
    render(<DockerPanel servers={SERVERS} />)

    const button = screen.getByRole('button', { name: /Read containers/ })
    expect((button as HTMLButtonElement).disabled).toBe(false)
    await userEvent.click(button)
    await waitFor(() => expect(list).toHaveBeenCalled())
    expect(list.mock.calls[0][0]).toMatchObject({ serverId: ALPHA.id })
  })

  it('tells an operator with no online server what to do instead', () => {
    stub()
    render(<DockerPanel servers={[]} />)

    // Previously one grey sentence stating the problem and nothing else.
    expect(screen.getByText(/No server in this workspace is online/)).toBeTruthy()
    expect(screen.getByText(/Connect a server from the sidebar/)).toBeTruthy()
  })
})

describe('an inventory that has collected nothing', () => {
  it('keeps its explanation and gains the door it points at', () => {
    stubBridge({})
    render(<InventoryPanel servers={SERVERS} />)

    // The sentence was always right; it named two next steps and offered
    // neither as a control. Check now is now the panel's primary, and the
    // Settings half has a button.
    expect(screen.getByText(/No server facts have been collected yet/)).toBeTruthy()
    expect(screen.getByRole('button', { name: /Check now/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /Open Monitoring settings/ })).toBeTruthy()
  })

  it('highlights exactly one action, and it is Check now', () => {
    stubBridge({})
    const { container } = render(<InventoryPanel servers={SERVERS} />)

    const actions = primaryActions(container as HTMLElement)
    expect(actions).toHaveLength(1)
    expect(actions[0].textContent).toContain('Check now')
  })
})

describe('a rules screen with no rules', () => {
  it('keeps the reassurance and adds the next step', async () => {
    stubBridge({ rules: { list: async () => [] } })
    render(<RulesPanel servers={SERVERS} />)

    // "No rules. Nothing runs on its own." is the sentence a standing-automation
    // screen owes its reader, and it was the whole of the empty state — 12px
    // grey, no action, no explanation of what a rule even is.
    expect(await screen.findByText(/No rules\. Nothing runs on its own\./)).toBeTruthy()
    expect(screen.getByText(/Press/).textContent).toContain('New rule')
    expect(screen.getByText(/refuses to run if either of those changes/)).toBeTruthy()
  })

  it('makes New rule the highlighted action', async () => {
    stubBridge({ rules: { list: async () => [] } })
    const { container } = render(<RulesPanel servers={SERVERS} />)

    await screen.findByText(/No rules/)
    const actions = primaryActions(container as HTMLElement)
    expect(actions).toHaveLength(1)
    expect(actions[0].textContent).toContain('New rule')
  })
})

describe('a broadcast composer that has run nothing', () => {
  it('states the order the two steps go in', () => {
    stubBridge({})
    render(<BroadcastPanel servers={SERVERS} />)

    // This panel had NO empty state at all: with a server online it drew a
    // command field, a row of host chips and stopped. That picking hosts is a
    // separate step from typing was left to be inferred.
    expect(screen.getByText(/Nothing has been run yet/)).toBeTruthy()
    expect(screen.getByText(/Pick the servers to run on from the row above/)).toBeTruthy()
  })

  it('counts the servers back once some are picked', async () => {
    stubBridge({})
    render(<BroadcastPanel servers={SERVERS} />)

    await userEvent.click(screen.getByRole('button', { name: 'alpha' }))
    expect(screen.getByText(/1 server selected\. Type a command above, then press Run\./)).toBeTruthy()
  })

  it('does not offer Run as the highlighted action until it can be used', () => {
    stubBridge({})
    const { container } = render(<BroadcastPanel servers={SERVERS} />)

    // Run stays the primary — it IS the action — but it is disabled with no
    // host and no command, so the highlight is not an invitation to a dead end.
    const actions = primaryActions(container as HTMLElement)
    expect(actions).toHaveLength(1)
    expect(actions[0].textContent).toContain('Run')
    expect((actions[0] as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('a change log with an empty window', () => {
  const page = (): unknown => ({
    enabled: true,
    entries: [],
    coverage: [],
    more: false,
    oldest: null
  })

  it('promotes its only action out of the ghost styling it shipped in', async () => {
    stubBridge({ changelog: { read: async () => page() } })
    const { container } = render(<ChangeLogPanel servers={SERVERS} />)

    await screen.findByTestId('changelog-empty')
    const actions = primaryActions(container as HTMLElement)
    expect(actions).toHaveLength(1)
    expect(actions[0].textContent).toContain('Refresh')
  })

  it('keeps the coverage warning and adds what to try next', async () => {
    stubBridge({ changelog: { read: async () => page() } })
    render(<ChangeLogPanel servers={SERVERS} />)

    const empty = await screen.findByTestId('changelog-empty')
    expect(empty.textContent).toContain('read the coverage above before reading that as a quiet period')
    expect(within(empty).getByText(/Widening the time range/)).toBeTruthy()
  })
})
