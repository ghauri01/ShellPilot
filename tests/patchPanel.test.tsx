// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { PatchPanel } from '../src/renderer/src/components/monitor/PatchPanel'
import { useFleet } from '../src/renderer/src/store/fleet'
import { useApp } from '../src/renderer/src/store/app'
import {
  FACT_SOURCE_IDS,
  FACT_SOURCE_LABEL,
  type FactSourceId,
  type FactSourceReport,
  type FactStatus,
  type HostFacts
} from '../src/shared/hostFacts'
import type { Server } from '../src/renderer/src/types'

// The patch screen, rendered.
//
// Three things are asserted here and nowhere else, because they are properties
// of what a person SEES rather than of what a function returns:
//
//  1. A host that can never report a security count is excluded from the total
//     and from the all-clear, in words, on the screen.
//  2. The reboot refusal is a disabled button and a named reason, not a
//     confirmation the operator can click past.
//  3. The topology hole — hops with no saved server behind them — is printed
//     next to those refusals, where it qualifies them.
//
// The rest of item 17's decisions are tested in tests/patch.test.ts, where they
// are made.

function server(id: string, name: string, route: Server['route'] = []): Server {
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
    route,
    vpnProfileId: null
  }
}

function hop(serverId: string | null): Server['route'][number] {
  return {
    id: `hop-${serverId ?? 'bare'}`,
    label: 'jump',
    host: 'jump.example.internal',
    port: 22,
    username: 'ops',
    auth: 'key',
    ...(serverId === null ? {} : { serverId })
  }
}

const sources = (over: Partial<Record<FactSourceId, FactStatus>> = {}): FactSourceReport[] =>
  FACT_SOURCE_IDS.map((id) => ({ id, label: FACT_SOURCE_LABEL[id], status: over[id] ?? 'ok' }))

const facts = (over: Partial<HostFacts> = {}): HostFacts => ({
  distroId: 'ubuntu',
  distroVersion: '24.04',
  prettyName: 'Ubuntu 24.04.1 LTS',
  arch: 'x86_64',
  cpuModel: 'AMD EPYC',
  packageManager: 'apt',
  pendingUpdates: 0,
  securityUpdates: 0,
  rebootRequired: false,
  rebootReason: null,
  virtualisation: 'kvm',
  metadataAt: Date.now(),
  collectedAt: Date.now(),
  sources: sources(),
  ...over
})

function seedFacts(entries: Record<string, HostFacts>): void {
  const at = Date.now()
  for (const [id, f] of Object.entries(entries)) useFleet.getState().reportFacts(id, f, at)
}

beforeEach(() => {
  stubBridge({ jobs: { onProgress: () => () => {}, run: vi.fn() } })
})

describe('the security column', () => {
  it('excludes a host that cannot answer from the total and from the all-clear', async () => {
    // Two hosts, nothing pending on either as far as anyone can tell — and one
    // of them can NEVER report a security count. The estate is not clear, and
    // the screen has to say so rather than printing a reassuring zero.
    seedFacts({
      a: facts(),
      b: facts({
        distroId: 'arch',
        packageManager: 'pacman',
        securityUpdates: null,
        sources: sources({ 'security-updates': 'unsupported' })
      })
    })
    render(<PatchPanel servers={[server('a', 'ubuntu-1'), server('b', 'archbox')]} />)

    const summary = await screen.findByTestId('patch-summary')
    expect(summary.textContent).not.toContain('All clear')
    expect(summary.textContent).toContain('not an all-clear')

    // And the cell itself is words, not a number and not a dash.
    const cell = document.querySelector('tr[data-host="archbox"] td[data-col="security"]')
    expect(cell?.textContent).toBe('cannot be answered')

    expect(screen.getByTestId('patch-unanswerable').textContent).toContain(
      'can never report a security update count'
    )
  })

  it('says all clear only when every host answered', async () => {
    seedFacts({ a: facts(), b: facts() })
    render(<PatchPanel servers={[server('a', 'one'), server('b', 'two')]} />)
    const summary = await screen.findByTestId('patch-summary')
    expect(summary.textContent).toContain('All clear')
    expect(summary.textContent).toContain('Every host answered')
  })
})

describe('the reboot refusal', () => {
  it('will not let a jump host be restarted, and names who depends on it', async () => {
    seedFacts({
      bastion: facts({ pendingUpdates: 4, rebootRequired: true, rebootReason: 'linux-image' }),
      web: facts({ pendingUpdates: 2 })
    })
    const servers = [server('bastion', 'bastion'), server('web', 'web-1', [hop('bastion')])]
    render(<PatchPanel servers={servers} />)

    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Select bastion'))
    await user.click(screen.getByLabelText('Select web-1'))
    // Restarting is opt-in; the refusal only exists once it is asked for.
    expect(screen.queryByTestId('patch-block')).toBeNull()
    await user.click(screen.getByRole('checkbox', { name: /restart the hosts/i }))

    const block = await screen.findByTestId('patch-block')
    expect(block.textContent).toContain('bastion is the jump host')
    expect(block.textContent).toContain('web-1')
    // A HARD REFUSAL: the run button is disabled. Not a confirmation, not a
    // checkbox to tick past — a question asked fifteen times during a staged
    // upgrade is answered by reflex.
    expect((screen.getByTestId('patch-run') as HTMLButtonElement).disabled).toBe(true)
  })

  it('does not refuse when nothing is being restarted', async () => {
    seedFacts({ bastion: facts({ pendingUpdates: 4 }), web: facts({ pendingUpdates: 2 }) })
    render(
      <PatchPanel servers={[server('bastion', 'bastion'), server('web', 'web-1', [hop('bastion')])]} />
    )
    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Select bastion'))
    expect(screen.queryByTestId('patch-block')).toBeNull()
    await waitFor(() => expect((screen.getByTestId('patch-run') as HTMLButtonElement).disabled).toBe(false))
  })
})

describe('the hole in the topology', () => {
  it('reports hops that could not be matched to saved servers rather than failing open', async () => {
    // Two servers share a bastion that was never saved. The graph cannot see
    // the edge, so neither host looks like a jump host — and the screen must
    // say that the check it just ran has a blind spot.
    seedFacts({ a: facts({ pendingUpdates: 1, rebootRequired: true }), b: facts({ pendingUpdates: 1 }) })
    render(
      <PatchPanel
        servers={[server('a', 'web-1', [hop(null)]), server('b', 'app-1', [hop(null)])]}
      />
    )
    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Select web-1'))
    await user.click(screen.getByRole('checkbox', { name: /restart the hosts/i }))

    const note = await screen.findByTestId('patch-unmatched-hops')
    expect(note.textContent).toContain('2 hops are not backed by a saved server')
    expect(note.textContent).toContain('share a bastion')
    // Nothing was blocked — there is nothing to block on — so the run is
    // allowed. The note is what stops that reading as "checked and safe".
    expect(screen.queryByTestId('patch-block')).toBeNull()
  })
})

describe('what the screen refuses to offer', () => {
  it('says out loud that it will not patch on a schedule', async () => {
    render(<PatchPanel servers={[server('a', 'one')]} />)
    const note = await screen.findByTestId('patch-no-automation')
    expect(note.textContent).toContain('does not patch on a schedule')
    expect(note.textContent).toContain('unattended-upgrades')
  })

  it('excludes a host it has no security-only command for, by name', async () => {
    seedFacts({
      a: facts({
        distroId: 'arch',
        packageManager: 'pacman',
        pendingUpdates: 7,
        securityUpdates: null,
        sources: sources({ 'security-updates': 'unsupported' })
      })
    })
    render(<PatchPanel servers={[server('a', 'archbox')]} />)
    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Select archbox'))
    await user.selectOptions(screen.getByLabelText('What to install'), 'security')
    const excluded = await screen.findByTestId('patch-excluded')
    expect(excluded.textContent).toContain('archbox')
    expect(excluded.textContent).toContain('Arch has no security channel')
    expect((screen.getByTestId('patch-run') as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('running it', () => {
  it('sends the reboot step as its own step, with a confirmation to match', async () => {
    seedFacts({ a: facts({ pendingUpdates: 3, rebootRequired: true }) })
    const run = vi.fn().mockResolvedValue({})
    stubBridge({ jobs: { onProgress: () => () => {}, run } })
    render(<PatchPanel servers={[server('a', 'web-1')]} />)

    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Select web-1'))
    await user.click(screen.getByRole('checkbox', { name: /restart the hosts/i }))
    await user.click(screen.getByTestId('patch-run'))

    // A declared reboot is destructive, so the dialog demands the word.
    const typed = await screen.findByLabelText('Type RUN to confirm')
    await user.type(typed, 'RUN')
    await user.click(screen.getByTestId('patch-confirm'))

    await waitFor(() => expect(run).toHaveBeenCalledTimes(1))
    const req = run.mock.calls[0][0]
    expect(req.spec.kind).toBe('patch')
    expect(req.spec.steps).toHaveLength(2)
    // The reboot is a STEP, with its own line, so it is inside the approval
    // record's command text by construction. Nothing reboots that the operator
    // was not shown.
    expect(req.spec.steps[1].reboot).toBe(true)
    expect(req.approval.commands).toEqual(req.spec.steps.map((s: { command: string }) => s.command))
    expect(req.approval.phrase).toBe('RUN')
    expect(req.targets[0].cohort).toBe('wave-1')
  })

  it('prints main’s refusal instead of leaving the panel wedged', async () => {
    seedFacts({ a: facts({ pendingUpdates: 3 }) })
    const run = vi.fn().mockRejectedValue(new Error('This job was not started: bastion is the jump host'))
    stubBridge({ jobs: { onProgress: () => () => {}, run } })
    render(<PatchPanel servers={[server('a', 'web-1')]} />)

    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Select web-1'))
    await user.click(screen.getByTestId('patch-run'))
    const confirm = screen.queryByTestId('patch-confirm')
    if (confirm) await user.click(confirm)

    const err = await screen.findByTestId('patch-error')
    expect(err.textContent).toContain('This job was not started')
  })
})

describe('the workspace’s own databases', () => {
  it('will not restart two hosts carrying the same saved database in one wave', async () => {
    seedFacts({
      a: facts({ pendingUpdates: 1, rebootRequired: true }),
      b: facts({ pendingUpdates: 1, rebootRequired: true })
    })
    useApp.setState({
      databases: [
        {
          id: 'd1',
          workspaceId: 'ws-default',
          name: 'orders primary',
          kind: 'postgres',
          host: 'x',
          port: 5432,
          username: 'app',
          database: 'orders',
          ssl: false,
          uri: false,
          folderId: null,
          sshServerId: 'a',
          vpnProfileId: null
        },
        {
          id: 'd2',
          workspaceId: 'ws-default',
          name: 'orders replica',
          kind: 'postgres',
          host: 'y',
          port: 5432,
          username: 'app',
          database: 'orders',
          ssl: false,
          uri: false,
          folderId: null,
          sshServerId: 'b',
          vpnProfileId: null
        }
      ]
    })
    render(<PatchPanel servers={[server('a', 'db-a'), server('b', 'db-b')]} />)

    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Select db-a'))
    await user.click(screen.getByLabelText('Select db-b'))
    await user.click(screen.getByRole('checkbox', { name: /restart the hosts/i }))
    // Waves of one is the default, and by itself it already separates them.
    // Widen the wave so both would restart together: refused.
    // fireEvent, not user.type: the field is a controlled number input, so
    // clear-then-type appends to the value React re-rendered rather than
    // replacing it — and a test that set 12 while believing it set 2 would
    // pass for the wrong reason.
    fireEvent.change(screen.getByLabelText('Hosts per wave'), { target: { value: '2' } })
    // Both in one wave: refused.
    const blocks = await screen.findAllByTestId('patch-block')
    expect(blocks).toHaveLength(2)
    expect(blocks[0].textContent).toContain('does not know whether they replicate')
    expect((screen.getByTestId('patch-run') as HTMLButtonElement).disabled).toBe(true)

    // One per wave: allowed.
    fireEvent.change(screen.getByLabelText('Hosts per wave'), { target: { value: '1' } })
    await waitFor(() => expect(screen.queryByTestId('patch-block')).toBeNull())
  })
})
