// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { RulesPanel } from '../src/renderer/src/components/monitor/RulesPanel'
import { jobApprovalFor } from '../src/shared/jobs'
import type { JobSpec, JobTargetRef } from '../src/shared/jobs'
import type { RuleDraftWire, RuleView } from '../src/shared/rules'
import type { Server } from '../src/renderer/src/types'

// The panel half of roadmap item 27, rendered rather than read.
//
// What this asserts is what an OPERATOR sees, because the failures that matter
// here all look fine. A rule that cannot run still renders as a rule; a rule
// with no ceiling renders identically to one with a sensible ceiling; and a
// standing authorisation created with one click renders exactly like one
// created deliberately. Every one of those is a screen with no error on it.

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

const ALPHA = server('srv-a', 'alpha')
const BRAVO = server('srv-b', 'bravo')
const SERVERS = [ALPHA, BRAVO]

const TARGETS: JobTargetRef[] = [
  { serverId: 'srv-a', serverName: 'alpha' },
  { serverId: 'srv-b', serverName: 'bravo' }
]

const SPEC: JobSpec = {
  kind: 'command',
  title: 'clear the journal',
  steps: [{ command: 'journalctl --vacuum-size=200M' }]
}

function jobRuleView(over: Partial<RuleView> = {}): RuleView {
  return {
    id: 'r1',
    name: 'vacuum the journal',
    enabled: true,
    trigger: { kind: 'disk', event: 'raised' },
    filter: {},
    action: {
      type: 'job',
      spec: SPEC,
      targets: TARGETS,
      approval: jobApprovalFor(SPEC, TARGETS, { phrase: null, confirmedAt: T0 })
    },
    limit: { maxFirings: 1, windowMs: 3_600_000 },
    armedAt: T0,
    status: { ruleId: 'r1', fired: [], suppressed: 0 },
    verdict: { ok: true },
    ...over
  }
}

function mount(rules: RuleView[], over: Record<string, unknown> = {}) {
  const create = vi.fn(async (_d: RuleDraftWire) => jobRuleView())
  const setEnabled = vi.fn(async () => true)
  const remove = vi.fn(async () => true)
  stubBridge({ rules: { list: async () => rules, create, setEnabled, remove, ...over } })
  return { create, setEnabled, remove, ...render(<RulesPanel servers={SERVERS} />) }
}

describe('reading a rule back', () => {
  it('shows the command and the hosts, not a job id', async () => {
    // A standing authorisation nobody can read back is not consent, it is a
    // setting. The step TEXT is what somebody has to be able to check a year
    // later, and a job id is not it.
    mount([jobRuleView()])
    expect(await screen.findByText('journalctl --vacuum-size=200M')).toBeTruthy()
    expect(screen.getByText(/Then run/)).toBeTruthy()
    expect(screen.getByText(/alpha, bravo/)).toBeTruthy()
  })

  it('says how often it may act, as a sentence', async () => {
    // A pair of numbers in a table is not read as "this may restart your
    // database once an hour".
    mount([jobRuleView()])
    expect(await screen.findByText(/At most once in an hour/)).toBeTruthy()
  })

  it('says how many events the ceiling has already declined', async () => {
    mount([jobRuleView({ status: { ruleId: 'r1', fired: [T0], suppressed: 37, lastFiredAt: T0 } })])
    expect(await screen.findByText(/37 matching event\(s\) declined by the rate limit/)).toBeTruthy()
  })

  it('says a rule has never acted rather than leaving the line blank', async () => {
    // A blank where a timestamp goes reads as "recently", which is the one
    // thing it is not.
    mount([jobRuleView()])
    expect(await screen.findByText(/has not acted yet/)).toBeTruthy()
  })

  it('shows a drifted rule as refusing, in daylight', async () => {
    // The failure this panel exists to prevent: a rule whose approval no
    // longer covers its spec renders identically to a working one, and the
    // operator finds out from a webhook at 3am.
    mount([
      jobRuleView({
        verdict: { ok: false, reason: 'step 1 was approved as `a` and is now `b`.' }
      })
    ])
    expect(await screen.findByText(/This rule will not run/)).toBeTruthy()
    expect(screen.getByText(/step 1 was approved as `a` and is now `b`/)).toBeTruthy()
  })

  it('shows the last refusal even when the record still verifies', async () => {
    // Main's own gate can refuse for a reason this side cannot see — item 17's
    // reboot-ordering block, for one.
    mount([
      jobRuleView({
        status: {
          ruleId: 'r1',
          fired: [T0],
          suppressed: 0,
          refusal: 'rebooting gateway would cut three hosts.',
          refusedAt: T0
        }
      })
    ])
    expect(await screen.findByText(/would cut three hosts/)).toBeTruthy()
  })

  it('says nothing runs on its own when there are none', async () => {
    mount([])
    expect(await screen.findByText('No rules. Nothing runs on its own.')).toBeTruthy()
  })
})

describe('writing a job rule', () => {
  it('will not create one without the typed word', async () => {
    // `planJob` asks for one click for an ordinary command on two hosts. A
    // standing authorisation is a different thing being agreed to.
    const user = userEvent.setup()
    const h = mount([])
    await user.click(await screen.findByRole('button', { name: /New rule/ }))
    await user.type(screen.getByPlaceholderText('Vacuum the journal'), 'nightly vacuum')
    await user.click(screen.getByLabelText('Run a job'))
    await user.type(screen.getByPlaceholderText('Clear the journal'), 'clear the journal')
    await user.type(
      screen.getByPlaceholderText('journalctl --vacuum-size=200M'),
      'journalctl --vacuum-size=200M'
    )
    await user.click(screen.getByLabelText('alpha'))

    const button = screen.getByRole('button', { name: /Create rule/ })
    expect((button as HTMLButtonElement).disabled).toBe(true)

    await user.type(screen.getByLabelText('Type UNATTENDED to confirm'), 'yes')
    expect((screen.getByRole('button', { name: /Create rule/ }) as HTMLButtonElement).disabled).toBe(true)

    await user.clear(screen.getByLabelText('Type UNATTENDED to confirm'))
    await user.type(screen.getByLabelText('Type UNATTENDED to confirm'), 'UNATTENDED')
    expect((screen.getByRole('button', { name: /Create rule/ }) as HTMLButtonElement).disabled).toBe(false)

    await user.click(screen.getByRole('button', { name: /Create rule/ }))
    await waitFor(() => expect(h.create).toHaveBeenCalled())
  })

  it('sends the pinned pair and an approval minted over it', async () => {
    const user = userEvent.setup()
    const h = mount([])
    await user.click(await screen.findByRole('button', { name: /New rule/ }))
    await user.type(screen.getByPlaceholderText('Vacuum the journal'), 'nightly vacuum')
    await user.click(screen.getByLabelText('Run a job'))
    await user.type(screen.getByPlaceholderText('Clear the journal'), 'clear the journal')
    await user.type(
      screen.getByPlaceholderText('journalctl --vacuum-size=200M'),
      'journalctl --vacuum-size=200M'
    )
    await user.click(screen.getByLabelText('alpha'))
    await user.type(screen.getByLabelText('Type UNATTENDED to confirm'), 'UNATTENDED')
    await user.click(screen.getByRole('button', { name: /Create rule/ }))

    await waitFor(() => expect(h.create).toHaveBeenCalled())
    const draft = h.create.mock.calls[0][0]
    expect(draft.action.type).toBe('job')
    if (draft.action.type !== 'job') throw new Error('unreachable')
    expect(draft.action.spec.steps.map((s) => s.command)).toEqual(['journalctl --vacuum-size=200M'])
    expect(draft.action.targets.map((t) => t.serverId)).toEqual(['srv-a'])
    // The record covers exactly the pair beside it. A record minted over
    // anything else would verify against nothing at the first firing.
    expect(draft.action.approval.commands).toEqual(['journalctl --vacuum-size=200M'])
    expect(draft.action.approval.targets.map((t) => t.serverId)).toEqual(['srv-a'])
    // And the panel never sends an armedAt or an id: a caller that could set
    // those could arm a rule into the past.
    expect('armedAt' in draft).toBe(false)
    expect('id' in draft).toBe(false)
  })

  it('states the blast radius while the rule is being written', async () => {
    // The whole property: knowable when it is written, not when it fires.
    const user = userEvent.setup()
    mount([])
    await user.click(await screen.findByRole('button', { name: /New rule/ }))
    await user.click(screen.getByLabelText('Run a job'))
    await user.type(screen.getByPlaceholderText('journalctl --vacuum-size=200M'), 'rm -rf /var/cache/*')
    await user.click(screen.getByLabelText('alpha'))
    await user.click(screen.getByLabelText('bravo'))

    expect(await screen.findByText(/2 host\(s\) at once/)).toBeTruthy()
    expect(screen.getByText(/destructive/)).toBeTruthy()
    expect(screen.getByText(/every time it fires/)).toBeTruthy()
  })

  it('needs no typed word for a rule that only posts to the webhook', async () => {
    // A notification carries no authority, and demanding a ceremony for it
    // would teach people to type the word without reading it.
    const user = userEvent.setup()
    const h = mount([])
    await user.click(await screen.findByRole('button', { name: /New rule/ }))
    await user.type(screen.getByPlaceholderText('Vacuum the journal'), 'tell me')
    expect((screen.getByRole('button', { name: /Create rule/ }) as HTMLButtonElement).disabled).toBe(false)
    expect(screen.queryByLabelText('Type UNATTENDED to confirm')).toBeNull()
    await user.click(screen.getByRole('button', { name: /Create rule/ }))
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    expect(h.create.mock.calls[0][0].action).toEqual({ type: 'notify' })
  })

  it('offers only the kinds a rule can actually watch', async () => {
    // `memory` is not on the list and the panel must not offer it. A select
    // whose options outrun what the engine accepts is a rule that is created,
    // shown, and silently never fires.
    const user = userEvent.setup()
    mount([])
    await user.click(await screen.findByRole('button', { name: /New rule/ }))
    const options = [...(screen.getByLabelText('When') as HTMLSelectElement).options].map((o) => o.value)
    expect(options).toEqual([
      'cpu',
      'disk',
      'inode',
      'load',
      'cert-expiry',
      'host-unreachable',
      'job-failed',
      'tunnel-down',
      'oom-kill',
      'db-alarm',
      'db-watch'
    ])
  })
})

describe('turning a rule off', () => {
  it('asks main rather than hiding it locally', async () => {
    // A panel that filtered a disabled rule out of its own list would show a
    // rule as off while the engine went on firing it.
    const user = userEvent.setup()
    const h = mount([jobRuleView()])
    await user.click(await screen.findByLabelText('Enable vacuum the journal'))
    await waitFor(() => expect(h.setEnabled).toHaveBeenCalledWith('r1', false))
  })

  it('shows a disabled rule as disabled rather than dropping it', async () => {
    mount([jobRuleView({ enabled: false })])
    expect(await screen.findByText('Disabled')).toBeTruthy()
    // Still fully legible: what it would run, and where, stays on screen.
    expect(screen.getByText('journalctl --vacuum-size=200M')).toBeTruthy()
  })

  it('deletes through main too', async () => {
    const user = userEvent.setup()
    const h = mount([jobRuleView()])
    await user.click(await screen.findByLabelText('Delete vacuum the journal'))
    await waitFor(() => expect(h.remove).toHaveBeenCalledWith('r1'))
  })
})

describe('a bridge that is not there', () => {
  it('renders rather than taking the window down', async () => {
    // The dev-server case src/renderer/src/lib/bridge.ts is written for: the
    // renderer is newer than the preload, so every method is undefined.
    stubBridge({})
    render(<RulesPanel servers={SERVERS} />)
    expect(await screen.findByText('No rules. Nothing runs on its own.')).toBeTruthy()
  })
})
