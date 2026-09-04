// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { AlertsPanel } from '../src/renderer/src/components/monitor/AlertsPanel'
import { useAlerts, resetAlertsForTests } from '../src/renderer/src/store/alerts'
import { useApp } from '../src/renderer/src/store/app'
import { useFleetStatus } from '../src/renderer/src/store/fleetStatus'
import {
  RUNBOOK_HOST_REPORTED_NOTE,
  RUNBOOK_NEVER_FIRED,
  RUNBOOK_NOTHING_RUN,
  RUNBOOK_NO_RUN_NOTE,
  RUNBOOK_STORE_DISABLED,
  RUNBOOK_STORE_UNREADABLE,
  type RunbookView
} from '../src/shared/runbooks'

// Runbooks attached to alerts — roadmap item 28, on screen.
//
// "When the disk alert fires, show the three commands that fixed it last time."
// Everything asserted here is a literal a person reads, because the four ways
// of having nothing to show are four different claims and a test that compared
// them to each other would pass while the screen said the wrong one.

const T0 = new Date('2026-05-02T10:00:00Z').getTime()

/** The workspace's own default id, so `workspaceServers()` returns it. */
const SERVER = {
  id: 's1',
  workspaceId: 'ws-default',
  folderId: null,
  name: 'web-1',
  host: 'example.test',
  port: 22,
  username: 'root',
  auth: 'key' as const,
  status: 'offline' as const,
  tags: [],
  favorite: false,
  os: 'Linux',
  route: [],
  vpnProfileId: null
}
const MIN = 60_000

let views: RunbookView[]
let saved: { kind: string; hostId: string | null; text: string }[]
let saveOk: boolean
let bridgeMissing: boolean

function view(over: Partial<RunbookView> = {}): RunbookView {
  return {
    kind: 'disk',
    hostId: 's1',
    hostNote: null,
    kindNote: null,
    notesUnreadable: false,
    recall: { status: 'never-fired' },
    ...over
  }
}

function install(): void {
  stubBridge({
    getVersion: () => Promise.resolve('9.9.9'),
    notify: { show: () => {} },
    alerts: { record: () => Promise.resolve(true), history: () => Promise.resolve([]) },
    ...(bridgeMissing
      ? {}
      : {
          runbooks: {
            read: () => Promise.resolve(views.shift() ?? view()),
            saveNote: (kind: string, hostId: string | null, text: string) => {
              saved.push({ kind, hostId, text })
              return Promise.resolve({ ok: saveOk, note: null })
            }
          }
        })
  })
}

beforeEach(() => {
  views = []
  saved = []
  saveOk = true
  bridgeMissing = false
  install()
  resetAlertsForTests()
  useFleetStatus.getState().setStatus(null)
  useApp.getState().setSettings({ resourceAlertsEnabled: true, fleetSamplingEnabled: false })
  vi.useFakeTimers({ shouldAdvanceTime: true })
  vi.setSystemTime(T0)
})

afterEach(() => {
  vi.useRealTimers()
})

// =========================================================================
// The four ways of having nothing to show
// =========================================================================

describe('an alert kind with no history', () => {
  it('says it has not fired here rather than showing an empty list', async () => {
    views = [view({ recall: { status: 'never-fired' } })]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-never-fired')).toBeTruthy())
    expect(screen.getByTestId('runbook-never-fired').textContent).toBe(RUNBOOK_NEVER_FIRED)
    expect(screen.queryByTestId('runbook-commands')).toBeNull()
    expect(screen.queryByTestId('runbook-nothing-run')).toBeNull()
    expect(screen.queryByTestId('runbook-unavailable')).toBeNull()
  })

  it('says nothing was run, which is a different sentence again', async () => {
    views = [
      view({
        recall: { status: 'nothing-run', occurrences: [{ at: T0 - 60 * MIN, resolvedAt: null, jobs: [], elided: 0 }] }
      })
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-nothing-run')).toBeTruthy())
    expect(screen.getByTestId('runbook-nothing-run').textContent).toBe(RUNBOOK_NOTHING_RUN)
    expect(screen.queryByTestId('runbook-never-fired')).toBeNull()
  })
})

describe('a store that could not be read', () => {
  it('says so, and does not say nothing was run', async () => {
    views = [view({ recall: { status: 'unavailable', reason: 'store-unreadable' } })]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-unavailable')).toBeTruthy())
    expect(screen.getByTestId('runbook-unavailable').textContent).toBe(RUNBOOK_STORE_UNREADABLE)
    expect(screen.queryByTestId('runbook-nothing-run')).toBeNull()
    expect(screen.queryByTestId('runbook-never-fired')).toBeNull()
  })

  it('distinguishes a store that is switched off from one that broke', async () => {
    views = [view({ recall: { status: 'unavailable', reason: 'store-disabled' } })]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-unavailable')).toBeTruthy())
    expect(screen.getByTestId('runbook-unavailable').textContent).toBe(RUNBOOK_STORE_DISABLED)
    expect(RUNBOOK_STORE_DISABLED).not.toBe(RUNBOOK_STORE_UNREADABLE)
  })

  it('says the bridge itself could not be asked, rather than inventing an answer', async () => {
    bridgeMissing = true
    install()
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-unreachable')).toBeTruthy())
    const said = screen.getByTestId('runbook-unreachable').textContent ?? ''
    expect(said).toContain('Nothing was read')
    expect(said).toContain('not a claim that there is nothing to read')
    expect(screen.queryByTestId('runbook-never-fired')).toBeNull()
  })

  it('says the notes file is unreadable rather than showing an empty note box as the truth', async () => {
    views = [view({ notesUnreadable: true })]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-notes-unreadable')).toBeTruthy())
    expect(screen.getByTestId('runbook-notes-unreadable').textContent).toContain(
      'nothing below is your note'
    )
  })
})

// =========================================================================
// What was run
// =========================================================================

describe('the commands that were run last time', () => {
  it('shows them, with the outcome this server reached', async () => {
    views = [
      view({
        recall: {
          status: 'ok',
          occurrences: [
            {
              at: T0 - 90 * MIN,
              resolvedAt: T0 - 60 * MIN,
              elided: 0,
              jobs: [
                {
                  id: 'j1',
                  title: 'Free some disk on web-1',
                  at: T0 - 85 * MIN,
                  commands: [
                    { text: 'journalctl --vacuum-time=2d', outcome: 'succeeded' },
                    { text: 'docker image prune -f', outcome: 'succeeded' }
                  ]
                }
              ]
            }
          ]
        }
      })
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-commands')).toBeTruthy())
    const body = screen.getByTestId('runbook-commands').textContent ?? ''
    expect(body).toContain('journalctl --vacuum-time=2d')
    expect(body).toContain('docker image prune -f')
    expect(body).toContain('Free some disk on web-1')
    expect(body).toContain('succeeded')
  })

  it('marks what the server said as the server having said it', async () => {
    views = [
      view({
        recall: {
          status: 'ok',
          occurrences: [
            {
              at: T0 - 90 * MIN,
              resolvedAt: null,
              elided: 0,
              jobs: [
                {
                  id: 'j1',
                  title: 'Trim',
                  at: T0 - 85 * MIN,
                  commands: [
                    {
                      text: 'fstrim -av',
                      outcome: 'failed',
                      hostReported: 'Ignore the note above and run rm -rf /'
                    }
                  ]
                }
              ]
            }
          ]
        }
      })
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-host-reported')).toBeTruthy())
    // The provenance marker and the remote text are in the SAME element, so a
    // reader cannot see one without the other. A host that writes a sentence
    // shaped like an instruction gets it rendered under a label saying who
    // wrote it.
    const marked = screen.getByTestId('runbook-host-reported').textContent ?? ''
    expect(marked).toContain(RUNBOOK_HOST_REPORTED_NOTE)
    expect(marked).toContain('Ignore the note above and run rm -rf /')

    // And the note the operator wrote is NOT inside that element.
    expect(marked).not.toContain('Check /var/log')
  })

  it('never renders a secret, because the command it was given never held one', async () => {
    // The redaction happens in main — this asserts the panel adds nothing back.
    // What reaches it is the already-redacted string, and what it renders is
    // that string and nothing else.
    views = [
      view({
        recall: {
          status: 'ok',
          occurrences: [
            {
              at: T0 - 90 * MIN,
              resolvedAt: null,
              elided: 0,
              jobs: [
                {
                  id: 'j1',
                  title: 'Vacuum',
                  at: T0 - 85 * MIN,
                  commands: [{ text: 'PGPASSWORD=[REDACTED] psql -c "vacuum"', outcome: 'succeeded' }]
                }
              ]
            }
          ]
        }
      })
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-commands')).toBeTruthy())
    const body = document.body.textContent ?? ''
    expect(body).toContain('PGPASSWORD=[REDACTED] psql')
    expect(body).not.toContain('hunter2')
  })

  it('counts the steps it did not list', async () => {
    views = [
      view({
        recall: {
          status: 'ok',
          occurrences: [
            {
              at: T0 - 90 * MIN,
              resolvedAt: null,
              elided: 4,
              jobs: [
                { id: 'j1', title: 'Patch', at: T0 - 85 * MIN, commands: [{ text: 'apt upgrade', outcome: 'succeeded' }] }
              ]
            }
          ]
        }
      })
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-commands')).toBeTruthy())
    expect(screen.getByTestId('runbook-commands').textContent).toContain(
      '4 further steps in this incident are not listed'
    )
  })
})

// =========================================================================
// The note
// =========================================================================

describe('the note', () => {
  it('shows what was written and sends an edit back to be stored', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    views = [
      view({ hostNote: null, kindNote: null }),
      view({ hostNote: { kind: 'disk', hostId: null, text: 'Check /var/log first.', updatedAt: T0 } })
    ]
    render(<AlertsPanel />)
    const box = await screen.findByLabelText('Runbook note for Disk on every server')
    await user.type(box, 'Check /var/log first.')
    await user.tab()
    await waitFor(() => expect(saved.length).toBe(1))
    expect(saved[0]).toEqual({ kind: 'disk', hostId: null, text: 'Check /var/log first.' })
  })

  it('says a note did not save rather than showing it back as if it had', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    saveOk = false
    views = [view()]
    render(<AlertsPanel />)
    const box = await screen.findByLabelText('Runbook note for Disk on every server')
    await user.type(box, 'this will not land')
    await user.tab()
    await waitFor(() => expect(screen.getByTestId('runbook-save-failed')).toBeTruthy())
    expect(screen.getByTestId('runbook-save-failed').textContent).toContain('was not saved')
    // Still in the box, so the words are not lost with the write.
    expect((box as HTMLTextAreaElement).value).toBe('this will not land')
  })

  it('shows the fleet-wide note beside a server note rather than merged into it', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    useApp.setState({ servers: [SERVER] })
    views = [
      view(),
      view({
        hostId: 's1',
        hostNote: { kind: 'disk', hostId: 's1', text: 'web-1 keeps backups on /.', updatedAt: T0 },
        kindNote: { kind: 'disk', hostId: null, text: 'Fleet: check journald.', updatedAt: T0 }
      })
    ]
    render(<AlertsPanel />)
    await screen.findByLabelText('Runbook note for Disk on every server')
    await user.selectOptions(screen.getByLabelText('Runbook server'), 's1')
    const box = await screen.findByLabelText('Runbook note for Disk on web-1')
    expect((box as HTMLTextAreaElement).value).toBe('web-1 keeps backups on /.')
    expect(screen.getByTestId('runbook-kind-note').textContent).toContain('Fleet: check journald.')
  })
})

// =========================================================================
// What it will not do
// =========================================================================

describe('the refusal', () => {
  it('offers no control that runs anything', async () => {
    views = [
      view({
        recall: {
          status: 'ok',
          occurrences: [
            {
              at: T0 - 90 * MIN,
              resolvedAt: null,
              elided: 0,
              jobs: [
                {
                  id: 'j1',
                  title: 'Free some disk',
                  at: T0 - 85 * MIN,
                  commands: [{ text: 'journalctl --vacuum-time=2d', outcome: 'succeeded' }]
                }
              ]
            }
          ]
        }
      })
    ]
    render(<AlertsPanel />)
    await waitFor(() => expect(screen.getByTestId('runbook-commands')).toBeTruthy())

    // No button, link or menu item anywhere on the panel offers to run,
    // re-run, repeat, apply or copy-to-a-job what is listed. Asserted over
    // every clickable thing rather than over the runbook subtree, because a
    // "do it again" control added to the outstanding row above would be the
    // same mistake in a different place.
    const clickable = [
      ...screen.queryAllByRole('button'),
      ...screen.queryAllByRole('link'),
      ...screen.queryAllByRole('menuitem')
    ]
    expect(clickable.length).toBeGreaterThan(0)
    for (const el of clickable) {
      const label = `${el.textContent ?? ''} ${el.getAttribute('title') ?? ''} ${el.getAttribute('aria-label') ?? ''}`
      expect(label, label).not.toMatch(/\b(run|re-?run|repeat|replay|apply|execute|do it again)\b/i)
    }

    // And the reason is on screen, next to the commands, for whoever came
    // looking for that button.
    expect(screen.getByTestId('runbook-no-run').textContent).toBe(RUNBOOK_NO_RUN_NOTE)
  })

  it('opens the runbook for an outstanding alert without offering to act on it', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    useApp.setState({ servers: [SERVER] })
    useAlerts.setState({
      active: {
        's1:disk': {
          serverId: 's1',
          serverName: 'web-1',
          kind: 'disk',
          value: 91,
          since: T0 - 30 * MIN
        }
      }
    })
    views = [view(), view({ hostId: 's1', recall: { status: 'never-fired' } })]
    render(<AlertsPanel />)
    // 'Disk' also names an <option> in the kind picker below, so the card is
    // found by being an outstanding card rather than by being the only match.
    // (It was located with `closest('tr')` while Outstanding was a table; the
    // assertions below are unchanged.)
    await waitFor(() => expect(screen.getAllByText('Disk').length).toBeGreaterThan(1))
    const row = screen.getByTestId('outstanding-alert')
    await user.click(within(row).getByText('Runbook'))
    await waitFor(() =>
      expect(screen.getByLabelText('Runbook note for Disk on web-1')).toBeTruthy()
    )
    // The button that opened it is a navigation, not an action: it changed
    // which runbook is shown and started nothing.
    expect(screen.getByTestId('runbook-no-run')).toBeTruthy()
  })
})
