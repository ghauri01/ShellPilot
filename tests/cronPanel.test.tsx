// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { CronPanel } from '../src/renderer/src/components/monitor/CronPanel'
import type { CronEntry, CronSourceReport } from '../src/shared/cron'
import { buildCronWriteCommand } from '../src/shared/cron'
import type { Server } from '../src/renderer/src/types'

// Rendered rather than read, for the reason the compose panel gives: the rules
// this panel keeps are not visible in a source regex. A component can import
// `cronEditRefusal` and never render it; it can offer an edit button on a host
// whose crontab was only half read, and no single line looks wrong.

const SERVER: Server = {
  id: 'srv-1',
  workspaceId: 'ws-default',
  folderId: null,
  name: 'db-01',
  host: 'db-01.example.internal',
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

const ok = (id: CronSourceReport['id']): CronSourceReport => ({ id, label: id, status: 'ok' })

const userJob: CronEntry = {
  kind: 'user-crontab',
  origin: 'crontab -l',
  schedule: '0 3 * * *',
  description: 'at 03:00 every day',
  user: null,
  command: '/usr/bin/backup --all',
  line: '0 3 * * * /usr/bin/backup --all'
}

const crondJob: CronEntry = {
  kind: 'cron.d',
  origin: '/etc/cron.d/certbot',
  schedule: '0 */12 * * *',
  description: null,
  user: 'root',
  command: 'certbot -q renew',
  line: '0 */12 * * * root certbot -q renew'
}

const rows = (over: Partial<Record<string, unknown>> = {}): unknown[] => [
  {
    serverId: SERVER.id,
    serverName: SERVER.name,
    entries: [userJob, crondJob],
    unparsed: 0,
    sources: [ok('user-crontab'), ok('system-crontab'), ok('cron.d'), ok('other-crontabs'), ok('systemd-timers')],
    ...over
  }
]

const TOKEN = '20260903T101112Z-a1b2c3'
const COMMAND = buildCronWriteCommand({
  before: '0 3 * * * /usr/bin/backup --all\n',
  after: '0 3 * * * /usr/bin/backup --nightly\n',
  token: TOKEN
})

const bridge = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  cron: {
    collect: vi.fn(async () => rows()),
    planEdit: vi.fn(async () => ({
      ok: true,
      before: '0 3 * * * /usr/bin/backup --all\n',
      after: '0 3 * * * /usr/bin/backup --nightly\n',
      summary: 'change `0 3 * * * /usr/bin/backup --all` to `0 3 * * * /usr/bin/backup --nightly`',
      addedFinalNewline: false,
      token: TOKEN,
      command: COMMAND
    })),
    write: vi.fn(async () => ({
      ok: true,
      serverId: SERVER.id,
      serverName: SERVER.name,
      outcome: 'written',
      backupPath: '/home/ops/.shellpilot-crontab-20260903T101112Z-a1b2c3.bak',
      detail: 'the crontab was replaced and read back identical'
    })),
    ...over
  }
})

const readSchedules = async (): Promise<void> => {
  await userEvent.click(screen.getByRole('button', { name: /read schedules/i }))
  await screen.findByText(/db-01/)
}

describe('the cron panel’s edit half', () => {
  it('offers nothing to edit when this build’s main process has no edit channels', async () => {
    // The precedent is the `sources` field: a main process that has not been
    // taught something sends nothing, and a button that silently does nothing
    // is worse than no button.
    stubBridge({ cron: { collect: vi.fn(async () => rows()) } })
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    expect(screen.queryByRole('button', { name: /add job/i })).toBeNull()
    expect(screen.queryByTitle('Change this job')).toBeNull()
  })

  it('says why a /etc/cron.d job cannot be edited instead of leaving the row bare', async () => {
    stubBridge(bridge())
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    const label = screen.getByText('not editable')
    expect(label.getAttribute('title')).toContain('/etc/cron.d')
  })

  it('will not edit a host whose own crontab was only partly read, and says so', async () => {
    stubBridge(
      bridge({
        collect: vi.fn(async () =>
          rows({
            sources: [
              { id: 'user-crontab', label: 'crontab -l', status: 'partial', detail: 'read 1 of 2' },
              ok('system-crontab'),
              ok('cron.d'),
              ok('other-crontabs'),
              ok('systemd-timers')
            ]
          })
        )
      })
    )
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    expect(screen.getByText(/was not read in full, so nothing here can be edited/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /add job/i })).toBeNull()
    expect(screen.queryByTitle('Change this job')).toBeNull()
  })

  it('refuses a schedule cron would not take, before anything reaches a host', async () => {
    const stub = bridge()
    stubBridge(stub)
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    const schedule = screen.getByDisplayValue('0 3 * * *')
    await userEvent.clear(schedule)
    await userEvent.type(schedule, '@every_minute')
    expect(screen.getByText(/not a schedule cron accepts/i)).toBeTruthy()
    expect((screen.getByRole('button', { name: /review change/i }) as HTMLButtonElement).disabled).toBe(true)
    expect((stub.cron as { planEdit: ReturnType<typeof vi.fn> }).planEdit).not.toHaveBeenCalled()
  })

  it('shows the same plain-English reading of a schedule the list shows', async () => {
    stubBridge(bridge())
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    expect(screen.getAllByText('at 03:00 every day').length).toBeGreaterThan(1)
  })

  it('points at the job by its line, never by its position in the list', async () => {
    const stub = bridge()
    stubBridge(stub)
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    const command = screen.getByDisplayValue('/usr/bin/backup --all')
    await userEvent.clear(command)
    await userEvent.type(command, '/usr/bin/backup --nightly')
    await userEvent.click(screen.getByRole('button', { name: /review change/i }))
    await waitFor(() =>
      expect((stub.cron as { planEdit: ReturnType<typeof vi.fn> }).planEdit).toHaveBeenCalled()
    )
    const [, req] = (stub.cron as { planEdit: ReturnType<typeof vi.fn> }).planEdit.mock.calls[0]
    expect(req).toEqual({
      op: 'update',
      line: '0 3 * * * /usr/bin/backup --all',
      schedule: '0 3 * * *',
      command: '/usr/bin/backup --nightly'
    })
  })

  it('shows main’s own summary of the change and will not apply it unconfirmed', async () => {
    const stub = bridge()
    stubBridge(stub)
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    await userEvent.click(screen.getByRole('button', { name: /review change/i }))
    await screen.findByText(/change `0 3 \* \* \* \/usr\/bin\/backup --all`/)
    // The command a cron write builds classifies destructive, so the panel
    // demands the word typed. Until it is, Apply does nothing.
    const apply = await screen.findByRole('button', { name: /apply to db-01/i })
    expect((apply as HTMLButtonElement).disabled).toBe(true)
    expect((stub.cron as { write: ReturnType<typeof vi.fn> }).write).not.toHaveBeenCalled()
  })

  it('sends the bytes main worked out, with an approval that carries the typed word', async () => {
    const stub = bridge()
    stubBridge(stub)
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    await userEvent.click(screen.getByRole('button', { name: /review change/i }))
    await userEvent.type(await screen.findByPlaceholderText('Type RUN'), 'RUN')
    await userEvent.click(screen.getByRole('button', { name: /apply to db-01/i }))
    await waitFor(() => expect((stub.cron as { write: ReturnType<typeof vi.fn> }).write).toHaveBeenCalled())
    const [target, req] = (stub.cron as { write: ReturnType<typeof vi.fn> }).write.mock.calls[0]
    expect(target.serverId).toBe(SERVER.id)
    expect(req.before).toBe('0 3 * * * /usr/bin/backup --all\n')
    expect(req.after).toBe('0 3 * * * /usr/bin/backup --nightly\n')
    expect(req.token).toBe(TOKEN)
    // The record is what a human was asked and what they answered. The command
    // in it is main's, so an edited command is a command that does not match.
    expect(req.approval.commands).toEqual([COMMAND])
    expect(req.approval.phrase).toBe('RUN')
    expect(req.approval.targets).toEqual([{ serverId: SERVER.id, serverName: SERVER.name }])
  })

  it('tells the operator where the previous crontab is, and re-reads the host', async () => {
    const stub = bridge()
    stubBridge(stub)
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    await userEvent.click(screen.getByRole('button', { name: /review change/i }))
    await userEvent.type(await screen.findByPlaceholderText('Type RUN'), 'RUN')
    await userEvent.click(screen.getByRole('button', { name: /apply to db-01/i }))
    await screen.findByText(/\.shellpilot-crontab-20260903T101112Z-a1b2c3\.bak/)
    // Read again rather than patched from what we sent: the host is the only
    // thing that knows what its crontab says now.
    expect((stub.cron as { collect: ReturnType<typeof vi.fn> }).collect).toHaveBeenCalledTimes(2)
  })

  it('shows main’s refusal rather than a generic failure', async () => {
    stubBridge(
      bridge({
        planEdit: vi.fn(async () => ({
          ok: false,
          reason: 'this crontab has 1 line ShellPilot could not parse, starting with `wat`.'
        }))
      })
    )
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    await userEvent.click(screen.getByRole('button', { name: /review change/i }))
    await screen.findByText(/could not parse, starting with `wat`/)
    expect(screen.queryByRole('button', { name: /apply to/i })).toBeNull()
  })

  it('warns when a missing final newline is about to be added for it', async () => {
    stubBridge(
      bridge({
        planEdit: vi.fn(async () => ({
          ok: true,
          before: '0 3 * * * /a',
          after: '0 3 * * * /a\n@hourly /b\n',
          summary: 'add `@hourly /b`',
          addedFinalNewline: true,
          token: TOKEN,
          command: COMMAND
        }))
      })
    )
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByRole('button', { name: /add job/i }))
    await userEvent.type(screen.getByPlaceholderText('/usr/bin/backup --all'), '/b')
    await userEvent.click(screen.getByRole('button', { name: /review change/i }))
    await screen.findByText(/glued onto the end of the previous one/i)
  })

  it('reports a write that did not land, in the host’s words', async () => {
    stubBridge(
      bridge({
        write: vi.fn(async () => ({
          ok: false,
          serverId: SERVER.id,
          serverName: SERVER.name,
          outcome: 'changed',
          detail: 'the crontab on this host is not the one this change was planned against',
          backupPath: undefined
        }))
      })
    )
    render(<CronPanel servers={[SERVER]} />)
    await readSchedules()
    await userEvent.click(screen.getByTitle('Change this job'))
    await userEvent.click(screen.getByRole('button', { name: /review change/i }))
    await userEvent.type(await screen.findByPlaceholderText('Type RUN'), 'RUN')
    await userEvent.click(screen.getByRole('button', { name: /apply to db-01/i }))
    await screen.findByText(/is not the one this change was planned against/)
  })
})
