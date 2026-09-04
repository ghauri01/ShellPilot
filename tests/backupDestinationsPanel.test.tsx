// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { BackupDestinations } from '../src/renderer/src/components/settings/BackupDestinations'
import { useVault } from '../src/renderer/src/store/vault'
import type {
  BackupDestination,
  BackupRunReport,
  BackupTargetsFile
} from '../src/shared/backup'

// Rendered rather than grepped. The rules this panel has to keep are not
// visible in a source regex: a component can import the exposure text and
// never render it, and it can report a failed run in language that reads like
// a success without any one line looking wrong.

const LOCAL: BackupDestination = {
  id: 'd-local',
  name: 'NAS folder',
  kind: 'local',
  directory: '/Volumes/nas/shellpilot',
  keep: 3,
  everyHours: 6,
  restoreTest: true,
  passphraseVaultEntryId: 'v-pw'
}

function targets(over: Partial<BackupTargetsFile> = {}): BackupTargetsFile {
  return { version: 1, destinations: [LOCAL], lastRunAt: {}, lastReport: {}, ...over }
}

function bridge(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    backup: {
      destinations: vi.fn(async () => targets()),
      saveDestinations: vi.fn(async (d: BackupDestination[]) => targets({ destinations: d })),
      runDestination: vi.fn(),
      listRemote: vi.fn(async () => ({ ok: true, generations: [] })),
      inspectRemote: vi.fn(),
      discardStaged: vi.fn(),
      chooseDirectory: vi.fn(async () => null),
      import: vi.fn(),
      relaunch: vi.fn(),
      ...over
    }
  }
}

const failedRun: BackupRunReport = {
  ok: false,
  destinationId: 'd-local',
  destinationName: 'NAS folder',
  destinationKind: 'local',
  startedAt: '2024-05-06T07:08:09.000Z',
  finishedAt: '2024-05-06T07:08:12.000Z',
  name: 'shellpilot-20240506T070809Z.spbackup',
  verified: false,
  restoreTested: false,
  removed: [],
  failedStage: 'verify',
  error: 'Permission denied'
}

const goodRun: BackupRunReport = {
  ...failedRun,
  ok: true,
  verified: true,
  restoreTested: true,
  failedStage: undefined,
  error: undefined,
  removed: ['shellpilot-20240101T000000Z.spbackup']
}

describe('the destination list', () => {
  it('states that a backup is the whole vault, before any destination exists', async () => {
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ destinations: [] })) }))
    render(<BackupDestinations />)

    await screen.findByText('A backup is your whole vault, wherever you send it')
    expect(
      screen.getByText(/contains your stored credentials, your vault and your trusted host keys/)
    ).toBeTruthy()
  })

  it('reports a failed run by naming the stage and the reason', async () => {
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ lastReport: { 'd-local': failedRun } })) }))
    render(<BackupDestinations />)

    await screen.findByText('Failed while reading the bundle back: Permission denied')
    // And nowhere does it claim the file was read back and matched. The
    // panel's own description of what a run does mentions reading back; the
    // card's verdict must not.
    expect(screen.queryByText(/— read back off the destination and/)).toBe(null)
    expect(screen.queryByText(/test-restored/)).toBe(null)
  })

  it('says what a successful run actually proved, not merely that it ran', async () => {
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ lastReport: { 'd-local': goodRun } })) }))
    render(<BackupDestinations />)

    await screen.findByText(
      'shellpilot-20240506T070809Z.spbackup — read back off the destination and test-restored, 1 older removed'
    )
  })

  it('will not run a backup on a passphrase too short to protect it', async () => {
    stubBridge(bridge())
    render(<BackupDestinations />)

    const field = await screen.findByPlaceholderText('Backup passphrase (min 8)')
    const button = screen.getByRole('button', { name: /Back up now/ })
    expect((button as HTMLButtonElement).disabled).toBe(true)

    await userEvent.type(field, 'short')
    expect((button as HTMLButtonElement).disabled).toBe(true)

    await userEvent.type(field, '-enough')
    expect((button as HTMLButtonElement).disabled).toBe(false)
  })

  it('passes the typed passphrase to main and never keeps it after a success', async () => {
    const runDestination = vi.fn(async () => goodRun)
    stubBridge(bridge({ runDestination }))
    render(<BackupDestinations />)

    const field = await screen.findByPlaceholderText('Backup passphrase (min 8)')
    await userEvent.type(field, 'a-real-passphrase')
    await userEvent.click(screen.getByRole('button', { name: /Back up now/ }))

    await waitFor(() => expect(runDestination).toHaveBeenCalledWith('d-local', 'a-real-passphrase'))
    await waitFor(() => expect((field as HTMLInputElement).value).toBe(''))
  })

  it('shows the destination it could not read, rather than an empty backup list', async () => {
    stubBridge(
      bridge({
        listRemote: vi.fn(async () => ({ ok: false, error: 'ENOENT: no such file or directory' }))
      })
    )
    render(<BackupDestinations />)

    await userEvent.click(await screen.findByRole('button', { name: /Restore from here/ }))

    await screen.findByText('ENOENT: no such file or directory')
    expect(screen.queryByText('No ShellPilot backups at this destination yet.')).toBe(null)
  })

  it('inspects a remote backup before offering to restore it', async () => {
    const inspectRemote = vi.fn(async () => ({
      ok: true,
      path: '/userdata/staged-shellpilot-20240506T070809Z.spbackup',
      summary: {
        createdAt: '2024-05-06T07:08:09.000Z',
        app: '0.11.0',
        servers: 12,
        databases: 3,
        workspaces: 2,
        secrets: 40,
        hasVault: true
      }
    }))
    stubBridge(
      bridge({
        inspectRemote,
        listRemote: vi.fn(async () => ({
          ok: true,
          generations: [
            { name: 'shellpilot-20240506T070809Z.spbackup', size: 4096, modified: 1714979289000 }
          ]
        }))
      })
    )
    render(<BackupDestinations />)

    await userEvent.type(
      await screen.findByPlaceholderText('Backup passphrase (min 8)'),
      'a-real-passphrase'
    )
    await userEvent.click(screen.getByRole('button', { name: /Restore from here/ }))
    await userEvent.click(await screen.findByRole('button', { name: 'Open' }))

    await waitFor(() =>
      expect(inspectRemote).toHaveBeenCalledWith(
        'd-local',
        'shellpilot-20240506T070809Z.spbackup',
        'a-real-passphrase'
      )
    )
    // Nothing is replaced until the contents have been shown and confirmed.
    await screen.findByText('Replace current data?')
    expect(screen.getByText(/12 servers/)).toBeTruthy()
  })

  it('refuses a corrupt remote bundle instead of offering to restore it', async () => {
    stubBridge(
      bridge({
        inspectRemote: vi.fn(async () => ({
          ok: false,
          error: 'The bundle at the destination did not decrypt — Unsupported state or unable to authenticate data'
        })),
        listRemote: vi.fn(async () => ({
          ok: true,
          generations: [
            { name: 'shellpilot-20240506T070809Z.spbackup', size: 4096, modified: 1714979289000 }
          ]
        }))
      })
    )
    render(<BackupDestinations />)

    await userEvent.type(
      await screen.findByPlaceholderText('Backup passphrase (min 8)'),
      'a-real-passphrase'
    )
    await userEvent.click(screen.getByRole('button', { name: /Restore from here/ }))
    await userEvent.click(await screen.findByRole('button', { name: 'Open' }))

    await screen.findByText(/did not decrypt/)
    expect(screen.queryByText('Replace current data?')).toBe(null)
  })
})

describe('choosing a destination', () => {
  it('states what lands in an S3 bucket at the moment the bucket is being named', async () => {
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ destinations: [] })) }))
    render(<BackupDestinations />)

    await userEvent.click(await screen.findByRole('button', { name: /S3-compatible storage/ }))

    // The sentence is beside the endpoint field, not in a footnote further
    // down the page — the decision is made here.
    await screen.findByPlaceholderText('Endpoint, e.g. https://s3.eu-west-1.amazonaws.com')
    expect(
      screen.getByText(
        /A bucket that is public, or whose keys leak, hands over the whole file/
      )
    ).toBeTruthy()
  })

  it('states what lands in a local folder, including that a synced folder copies it onward', async () => {
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ destinations: [] })) }))
    render(<BackupDestinations />)

    await userEvent.click(await screen.findByRole('button', { name: /Local directory/ }))
    expect(screen.getByText(/A synced folder \(Dropbox, OneDrive, iCloud\) copies it onward/)).toBeTruthy()
  })

  it('will not save an S3 destination whose secret key has nowhere safe to live', async () => {
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ destinations: [] })) }))
    render(<BackupDestinations />)

    await userEvent.click(await screen.findByRole('button', { name: /S3-compatible storage/ }))
    await userEvent.type(screen.getByPlaceholderText('Name this destination'), 'Off-site')
    await userEvent.type(
      screen.getByPlaceholderText('Endpoint, e.g. https://s3.eu-west-1.amazonaws.com'),
      'https://s3.eu-west-1.amazonaws.com'
    )
    await userEvent.type(screen.getByPlaceholderText('Region'), 'eu-west-1')
    await userEvent.type(screen.getByPlaceholderText('Bucket'), 'estate-backups')

    const save = screen.getByRole('button', { name: 'Save destination' })
    expect((save as HTMLButtonElement).disabled).toBe(true)
    expect(
      screen.getByText(
        'Choose the vault entry holding the access key — the secret key cannot be stored in settings, because settings travel inside every backup written here.'
      )
    ).toBeTruthy()
  })

  it('lets an S3 destination be saved once its key is a vault entry', async () => {
    useVault.setState({
      unlocked: true,
      entries: [
        {
          id: 'v-s3',
          name: 'Backup bucket key',
          kind: 'key',
          url: '',
          username: '',
          password: '',
          notes: '',
          tags: [],
          fields: [],
          createdAt: '2024-01-01T00:00:00.000Z',
          updatedAt: '2024-01-01T00:00:00.000Z'
        }
      ]
    })
    const saveDestinations = vi.fn(async (d: BackupDestination[]) => targets({ destinations: d }))
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ destinations: [] })), saveDestinations }))
    render(<BackupDestinations />)

    await userEvent.click(await screen.findByRole('button', { name: /S3-compatible storage/ }))
    await userEvent.type(screen.getByPlaceholderText('Name this destination'), 'Off-site')
    await userEvent.type(
      screen.getByPlaceholderText('Endpoint, e.g. https://s3.eu-west-1.amazonaws.com'),
      'https://s3.eu-west-1.amazonaws.com'
    )
    await userEvent.type(screen.getByPlaceholderText('Region'), 'eu-west-1')
    await userEvent.type(screen.getByPlaceholderText('Bucket'), 'estate-backups')
    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: '' }),
      'v-s3'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Save destination' }))

    await waitFor(() => expect(saveDestinations).toHaveBeenCalled())
    const saved = saveDestinations.mock.calls[0][0][0]
    expect(saved.kind).toBe('s3')
    expect(saved).toMatchObject({ vaultEntryId: 'v-s3', bucket: 'estate-backups' })
    // The secret itself never came through this component.
    expect(JSON.stringify(saved)).not.toContain('secretAccessKey')
  })

  it('asks for a vault entry as soon as a schedule is set, and says why', async () => {
    stubBridge(bridge({ destinations: vi.fn(async () => targets({ destinations: [] })) }))
    render(<BackupDestinations />)

    await userEvent.click(await screen.findByRole('button', { name: /Local directory/ }))
    await userEvent.type(screen.getByPlaceholderText('Name this destination'), 'NAS')
    await userEvent.type(screen.getByPlaceholderText('Folder to write backups into'), '/Volumes/nas')

    const save = screen.getByRole('button', { name: 'Save destination' })
    expect((save as HTMLButtonElement).disabled).toBe(false)

    const hours = screen.getByRole('spinbutton', { name: /Run every/ })
    await userEvent.clear(hours)
    await userEvent.type(hours, '6')

    expect((save as HTMLButtonElement).disabled).toBe(true)
    expect(
      screen.getByText(
        'A scheduled run has nobody to type a passphrase, so it needs a vault entry holding one.'
      )
    ).toBeTruthy()
    expect(screen.getByText(/only happen while the vault is unlocked/)).toBeTruthy()
  })
})

describe('database dumps', () => {
  const withDbs = (over: Record<string, unknown> = {}): Record<string, unknown> =>
    bridge({
      dumpableDatabases: vi.fn(async () => [
        { id: 'db-orders', name: 'orders-prod', engine: 'postgres' as const }
      ]),
      ...over
    })

  it('says a dump is not encrypted, right where the button is', async () => {
    stubBridge(withDbs())
    render(<BackupDestinations />)

    await screen.findByRole('button', { name: /Dump now/ })
    expect(
      screen.getByText(
        /A dump is plain SQL, written alongside the backups and encrypted by nothing/
      )
    ).toBeTruthy()
  })

  it('reports what a dump wrote, in bytes it read back', async () => {
    stubBridge(
      withDbs({
        dumpDatabase: vi.fn(async () => ({
          ok: true,
          destinationId: 'd-local',
          destinationName: 'NAS folder',
          name: 'shellpilot-dump-orders-20240506T070809Z.sql',
          bytes: 81920,
          verified: true,
          startedAt: '',
          finishedAt: ''
        }))
      })
    )
    render(<BackupDestinations />)

    await userEvent.selectOptions(
      await screen.findByRole('combobox'),
      'db-orders'
    )
    await userEvent.click(screen.getByRole('button', { name: /Dump now/ }))

    await screen.findByText(
      'shellpilot-dump-orders-20240506T070809Z.sql written and read back (81920 bytes).'
    )
  })

  it('says nothing was written when the dump failed', async () => {
    stubBridge(
      withDbs({
        dumpDatabase: vi.fn(async () => ({
          ok: false,
          destinationId: 'd-local',
          destinationName: 'NAS folder',
          verified: false,
          error: 'pg_dump exited cleanly but produced no output.',
          startedAt: '',
          finishedAt: ''
        }))
      })
    )
    render(<BackupDestinations />)

    await userEvent.selectOptions(await screen.findByRole('combobox'), 'db-orders')
    await userEvent.click(screen.getByRole('button', { name: /Dump now/ }))

    await screen.findByText(
      'Nothing was written: pg_dump exited cleanly but produced no output.'
    )
  })
})

describe('when the destinations file cannot be read', () => {
  it('says so, rather than showing an empty list that looks deliberate', async () => {
    stubBridge(
      bridge({
        destinations: vi.fn(async () =>
          targets({
            destinations: [],
            corrupt:
              'shellpilot-backup-targets.json could not be read (Unexpected end of JSON input), so no destination is configured and nothing is being backed up on a schedule.'
          })
        )
      })
    )
    render(<BackupDestinations />)

    await screen.findByText('Your destinations could not be read')
    expect(screen.getByText(/nothing is being backed up on a schedule/)).toBeTruthy()
    // The reassuring reading of an empty list must not be the only thing on
    // screen.
    expect(screen.getByText(/moves the unreadable file aside/)).toBeTruthy()
  })
})
