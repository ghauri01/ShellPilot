// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { DriftPanel } from '../src/renderer/src/components/monitor/DriftPanel'
import type { DriftReading, HostDrift } from '../src/shared/drift'
import type { Server } from '../src/renderer/src/types'

// Configuration drift — roadmap item 25, the panel.
//
// These assert what an operator SEES, because everything this item can get
// wrong looks fine on screen: a host that could not be read sitting in the
// matching column, a difference a rule ate reported as "identical", and a
// secret from a watched file rendered into the page.

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

const reading = (over: Partial<DriftReading> = {}): DriftReading => ({
  watchId: 'sshd-config',
  status: 'ok',
  hash: 'h-same',
  normalisedHash: 'n-same',
  applied: [],
  ...over
})

const drift = (r: DriftReading): HostDrift => ({ at: 1_700_000_000_000, readings: [r] })

/** Stub `fleet.drift` with one reply per server id. */
function stub(replies: Record<string, { drift?: HostDrift; error?: string }>): void {
  stubBridge({
    fleet: {
      drift: async (serverId: string) => replies[serverId] ?? {},
      sampleNow: async () => ({})
    }
  })
}

// The panel opens on the first watch in the catalogue, which is sshd-config.
const SERVERS = [server('a', 'web-01'), server('b', 'web-02'), server('c', 'web-03')]

/** The verdict cell for one host: the row's second column. */
async function verdictFor(name: string): Promise<string> {
  const cell = await screen.findByText(name)
  const row = cell.closest('tr') as HTMLTableRowElement
  return (row.cells[1].textContent ?? '').trim()
}

describe('a server that could not be read', () => {
  it('is never shown as matching', async () => {
    // The failure this codebase has been bitten by repeatedly. A denied read is
    // its own word, in its own colour, with the status's own explanation beside
    // it — and it is not in the "matches" count.
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading()) },
      c: { drift: drift(reading({ status: 'denied', hash: undefined, normalisedHash: undefined })) }
    })
    render(<DriftPanel servers={SERVERS} />)

    expect(await verdictFor('web-03')).toBe('could not be read')
    expect(await verdictFor('web-02')).toBe('identical')
    // The headline counts two, not three.
    expect(await screen.findByText(/2 matches/)).toBeTruthy()
    // And the reason is on the row, in the words the status vocabulary uses.
    expect(screen.getByText(/not allowed to read it/)).toBeTruthy()
  })

  it('says so in the coverage line rather than leaving a silent gap', async () => {
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading({ status: 'denied', hash: undefined, normalisedHash: undefined })) },
      c: {}
    })
    render(<DriftPanel servers={SERVERS} />)
    const line = await screen.findByTestId('drift-coverage')
    expect(line.textContent).toContain('web-02 would not let this account read it')
    expect(line.textContent).toContain('web-03 have not been collected yet')
  })

  it('is not silently replaced as a baseline when it was the one pinned', async () => {
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading()) },
      c: { drift: drift(reading({ status: 'denied', hash: undefined, normalisedHash: undefined })) }
    })
    render(<DriftPanel servers={SERVERS} />)
    await screen.findByText('web-03')
    // Pin the unreadable host.
    const row = (await screen.findByText('web-03')).closest('tr') as HTMLTableRowElement
    await userEvent.click(row.cells[0].querySelector('button') as HTMLButtonElement)
    await waitFor(() => expect(screen.getByTestId('drift-no-baseline')).toBeTruthy())
    expect(screen.getByTestId('drift-no-baseline').textContent).toContain(
      'has NOT been substituted for it'
    )
  })
})

describe('a difference a rule ate', () => {
  it('is reported as ignored, never as identical', async () => {
    // The verdict the whole item turns on.
    stub({
      a: { drift: drift(reading({ hash: 'h-a', applied: ['comments'] })) },
      b: { drift: drift(reading({ hash: 'h-b', applied: ['trailing-space'] })) },
      c: { drift: drift(reading({ hash: 'h-a', applied: ['comments'] })) }
    })
    render(<DriftPanel servers={SERVERS} />)
    expect(await verdictFor('web-02')).toBe('differs in ignored ways')
    // web-03 has the same bytes as the baseline, so it really is identical, and
    // the two answers are not the same word.
    expect(await verdictFor('web-03')).toBe('identical')
  })

  it('names the rules that were doing the work', async () => {
    stub({
      a: { drift: drift(reading({ hash: 'h-a', applied: ['comments'] })) },
      b: { drift: drift(reading({ hash: 'h-b', applied: ['trailing-space'] })) }
    })
    render(<DriftPanel servers={[SERVERS[0], SERVERS[1]]} />)
    await screen.findByText('web-02')
    expect(
      screen.getByText(/The bytes differ. After whole-line comments, trailing whitespace they match./)
    ).toBeTruthy()
  })

  it('shows every rule the file is compared under, with a worked example', async () => {
    // An operator disagreeing with a verdict has exactly this to go on. Hidden
    // heuristics are how the feature stops being trusted.
    stub({ a: { drift: drift(reading()) } })
    render(<DriftPanel servers={[SERVERS[0]]} />)
    await userEvent.click(await screen.findByText(/rules this is compared under/))
    const rules = screen.getByTestId('drift-rules')
    expect(rules.textContent).toContain('Whole-line comments')
    expect(rules.textContent).toContain('# managed by puppet')
    // And the reason THIS file gets THIS rule set.
    expect(rules.textContent).toContain('the first occurrence of a keyword wins')
    // sshd_config is not sorted, so the loudest rule must not be listed for it.
    expect(rules.textContent).not.toContain('Line order')
  })
})

describe('a server that does not have the file', () => {
  it('gets its own answer rather than being called divergent or unread', async () => {
    // "All twelve web servers have this nginx.conf. Three do not."
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading()) },
      c: { drift: drift(reading({ status: 'absent', hash: undefined, normalisedHash: undefined })) }
    })
    render(<DriftPanel servers={SERVERS} />)
    expect(await verdictFor('web-03')).toBe('not on this server')
    expect(await screen.findByText(/1 do not have the file/)).toBeTruthy()
  })
})

describe('secrets', () => {
  it('never renders a preview, so nothing from a watched file reaches the page', async () => {
    // The panel compares hashes and shows verdicts. The bounded redacted
    // preview exists for a side-by-side that is not built yet, and until it is,
    // no line of anybody's configuration is drawn here at all.
    stub({
      a: { drift: drift(reading({ preview: 'DB_PASSWORD=[REDACTED]\nPort 22\n' })) },
      b: { drift: drift(reading({ preview: 'Port 22\n' })) }
    })
    render(<DriftPanel servers={[SERVERS[0], SERVERS[1]]} />)
    await screen.findByText('web-01')
    expect(document.body.textContent).not.toContain('Port 22')
    expect(document.body.textContent).not.toContain('DB_PASSWORD')
  })

  it('says when redaction happened, because it hides differences too', async () => {
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading({ redacted: true })) }
    })
    render(<DriftPanel servers={[SERVERS[0], SERVERS[1]]} />)
    // Twice, and deliberately: once on the row it applies to, and once in the
    // coverage sentence that names every host it applied to. Someone reading
    // one row and someone reading the summary both need to know.
    expect(await verdictFor('web-02')).toBe('identical')
    const said = await screen.findAllByText(/a difference inside it is invisible here/)
    expect(said).toHaveLength(2)
    expect((await screen.findByTestId('drift-coverage')).textContent).toContain(
      'secret-shaped text was replaced before comparing on web-02'
    )
  })
})

describe('the baseline', () => {
  it('says when it picked the majority rather than being told', async () => {
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading()) },
      c: { drift: drift(reading({ hash: 'h-x', normalisedHash: 'n-x' })) }
    })
    render(<DriftPanel servers={SERVERS} />)
    const note = await screen.findByTestId('drift-chosen-baseline')
    expect(note.textContent).toContain('a server that was fixed first looks exactly like a server that drifted')
    expect(await verdictFor('web-03')).toBe('differs')
  })

  it('stops saying so once a server is pinned', async () => {
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading({ hash: 'h-x', normalisedHash: 'n-x' })) }
    })
    render(<DriftPanel servers={[SERVERS[0], SERVERS[1]]} />)
    const row = (await screen.findByText('web-02')).closest('tr') as HTMLTableRowElement
    await userEvent.click(row.cells[0].querySelector('button') as HTMLButtonElement)
    await waitFor(() => expect(screen.queryByTestId('drift-chosen-baseline')).toBeNull())
    expect(await verdictFor('web-01')).toBe('differs')
  })
})

describe('what the panel refuses', () => {
  it('states the refusal to push a file where somebody would look for the button', async () => {
    stub({ a: { drift: drift(reading()) } })
    render(<DriftPanel servers={[SERVERS[0]]} />)
    const refusal = await screen.findByTestId('drift-no-push')
    expect(refusal.textContent).toContain('never writes a file to a server')
    expect(refusal.textContent).toContain('that is a job')
  })

  it('offers no control that could change a server', async () => {
    stub({
      a: { drift: drift(reading()) },
      b: { drift: drift(reading({ hash: 'h-x', normalisedHash: 'n-x' })) }
    })
    render(<DriftPanel servers={[SERVERS[0], SERVERS[1]]} />)
    await screen.findByText('web-02')
    // Read off the buttons rather than the source: the refusal is worth nothing
    // if a "Make them match" arrives beside it.
    for (const b of screen.getAllByRole('button')) {
      expect(b.textContent ?? '').not.toMatch(/push|apply|fix|sync|enforce|make them match/i)
    }
  })
})

describe('before anything has been collected', () => {
  it('says nothing has been read, rather than showing an empty comparison', async () => {
    // A host nobody has looked at is not a host whose configuration matches.
    stub({})
    render(<DriftPanel servers={SERVERS} />)
    expect(await screen.findByText(/No configuration files have been read yet/)).toBeTruthy()
    expect(screen.queryByText('identical')).toBeNull()
  })
})
