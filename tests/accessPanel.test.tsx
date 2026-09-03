// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { AccessPanel } from '../src/renderer/src/components/monitor/AccessPanel'
import {
  ACCESS_STATUS_MARKER,
  parseAccessCollection,
  type HostAccess,
  type Sha256
} from '../src/shared/access'
import type { Server } from '../src/renderer/src/types'

// Fleet keys and access — roadmap item 23, renderer half.
//
// Every test here is about one thing: a host whose authorized_keys could not be
// read must never render as a host with no keys, and a count drawn over part of
// the estate must never render as an answer about the estate.
//
// src/shared/access.ts goes to real trouble to keep `denied`, `absent`,
// `no-tool`, `unsupported` and "never collected" apart on the way in. All of it
// is thrown away by one `?? 0` in a renderer, and until this file there was
// nothing that could notice.

const sha256: Sha256 = (data) => new Uint8Array(createHash('sha256').update(data).digest())

const ED25519 = 'AAAAC3NzaC1lZDI1NTE5AAAAIJp0kFqDkGDMEnCH7mFY3sBRb+tSVEyKvJhLhZ+SHDdw'
const ED25519_FP = 'SHA256:wVlk8sEGn2qqP1yFjdkoYGu+eWPmKJ/koiL8zATTjxI'

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

const OK_STATUS = [
  'accounts ok -',
  'sshd-config ok - /etc/ssh/sshd_config',
  'account-status ok -',
  'sudoers ok -',
  'last-login ok - lastlog'
]

/**
 * Access as the PARSER produces it, from collector-shaped records.
 *
 * Hand-building a HostAccess would let a test assert a shape the collector can
 * never emit — and worse, would keep passing if the derivation of
 * `authorized-keys` or `certain` were deleted outright. Everything here goes
 * through the real parser.
 */
function collected(body: string[], status: string[] = OK_STATUS): HostAccess {
  return parseAccessCollection([...body, ACCESS_STATUS_MARKER, ...status].join('\n'), {
    sha256,
    now: 1_800_000_000_000
  })
}

const complete = (): HostAccess =>
  collected([
    'V tz +0000',
    'U 1 uid 1000',
    'U 1 keys ok -',
    'U 1 name ops',
    `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`
  ])

/** One account read, one denied. The host answered; the answer is partial. */
const partial = (): HostAccess =>
  collected([
    'V tz +0000',
    'U 1 keys ok -',
    'U 1 name ops',
    `K 1 1 60 ssh-ed25519 ${ED25519} ops@laptop`,
    'U 2 keys denied -',
    'U 2 name deploy'
  ])

type Entry = { access?: HostAccess; at?: number; error?: string; errorAt?: number }

function mount(servers: Server[], byId: Record<string, Entry>): void {
  stubBridge({
    fleet: {
      access: async (id: string) => byId[id] ?? { intervalMs: 3_600_000 },
      sampleNow: async () => undefined
    }
  })
  render(<AccessPanel servers={servers} />)
}

describe('a host that could not be read', () => {
  it('is named, excluded, and explicitly not called a host with no keys', async () => {
    // The sentence this panel exists to print. Without it, a failed probe
    // renders as a host that contributed nothing to the totals — which reads
    // as a host that trusts nobody.
    mount([server('a', 'web-1'), server('b', 'db-1')], {
      a: { access: complete(), at: 1 },
      b: { error: 'unreachable: ECONNREFUSED', errorAt: 1 }
    })
    const failed = await screen.findByTestId('failed-db-1')
    expect(failed.textContent).toContain('the access probe failed')
    expect(failed.textContent).toContain('it is not a host with no keys')
    expect(failed.textContent).not.toMatch(/\b0 keys\b/)
  })

  it('is counted in the unchecked total, not silently dropped', async () => {
    mount([server('a', 'web-1'), server('b', 'db-1')], {
      a: { access: complete(), at: 1 },
      b: { error: 'unreachable', errorAt: 1 }
    })
    const unchecked = await screen.findByTestId('unchecked-hosts')
    expect(unchecked.textContent).toContain('1 host could not be checked')
    expect(unchecked.textContent).toContain('not in that count')
  })

  it('names a host that has simply never been collected, separately from a failure', async () => {
    // Three states, not two: read, failed, and never looked at. A server added
    // ten minutes ago is the third and it is not a failure.
    mount([server('a', 'web-1'), server('b', 'db-1')], { a: { access: complete(), at: 1 } })
    const never = await screen.findByTestId('never-collected')
    expect(never.textContent).toContain('db-1')
    expect(never.textContent).toContain('not been read yet')
    expect(screen.queryByTestId('failed-db-1')).toBeNull()
  })
})

describe('what the panel refuses to conclude', () => {
  it('says outright that “this key is not on my fleet” cannot be concluded', async () => {
    mount([server('a', 'web-1'), server('b', 'db-1')], {
      a: { access: complete(), at: 1 },
      b: { error: 'unreachable', errorAt: 1 }
    })
    const banner = await screen.findByTestId('not-an-answer')
    expect(banner.textContent).toContain('cannot be concluded')
    expect(banner.textContent).toContain('lower bound')
  })

  it('raises the same warning for a host that answered only partly', async () => {
    // A host can be perfectly reachable and still hide half its accounts behind
    // a home directory this account cannot traverse. That is the same size of
    // gap as an unreachable host and gets the same sentence.
    mount([server('a', 'web-1')], { a: { access: partial(), at: 1 } })
    expect((await screen.findByTestId('not-an-answer')).textContent).toContain('cannot be concluded')
    const why = await screen.findByTestId('incomplete-web-1')
    expect(why.textContent).toContain('1 of 2 accounts could not be read')
  })

  it('does NOT raise it when every host answered completely', async () => {
    // The other half of the assertion, and the one that keeps the warning
    // meaningful: a banner that is always on is a banner nobody reads.
    mount([server('a', 'web-1')], { a: { access: complete(), at: 1 } })
    await screen.findByText(/1 distinct key/)
    expect(screen.queryByTestId('not-an-answer')).toBeNull()
    expect(screen.queryByTestId('unchecked-hosts')).toBeNull()
    expect(screen.queryByTestId('incomplete-hosts')).toBeNull()
  })

  it('warns about a legacy authorized_keys2 it deliberately did not read', async () => {
    mount([server('a', 'web-1')], {
      a: {
        access: collected(['U 1 keys ok -', 'U 1 keys2 present', 'U 1 name ops']),
        at: 1
      }
    })
    expect((await screen.findByTestId('incomplete-web-1')).textContent).toMatch(
      /authorized_keys2.*sshd still reads/
    )
  })
})

describe('the by-key view', () => {
  it('shows where a key is, across hosts', async () => {
    // The question the whole item exists for: which of my hosts still trusts
    // this key.
    mount([server('a', 'web-1'), server('b', 'db-1')], {
      a: { access: complete(), at: 1 },
      b: { access: complete(), at: 1 }
    })
    const row = await waitFor(() => {
      const r = document.querySelector(`tr[data-fingerprint="${ED25519_FP}"]`)
      if (!r) throw new Error('no row for the key')
      return r
    })
    expect(row.textContent).toContain('web-1')
    expect(row.textContent).toContain('db-1')
    expect(row.textContent).toContain('ops@laptop')
  })

  it('renders a key comment as text, marker and all', async () => {
    // The most attacker-controlled string in the feature. It arrives with
    // control characters and bidi overrides already stripped by the parser, and
    // the panel puts it in a cell — never in a title, a link or markup.
    mount([server('a', 'web-1')], {
      a: {
        access: collected([
          'U 1 keys ok -',
          'U 1 name ops',
          `K 1 1 90 ssh-ed25519 ${ED25519} ${ACCESS_STATUS_MARKER}`
        ]),
        at: 1
      }
    })
    const row = await waitFor(() => {
      const r = document.querySelector(`tr[data-fingerprint="${ED25519_FP}"]`)
      if (!r) throw new Error('no row for the key')
      return r
    })
    expect(row.textContent).toContain(ACCESS_STATUS_MARKER)
    expect(row.innerHTML).not.toContain('<script')
  })

  it('says a key has no label rather than leaving the cell empty', async () => {
    // An unlabelled key is not an unused key — it is a key nobody wrote down
    // the owner of, which is worse and has to look different from blank.
    mount([server('a', 'web-1')], {
      a: { access: collected(['U 1 keys ok -', 'U 1 name ops', `K 1 1 50 ssh-ed25519 ${ED25519}`]), at: 1 }
    })
    expect((await screen.findByText('no label')).textContent).toBe('no label')
  })
})

describe('the by-host view', () => {
  async function hosts(access: HostAccess): Promise<void> {
    mount([server('a', 'web-1')], { a: { access, at: 1 } })
    await screen.findByRole('button', { name: /By host/ })
    await userEvent.click(screen.getByRole('button', { name: /By host/ }))
  }

  it('shows a reason, not a zero, for an account whose file was not read', async () => {
    // The single substitution this whole feature exists to prevent.
    await hosts(partial())
    const denied = await waitFor(() => {
      const r = document.querySelector('tr[data-user="deploy"]')
      if (!r) throw new Error('no row for deploy')
      return r
    })
    expect(denied.textContent).toContain('not permitted')
    expect(denied.querySelector('.mono')?.textContent).not.toBe('0')
    // And the account that WAS read still shows its real count.
    expect(document.querySelector('tr[data-user="ops"]')!.textContent).toContain('1')
  })

  it('warns when a locked password sits next to a live key', async () => {
    // `passwd -l` defeats password authentication and does nothing to key
    // authentication. Locked-plus-key is fully usable by whoever holds the key,
    // and is exactly what a naive reading of "locked" files as safe.
    await hosts(
      collected([
        'S L ops',
        'U 1 keys ok -',
        'U 1 name ops',
        `K 1 1 60 ssh-ed25519 ${ED25519} old-laptop`
      ])
    )
    const row = await waitFor(() => {
      const r = document.querySelector('tr[data-user="ops"]')
      if (!r) throw new Error('no row for ops')
      return r
    })
    const chip = [...row.querySelectorAll('.chip')].find((c) => c.textContent === 'locked')!
    expect(chip.className).toContain('warn')
    expect(chip.getAttribute('title')).toContain('can still log in')
  })

  it('does not warn about a locked account with no keys at all', async () => {
    await hosts(collected(['S L svc', 'U 1 keys ok -', 'U 1 name svc']))
    const row = await waitFor(() => {
      const r = document.querySelector('tr[data-user="svc"]')
      if (!r) throw new Error('no row for svc')
      return r
    })
    const chip = [...row.querySelectorAll('.chip')].find((c) => c.textContent === 'locked')!
    expect(chip.className).not.toContain('warn')
  })

  it('keeps the host’s own last-login phrase when it could not be dated', async () => {
    // "We cannot make a date out of this" is not "we do not know when they
    // logged in", and showing the phrase is the better of the two answers.
    await hosts(
      collected(['L ops tty1 sometime in the past', 'U 1 keys ok -', 'U 1 name ops'], [
        ...OK_STATUS.filter((s) => !s.startsWith('last-login')),
        'last-login partial - lastlog is not available'
      ])
    )
    const row = await waitFor(() => {
      const r = document.querySelector('tr[data-user="ops"]')
      if (!r) throw new Error('no row for ops')
      return r
    })
    expect(row.textContent).toContain('sometime in the past')
  })
})

describe('before anything has been collected', () => {
  it('says so, and says nothing is written to any host', async () => {
    mount([server('a', 'web-1')], {})
    expect((await screen.findByText(/No authorized_keys have been collected yet/)).textContent).toBeTruthy()
    expect(document.body.textContent).toContain('no private key is touched')
    // And no table at all, rather than an empty one that reads as "no keys".
    expect(document.querySelector('table')).toBeNull()
  })

  it('survives a bridge with no access method on it', async () => {
    // Every call site in the renderer has to survive a missing method; a panel
    // that throws on an older preload takes the monitor down with it.
    stubBridge({ fleet: {} })
    render(<AccessPanel servers={[server('a', 'web-1')]} />)
    expect(await screen.findByText(/No authorized_keys have been collected yet/)).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// The write half — roadmap item 23, rule 2, in the panel
// ---------------------------------------------------------------------------
//
// The three outcomes are the whole reason this section exists. A staged key
// change can end three ways and only one of them is a fault, and a panel that
// rendered the other two the same way would teach an operator that the
// dead-man's switch is a failure — which is the fastest route to somebody
// wanting it turned off.

type Preview = {
  token: string
  command: string
  hosts: { serverId: string; serverName: string; user: string }[]
  blocks: { serverId: string; serverName: string; user: string; kind: string; reason: string }[]
  refusals: { serverId: string; serverName: string; user: string; reason: string }[]
  rollbackSeconds: number
}

const PREVIEW: Preview = {
  token: '1800000000000',
  command: 'SP_F="$HOME/.ssh/authorized_keys"\ngrep -v -F',
  hosts: [{ serverId: 'a', serverName: 'web-1', user: 'ops' }],
  blocks: [],
  refusals: [],
  rollbackSeconds: 300
}

function mountWrite(
  over: {
    preview?: Partial<Preview>
    run?: unknown
    onRun?: (req: Record<string, unknown>) => void
    planThrows?: string
  } = {}
): void {
  stubBridge({
    fleet: {
      access: async () => ({ access: complete(), at: 1, intervalMs: 3_600_000 }),
      sampleNow: async () => undefined,
      accessPlan: async () => {
        if (over.planThrows) throw new Error(over.planThrows)
        return { ...PREVIEW, ...over.preview }
      },
      accessRun: async (req: Record<string, unknown>) => {
        over.onRun?.(req)
        return over.run ?? { blocks: [], refusals: [], notStaged: [], reports: [] }
      }
    }
  })
  render(<AccessPanel servers={[server('a', 'web-1')]} />)
}

const report = (outcome: string, detail: string): Record<string, unknown> => ({
  serverId: 'a',
  serverName: 'web-1',
  user: 'ops',
  token: '1800000000000',
  outcome,
  detail,
  backupPath: '/home/ops/.ssh/authorized_keys.shellpilot-1800000000000.bak',
  at: 1
})

describe('revoking a key', () => {
  it('shows no revoke control at all when the bridge cannot write', async () => {
    // The module gate lives in main. A build where it is off must show no
    // button rather than one that fails when pressed.
    mount([server('a', 'web-1')], { a: { access: complete(), at: 1 } })
    await screen.findByText(ED25519_FP)
    expect(screen.queryByTestId(`revoke-${ED25519_FP}`)).toBeNull()
  })

  it('asks before anything is written, and says the change is staged rather than applied', async () => {
    mountWrite()
    await userEvent.click(await screen.findByTestId(`revoke-${ED25519_FP}`))
    const confirm = await screen.findByTestId('revoke-confirm')
    expect(confirm.textContent).toContain('This is staged, not applied')
    expect(confirm.textContent).toContain('arms its OWN rollback')
    expect(confirm.textContent).toContain('300 seconds')
    expect(confirm.textContent).toContain('web-1')
  })

  it('sends back the command it displayed, so main can refuse a change nobody agreed to', async () => {
    let sent: Record<string, unknown> | null = null
    mountWrite({ onRun: (r) => (sent = r) })
    await userEvent.click(await screen.findByTestId(`revoke-${ED25519_FP}`))
    await userEvent.click(await screen.findByTestId('revoke-go'))
    await waitFor(() => expect(sent).not.toBeNull())
    expect(sent!.confirmedCommand).toBe(PREVIEW.command)
    expect(sent!.token).toBe(PREVIEW.token)
    expect(sent!.fingerprint).toBe(ED25519_FP)
  })

  it('names every host it will not touch, in the same dialog as the ones it will', async () => {
    // A host quietly left out of a fleet-wide revocation is the exact failure
    // the read half exists to prevent.
    mountWrite({
      preview: {
        blocks: [
          {
            serverId: 'b',
            serverName: 'db-1',
            user: 'ops',
            kind: 'session-key-unknown',
            reason: 'db-1 does not report which key this session authenticated with.'
          }
        ],
        refusals: [
          {
            serverId: 'c',
            serverName: 'cache-1',
            user: 'deploy',
            reason: 'the change would run as ops on cache-1.'
          }
        ]
      }
    })
    await userEvent.click(await screen.findByTestId(`revoke-${ED25519_FP}`))
    const blocked = await screen.findByTestId('revoke-blocked')
    expect(blocked.textContent).toContain('2 left out, and not by choice')
    expect(blocked.textContent).toContain('does not report which key this session authenticated with')
    expect(blocked.textContent).toContain('the change would run as ops on cache-1')
  })

  it('renders the three outcomes as three different things', async () => {
    mountWrite({
      run: {
        blocks: [],
        refusals: [],
        notStaged: [],
        reports: [
          { ...report('committed', 'Committed on web-1.'), serverId: 'a' },
          { ...report('reverted-verification-failed', 'Reverted on db-1: the check failed.'), serverId: 'b' },
          { ...report('reverted-unconfirmed', 'Reverted on cache-1: nothing confirmed it in time.'), serverId: 'c' }
        ]
      }
    })
    await userEvent.click(await screen.findByTestId(`revoke-${ED25519_FP}`))
    await userEvent.click(await screen.findByTestId('revoke-go'))

    const committed = await screen.findByTestId('outcome-a')
    const failed = await screen.findByTestId('outcome-b')
    const unconfirmed = await screen.findByTestId('outcome-c')

    expect(committed.textContent).toContain('Committed')
    expect(failed.textContent).toContain('Reverted — the host would not let a new session in')
    expect(unconfirmed.textContent).toContain('Reverted — nothing confirmed it in time')

    // Three labels, three chips, three classes. The one that is not a fault is
    // not dressed as one.
    const chip = (el: Element): Element => el.querySelector('.chip')!
    expect(chip(committed).className).toContain('ok')
    expect(chip(failed).className).toContain('loud')
    expect(chip(unconfirmed).className).toContain('warn')
    expect(chip(unconfirmed).className).not.toContain('loud')
    expect(
      new Set([chip(committed).textContent, chip(failed).textContent, chip(unconfirmed).textContent]).size
    ).toBe(3)
  })

  it('keeps a host whose staged write never landed apart from all three', async () => {
    // Nothing happened there at all: no backup, no watchdog, no change. It is a
    // fourth thing, and calling it "reverted" would say a file was put back
    // that was never replaced.
    mountWrite({
      run: {
        blocks: [],
        refusals: [],
        notStaged: [{ serverId: 'b', serverName: 'db-1', detail: 'authorized_keys is not writable by this account' }],
        reports: []
      }
    })
    await userEvent.click(await screen.findByTestId(`revoke-${ED25519_FP}`))
    await userEvent.click(await screen.findByTestId('revoke-go'))
    const row = await screen.findByTestId('not-staged-b')
    expect(row.textContent).toContain('Nothing was changed on db-1')
    expect(row.textContent).toContain('not writable by this account')
    expect(row.textContent).not.toContain('Reverted')
  })

  it('says nothing was changed when main refuses the run', async () => {
    mountWrite({ planThrows: 'the collection has changed since the plan was shown' })
    await userEvent.click(await screen.findByTestId(`revoke-${ED25519_FP}`))
    const problem = await screen.findByTestId('access-problem')
    expect(problem.textContent).toContain('Nothing was changed')
    expect(problem.textContent).toContain('the collection has changed since the plan was shown')
  })
})
