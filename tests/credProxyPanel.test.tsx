// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { CredProxyPanel } from '../src/renderer/src/components/settings/CredProxyPanel'
import type { CredProxyCall, CredProxyRule, CredProxyStatus } from '../src/shared/credproxy'
import type { VaultEntry } from '../src/shared/vault'

// The panel half of roadmap item 7.
//
// These assert what an operator SEES, because the two ways this pane can be
// wrong both look fine on screen: a token handed over with no statement of
// what holding it grants, and an empty rule list that reads as "not set up
// yet" rather than as "everything will be refused, which is correct".

const TOKEN = 'cpx_5f4d3c2b1a09876543210fedcba98765'

const status = (over: Partial<CredProxyStatus> = {}): CredProxyStatus => ({
  enabled: true,
  port: 5178,
  listening: true,
  address: '127.0.0.1:5178',
  hasToken: true,
  ruleCount: 1,
  ...over
})

const rule = (over: Partial<CredProxyRule> = {}): CredProxyRule => ({
  id: 'r1',
  name: 'Billing API',
  origin: 'https://api.example.com',
  credential: { vaultEntryId: 'v1', slot: 'password' },
  injection: { kind: 'bearer' },
  enabled: true,
  createdAt: '2026-01-01T00:00:00.000Z',
  ...over
})

const entry = (over: Partial<VaultEntry> = {}): VaultEntry => ({
  id: 'v1',
  name: 'Example live key',
  kind: 'key',
  url: '',
  username: '',
  password: 'sk-live-NEVER-RENDERED',
  notes: '',
  tags: [],
  fields: [],
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
  ...over
})

interface Stub {
  status?: CredProxyStatus
  rules?: CredProxyRule[]
  calls?: CredProxyCall[]
  entries?: VaultEntry[]
  saveRule?: (draft: unknown) => Promise<unknown>
  token?: () => Promise<unknown>
  rotateToken?: () => Promise<unknown>
  start?: (port?: number) => Promise<unknown>
  stop?: () => Promise<unknown>
  removeRule?: (id: string) => Promise<unknown>
}

function mount(s: Stub = {}): void {
  stubBridge({
    credproxy: {
      status: async () => s.status ?? status(),
      rules: async () => s.rules ?? [],
      calls: async () => s.calls ?? [],
      saveRule: s.saveRule ?? (async () => ({ ok: true, rule: rule() })),
      removeRule: s.removeRule ?? (async () => ({ ok: true })),
      start: s.start ?? (async () => ({ ok: true, status: status() })),
      stop: s.stop ?? (async () => status({ listening: false, enabled: false })),
      token: s.token ?? (async () => ({ ok: true, token: TOKEN })),
      rotateToken: s.rotateToken ?? (async () => ({ ok: true, token: 'cpx_rotated' }))
    },
    vault: {
      list: async () => ({ ok: true, entries: s.entries ?? [entry()] })
    }
  })
  render(<CredProxyPanel />)
}

describe('the pane says what the token grants, where the token is', () => {
  it('names the header and states the power before the token is on screen', async () => {
    mount()
    await screen.findByText('x-shellpilot-proxy-token')
    expect(
      screen.getByText(/Anything holding this token can spend your API budget/)
    ).toBeTruthy()
    expect(screen.getByText(/Treat it like the API key it stands in for/)).toBeTruthy()
  })

  it('shows the token only when asked, and then shows the whole of it', async () => {
    mount()
    const user = userEvent.setup()
    expect(screen.queryByDisplayValue(TOKEN)).toBeNull()

    await user.click(await screen.findByRole('button', { name: 'Show token' }))

    expect(await screen.findByDisplayValue(TOKEN)).toBeTruthy()
  })

  it('warns that rotating breaks whatever is still using the old one', async () => {
    mount()
    const user = userEvent.setup()

    await user.click(await screen.findByRole('button', { name: 'Rotate' }))

    expect(
      await screen.findByText(
        'New token. Anything still using the old one will now be refused — update your scripts.'
      )
    ).toBeTruthy()
  })

  it('says plainly that being on loopback is not a permission', async () => {
    mount()
    expect(
      await screen.findByText(
        /Every process on this machine can reach a loopback port, so being local is not a permission/
      )
    ).toBeTruthy()
  })
})

describe('an empty rule list reads as the safe state, not as a broken one', () => {
  it('says everything will be refused', async () => {
    mount({ rules: [] })
    expect(
      await screen.findByText(
        /No rules yet, so the proxy will refuse everything. That is the safe state, not a broken one./
      )
    ).toBeTruthy()
  })

  it('says a destination with no rule is refused rather than forwarded', async () => {
    mount({ rules: [] })
    expect(
      await screen.findByText(
        /a destination with no rule is refused, never forwarded/i
      )
    ).toBeTruthy()
  })
})

describe('a rule reads as a sentence about where a credential goes', () => {
  it('names the destination, the vault entry and how it is sent', async () => {
    mount({ rules: [rule()], entries: [entry({ name: 'Example live key' })] })

    expect(
      await screen.findByText(
        'https://api.example.com — key from “Example live key”, sent as Authorization: Bearer'
      )
    ).toBeTruthy()
  })

  it('shows the base URL a caller points at', async () => {
    mount({ rules: [rule()] })
    expect(await screen.findByText('http://127.0.0.1:5178/https://api.example.com')).toBeTruthy()
  })

  // The panel must never render a credential, only the name of the entry
  // holding it. The stub's entry carries a value on purpose.
  it('never renders the credential itself', async () => {
    mount({ rules: [rule()], entries: [entry()] })
    await screen.findByText(/key from/)
    expect(document.body.textContent).not.toContain('sk-live-NEVER-RENDERED')
  })

  it('says so when the vault entry behind a rule has gone', async () => {
    mount({ rules: [rule()], entries: [] })
    expect(
      await screen.findByText(/key from “a vault entry that is no longer there”/)
    ).toBeTruthy()
  })

  it('surfaces the exact refusal when a rule will not save', async () => {
    mount({
      rules: [],
      saveRule: async () => ({ ok: false, error: '"Server" cannot carry a credential.' })
    })
    const user = userEvent.setup()

    await user.click(await screen.findByRole('button', { name: 'Add rule' }))
    await user.click(screen.getByRole('button', { name: 'Save rule' }))

    expect(await screen.findByText('"Server" cannot carry a credential.')).toBeTruthy()
  })

  it('sends the draft as a rule, with the injection the form chose', async () => {
    // The parameter is declared, not just ignored: `vi.fn(async () => ...)`
    // gives `mock.calls` an element type of `[]`, so `calls[0][0]` below was an
    // index into an empty tuple — the draft it asserts on was untyped as well
    // as unread.
    const saveRule = vi.fn(async (_draft: unknown) => ({ ok: true, rule: rule() }))
    mount({ rules: [], saveRule, entries: [entry({ id: 'v1', name: 'Example live key' })] })
    const user = userEvent.setup()

    await user.click(await screen.findByRole('button', { name: 'Add rule' }))
    await user.type(screen.getByLabelText('Rule name'), 'Billing API')
    await user.type(screen.getByLabelText('Destination'), 'https://api.example.com')
    await user.selectOptions(screen.getByLabelText('Vault entry'), 'v1')
    await user.selectOptions(screen.getByLabelText('How it is sent'), 'header')
    await user.type(await screen.findByLabelText('Header name'), 'X-Api-Key')
    await user.click(screen.getByRole('button', { name: 'Save rule' }))

    await waitFor(() => expect(saveRule).toHaveBeenCalled())
    expect(saveRule.mock.calls[0][0]).toEqual({
      id: undefined,
      name: 'Billing API',
      origin: 'https://api.example.com',
      credential: { vaultEntryId: 'v1', slot: 'password' },
      injection: { kind: 'header', name: 'X-Api-Key' },
      enabled: true
    })
  })

  it('warns in the form that the origin is exact and redirects are not followed', async () => {
    mount({ rules: [] })
    const user = userEvent.setup()

    await user.click(await screen.findByRole('button', { name: 'Add rule' }))

    expect(
      screen.getByText(
        /A rule for api\.example\.com does not cover api\.example\.com\.something-else, and it does not follow a redirect anywhere either\./
      )
    ).toBeTruthy()
  })
})

describe('a locked vault is a state on screen, not a stream of failures', () => {
  it('says how many calls were parked, and that none went out bare', async () => {
    mount({
      status: status({
        parked: { reason: 'vault-locked', since: '2026-09-04T09:12:00.000Z', calls: 14 }
      })
    })

    const note = await screen.findByRole('status')
    expect(note.textContent).toContain('The vault is locked')
    expect(note.textContent).toContain('14 calls were parked')
    expect(note.textContent).toContain('rather than sent without a credential')
  })

  it('reads correctly for a single parked call', async () => {
    mount({
      status: status({
        parked: { reason: 'vault-locked', since: '2026-09-04T09:12:00.000Z', calls: 1 }
      })
    })
    const note = await screen.findByRole('status')
    expect(note.textContent).toContain('1 call was parked')
  })

  it('distinguishes an empty vault entry from a locked vault', async () => {
    mount({
      status: status({
        parked: { reason: 'credential-missing', since: '2026-09-04T09:12:00.000Z', calls: 2 }
      })
    })
    const note = await screen.findByRole('status')
    expect(note.textContent).toContain('points at a vault entry that no longer holds anything')
    expect(note.textContent).not.toContain('The vault is locked')
  })
})

describe('recent calls show a rule that has quietly stopped matching', () => {
  const call = (over: Partial<CredProxyCall> = {}): CredProxyCall => ({
    id: 'c1',
    at: '2026-09-04T09:00:00.000Z',
    method: 'GET',
    origin: 'https://api.example.com',
    path: '/v1/things',
    ruleId: 'r1',
    ruleName: 'Billing API',
    outcome: 'forwarded',
    status: 200,
    ms: 42,
    ...over
  })

  it('shows a forwarded call with its status and duration', async () => {
    mount({ calls: [call()] })
    expect(await screen.findByText('https://api.example.com/v1/things')).toBeTruthy()
    expect(screen.getByText('200')).toBeTruthy()
    expect(screen.getByText('42 ms')).toBeTruthy()
  })

  it('shows a refusal by name, with no rule attached', async () => {
    mount({
      calls: [call({ id: 'c2', outcome: 'no-rule', ruleId: null, ruleName: null, status: undefined })]
    })
    expect(await screen.findByText('no-rule')).toBeTruthy()
    expect(screen.getByText('no rule')).toBeTruthy()
  })

  it('shows the note when a redirect was refused', async () => {
    mount({
      calls: [
        call({
          id: 'c3',
          status: 302,
          detail: 'Upstream redirected to https://evil.tld; not followed, credential not resent.'
        })
      ]
    })
    expect(
      await screen.findByText(
        'Upstream redirected to https://evil.tld; not followed, credential not resent.'
      )
    ).toBeTruthy()
  })

  it('says nothing has come through rather than showing an empty box', async () => {
    mount({ calls: [] })
    expect(await screen.findByText('Nothing has come through yet.')).toBeTruthy()
  })

  it('states that the body, the headers and the query string are not recorded', async () => {
    mount()
    expect(
      await screen.findByText(
        /Never the body, the headers or the query string — a rule that puts the key in a query parameter is exactly the rule whose query string must not be written down\./
      )
    ).toBeTruthy()
  })
})

describe('the listener switch', () => {
  it('reports why the listener would not start rather than silently staying off', async () => {
    mount({
      status: status({ listening: false, enabled: false }),
      start: async () => ({
        ok: false,
        error: 'listen EADDRINUSE: address already in use 127.0.0.1:5178',
        status: status({ listening: false })
      })
    })
    const user = userEvent.setup()

    await user.click(await screen.findByRole('switch', { name: 'Run the API credential proxy' }))

    expect(
      await screen.findByText('listen EADDRINUSE: address already in use 127.0.0.1:5178')
    ).toBeTruthy()
  })

  it('says which address it is bound to, as a fact rather than a promise', async () => {
    mount()
    expect(await screen.findByText(/Listening on 127\.0\.0\.1:5178\./)).toBeTruthy()
  })
})
