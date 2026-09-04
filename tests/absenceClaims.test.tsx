// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { stubBridge } from './setup/renderer'
import { AiApprovals } from '../src/renderer/src/components/ai/AiApprovals'
import { ProcessesPanel } from '../src/renderer/src/components/processes/ProcessesPanel'
import { CredProxyPanel } from '../src/renderer/src/components/settings/CredProxyPanel'

// Screens that tell an operator nothing is there.
//
// Four of these have now been found saying it before they had looked, each in a
// list that starts as `[]` and is filled by an await. The pattern is worth a
// file of its own, because the bug is invisible to a test that waits: assert
// with `findByText` and the claim passes whether or not it was ALSO on screen a
// moment earlier, which is exactly when it was wrong.
//
// So each of these holds the read open and looks while it is pending.

describe('the approvals list, which is the one someone acts on', () => {
  it('does not say nothing is waiting before it has asked', async () => {
    // An agent can be blocked on a decision right now. "Nothing waiting on you"
    // is the sentence that makes an operator close the screen and walk away,
    // and it was being shown for the first moments of every visit.
    stubBridge({ aiMcp: { listApprovals: () => new Promise(() => {}) } } as never)
    render(<AiApprovals />)

    expect(await screen.findByText(/Checking for anything waiting/)).toBeTruthy()
    expect(screen.queryByText('Nothing waiting on you right now.')).toBeNull()
  })

  it('says it once the read comes back empty', async () => {
    stubBridge({ aiMcp: { listApprovals: async () => [] } } as never)
    render(<AiApprovals />)
    expect(await screen.findByText('Nothing waiting on you right now.')).toBeTruthy()
  })

  it('does not turn a failed read into an empty one', async () => {
    // The promise had no rejection path, so a bridge error left this panel
    // saying nothing was waiting for as long as it stayed open -- a wrong
    // answer that looks exactly like a right one.
    stubBridge({
      aiMcp: {
        listApprovals: async () => {
          throw new Error('bridge is down')
        }
      }
    } as never)
    render(<AiApprovals />)

    expect(await screen.findByText(/could not be read/)).toBeTruthy()
    expect(screen.queryByText('Nothing waiting on you right now.')).toBeNull()
  })
})

describe('the supervised process list', () => {
  it('does not say there are none before it has read them', async () => {
    stubBridge({
      processes: {
        list: () => new Promise(() => {}),
        status: async () => [],
        logs: async () => [],
        // processBridge() requires BOTH list and start before it treats the
        // channel as present -- a half-taught main process answers nothing.
        start: async () => ({}),
        stop: async () => ({}),
        create: async () => ({}),
        remove: async () => true,
        onEvent: () => () => {}
      }
    } as never)
    render(<ProcessesPanel />)

    expect(await screen.findByText(/Reading what is under supervision/)).toBeTruthy()
    expect(screen.queryByText(/No processes yet/)).toBeNull()
  })

  it('says so once the read comes back empty', async () => {
    stubBridge({
      processes: {
        list: async () => [],
        status: async () => [],
        logs: async () => [],
        // processBridge() requires BOTH list and start before it treats the
        // channel as present -- a half-taught main process answers nothing.
        start: async () => ({}),
        stop: async () => ({}),
        create: async () => ({}),
        remove: async () => true,
        onEvent: () => () => {}
      }
    } as never)
    render(<ProcessesPanel />)
    expect(await screen.findByText(/No processes yet/)).toBeTruthy()
  })
})

describe('the credential proxy rules, where the claim is reassuring', () => {
  const proxy = (over: Record<string, unknown>) => ({
    credproxy: {
      status: async () => ({ enabled: false, listening: false, port: 8787, rules: 0 }),
      calls: async () => [],
      saveRule: async () => ({ ok: true }),
      removeRule: async () => ({ ok: true }),
      start: async () => ({ ok: true }),
      stop: async () => ({}),
      ...over
    }
  })

  it('does not promise the proxy refuses everything before reading the rules', async () => {
    // "No rules yet, so the proxy will refuse everything. That is the safe
    // state" is a REASSURANCE, and a false reassurance is worse than a false
    // alarm: it tells someone the proxy is shut when it may be holding
    // permissive rules nobody has fetched.
    stubBridge(proxy({ rules: () => new Promise(() => {}) }) as never)
    render(<CredProxyPanel />)

    expect(await screen.findByText(/Reading the rules/)).toBeTruthy()
    expect(screen.queryByText(/refuse everything/)).toBeNull()
  })

  it('gives the reassurance once it has actually read them', async () => {
    stubBridge(proxy({ rules: async () => [] }) as never)
    render(<CredProxyPanel />)
    expect(await screen.findByText(/refuse everything/)).toBeTruthy()
  })

  it('says the channel is missing rather than waiting on it forever', async () => {
    // No credproxy bridge at all. Nothing is coming, so "reading…" would be a
    // spinner with no end -- the same defect pointed the other way.
    stubBridge({})
    render(<CredProxyPanel />)

    expect(await screen.findByText(/does not expose the credential proxy/)).toBeTruthy()
    expect(screen.queryByText(/refuse everything/)).toBeNull()
  })
})
