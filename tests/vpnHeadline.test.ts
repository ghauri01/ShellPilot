import { describe, it, expect } from 'vitest'
import { headline } from '../src/renderer/src/components/vpn/useVpnProfiles'

describe('the toast says something', () => {
  it('keeps the first sentence for a failure that has one', () => {
    expect(headline('The server rejected these credentials. Check the username.')).toBe(
      'The server rejected these credentials.'
    )
  })

  it('promotes the detail when the first sentence is the internal non-message', () => {
    // What OpenVPN actually produced: a toast with no fact in it, in front of
    // the one detail that explained the failure.
    expect(
      headline(
        'Something went wrong inside ShellPilot. The management socket path is 123 bytes, which is too long: /Users/x/Library/Application Support/ShellPilot/vpn-run/vpn-abc/mgmt/m.sock'
      )
    ).toBe('The management socket path is 123 bytes, which is too long: /Users/x/Library/Application Support/ShellPilot/vpn-run/vpn-abc/mgmt/m.sock')
  })

  it('falls back to the generic sentence when there is genuinely nothing else', () => {
    expect(headline('Something went wrong inside ShellPilot.')).toBe(
      'Something went wrong inside ShellPilot.'
    )
  })

  it('handles a message with no sentence break', () => {
    expect(headline('  No response from the server  ')).toBe('No response from the server')
  })
})
