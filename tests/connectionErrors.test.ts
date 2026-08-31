import { describe, expect, it } from 'vitest'
import { classifyConnectionError, errorText } from '../src/renderer/src/lib/connectionError'

// Which button an error gets is decided entirely by this classifier, so the
// strings it is fed are the ones the app actually produces — ssh2's phrasing,
// node's errno text, and the sentences tunnel.ts writes itself. A pattern that
// drifts away from those does not fail loudly; it quietly turns a fixable
// problem back into a wall of driver output with no way out. Hence the fixtures.

describe('classifyConnectionError', () => {
  it('reads a host key that no longer matches', () => {
    expect(classifyConnectionError('Handshake failed: host key verification failed')).toBe('host-key')
  })

  it('reads a taken port from the sentence tunnel.ts writes', () => {
    // Not "EADDRINUSE": tunnel.ts already translates that one, and the
    // classifier has to recognise its own app's wording too.
    expect(classifyConnectionError('Port 8080 on 127.0.0.1 is already in use.')).toBe('port-in-use')
    expect(classifyConnectionError('listen EADDRINUSE: address already in use')).toBe('port-in-use')
  })

  it('separates a rejected credential from a refused file', () => {
    expect(classifyConnectionError('All configured authentication methods failed')).toBe('auth')
    expect(classifyConnectionError('Permission denied (publickey,password)')).toBe('auth')
    // The bare form is a filesystem refusal — a different sentence and a
    // different fix from a credential the server would not take.
    expect(classifyConnectionError('Permission denied')).toBe('permission')
  })

  it('reads a missing key file without claiming every missing file is one', () => {
    expect(classifyConnectionError("ENOENT: no such file or directory, open '/home/a/.ssh/id_ed25519'")).toBe(
      'key-missing'
    )
    expect(classifyConnectionError('No such file /var/log/app.log')).toBe('unknown')
  })

  it('reads the ordinary network refusals', () => {
    expect(classifyConnectionError('connect ECONNREFUSED 10.0.0.4:5432')).toBe('refused')
    expect(classifyConnectionError('getaddrinfo ENOTFOUND db.internal')).toBe('unreachable')
    expect(classifyConnectionError('Timed out while waiting for handshake')).toBe('unreachable')
  })

  it('says nothing rather than guessing', () => {
    expect(classifyConnectionError(undefined)).toBe('unknown')
    expect(classifyConnectionError('')).toBe('unknown')
    expect(classifyConnectionError('something nobody has seen before')).toBe('unknown')
  })
})

describe('errorText', () => {
  it('drops the IPC preamble that describes the transport, not the problem', () => {
    const err = new Error(
      "Error invoking remote method 'sftp:connect': Error: SHELLPILOT_VAULT_LOCKED: this server authenticates with a vault credential, and the vault is locked."
    )
    expect(errorText(err)).toBe(
      'SHELLPILOT_VAULT_LOCKED: this server authenticates with a vault credential, and the vault is locked.'
    )
  })

  it('handles anything that was thrown, not just Errors', () => {
    expect(errorText('plain string')).toBe('plain string')
    expect(errorText(new Error('Error: doubled up'))).toBe('doubled up')
  })
})
