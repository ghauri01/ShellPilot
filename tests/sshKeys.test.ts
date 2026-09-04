import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { listDefaultKeys, isEncryptedPrivateKey } from '../src/main/services/sshKeys'

let home: string
let ssh: string
let originalHome: string | undefined

// Real OpenSSH keys base64-encode the cipher name, so these fixtures are built
// the same way: the literal word "none" never appears in the armoured text,
// which is exactly what the old substring check got wrong.
const OPENSSH_PLAIN = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END OPENSSH PRIVATE KEY-----\n'
const OPENSSH_ENCRYPTED = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END OPENSSH PRIVATE KEY-----\n'
const RSA_ENCRYPTED = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,X\n'

beforeEach(() => {
  originalHome = process.env.HOME
  home = mkdtempSync(join(tmpdir(), 'shellpilot-sshkeys-'))
  ssh = join(home, '.ssh')
  mkdirSync(ssh)
  process.env.HOME = home
})

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME
  else process.env.HOME = originalHome
  rmSync(home, { recursive: true, force: true })
})

describe('default ssh key detection', () => {
  it('returns nothing when ~/.ssh does not exist', () => {
    rmSync(ssh, { recursive: true })
    expect(listDefaultKeys()).toEqual([])
  })

  it('finds private keys and ignores everything else in the folder', () => {
    writeFileSync(join(ssh, 'id_ed25519'), OPENSSH_PLAIN)
    writeFileSync(join(ssh, 'id_ed25519.pub'), 'ssh-ed25519 AAAAC3Nza user@server\n')
    writeFileSync(join(ssh, 'config'), 'Host example\n  User root\n')
    writeFileSync(join(ssh, 'known_hosts'), 'github.com ssh-ed25519 AAAA\n')
    writeFileSync(join(ssh, 'known_hosts_custom'), 'example.com ssh-rsa AAAA\n')
    writeFileSync(join(ssh, 'authorized_keys'), 'ssh-rsa AAAA\n')

    expect(listDefaultKeys().map((k) => k.fileName)).toEqual(['id_ed25519'])
  })

  it('labels the algorithm from the matching .pub', () => {
    writeFileSync(join(ssh, 'id_ed25519'), OPENSSH_PLAIN)
    writeFileSync(join(ssh, 'id_ed25519.pub'), 'ssh-ed25519 AAAAC3Nza user@server\n')
    writeFileSync(join(ssh, 'id_rsa'), OPENSSH_PLAIN)

    const keys = listDefaultKeys()
    expect(keys.find((k) => k.fileName === 'id_ed25519')?.algorithm).toBe('ED25519')
    // No .pub alongside it, so there is nothing to read the algorithm from.
    expect(keys.find((k) => k.fileName === 'id_rsa')?.algorithm).toBeNull()
  })

  it('flags passphrase-protected keys in both OpenSSH and PEM formats', () => {
    writeFileSync(join(ssh, 'id_ed25519'), OPENSSH_PLAIN)
    writeFileSync(join(ssh, 'id_ecdsa'), OPENSSH_ENCRYPTED)
    writeFileSync(join(ssh, 'id_rsa'), RSA_ENCRYPTED)

    const byName = Object.fromEntries(listDefaultKeys().map((k) => [k.fileName, k.encrypted]))
    expect(byName).toEqual({ id_ed25519: false, id_ecdsa: true, id_rsa: true })
  })

  it('orders the conventional key names first', () => {
    for (const n of ['zz_custom', 'id_rsa', 'id_ed25519', 'work_key', 'id_ecdsa']) {
      writeFileSync(join(ssh, n), OPENSSH_PLAIN)
    }
    expect(listDefaultKeys().map((k) => k.fileName)).toEqual([
      'id_ed25519',
      'id_ecdsa',
      'id_rsa',
      'work_key',
      'zz_custom'
    ])
  })

  it('survives an unreadable entry rather than failing the whole scan', () => {
    writeFileSync(join(ssh, 'id_ed25519'), OPENSSH_PLAIN)
    // A dangling symlink cannot be stat'd or read.
    symlinkSync(join(ssh, 'gone'), join(ssh, 'broken_link'))
    expect(listDefaultKeys().map((k) => k.fileName)).toEqual(['id_ed25519'])
  })
})

describe('encrypted key detection', () => {
  it('does not mistake an unencrypted OpenSSH key for a protected one', () => {
    // Regression: the previous check tested the armoured text for the literal
    // word "none". A real key spells its cipher inside the base64, so every
    // passphrase-free ed25519/rsa key was rejected as "passphrase-protected"
    // before ssh2 ever got to try it.
    expect(isEncryptedPrivateKey(OPENSSH_PLAIN)).toBe(false)
  })

  it('detects an OpenSSH key that names a real cipher', () => {
    expect(isEncryptedPrivateKey(OPENSSH_ENCRYPTED)).toBe(true)
  })

  it('detects legacy PEM keys by their header', () => {
    expect(isEncryptedPrivateKey(RSA_ENCRYPTED)).toBe(true)
  })

  it('treats unparseable armour as not encrypted rather than blocking the key', () => {
    expect(isEncryptedPrivateKey('-----BEGIN OPENSSH PRIVATE KEY-----\nnot-base64!!!\n')).toBe(false)
  })
})
