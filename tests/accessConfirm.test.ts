import { afterAll, describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  ACCESS_COMMITTED_PREFIX,
  ACCESS_VERIFIED_PREFIX,
  accessBackupPath,
  accessDisarmCommand,
  accessVerifyCommand,
  buildRevokeKeyCommand,
  describeAccessOutcome,
  judgeAccessVerification,
  type AccessCommitEvidence
} from '../src/shared/access'
import {
  AccessCommitter,
  type AccessCommitRequest,
  type AccessFreshSession
} from '../src/main/services/access'

// Roadmap item 23, rule 2 — the confirmation.
//
// The write half staged a change behind a watchdog the host arms on itself and
// then stopped, because the disarm may only ride a session that authenticated
// AFTER the write, and nothing could produce one. This is the rule that now
// consumes it.
//
// Nothing here asserts that a function was called. What is asserted is which
// COMMANDS reached the host — a confirmation that never left this process is
// exactly as good as none — and, at the bottom, what the real commands do to a
// real file.

const STAGED_AT = 1_800_000_000_000
const TOKEN = 't42'
const KEY_PATH = '/home/ops/.ssh/authorized_keys'

const req = (over: Partial<AccessCommitRequest> = {}): AccessCommitRequest => ({
  serverId: 'a',
  serverName: 'web-1',
  user: 'ops',
  token: TOKEN,
  keyPath: KEY_PATH,
  stagedAt: STAGED_AT,
  rollbackSeconds: 300,
  ...over
})

interface Fake extends AccessFreshSession {
  ran: string[]
  closes: number
}

/**
 * A session that behaves however the test needs, and records what was run on
 * it. Honest by default: it authenticated a second after the write, it is not
 * in the pool, and the host answers the check.
 */
function session(over: Partial<AccessFreshSession> & { verifyOut?: string; verifyCode?: number; verifyErr?: string; disarmCode?: number } = {}): Fake {
  const ran: string[] = []
  const f: Fake = {
    ran,
    closes: 0,
    connectionId: 'fresh#7',
    pooledConnectionIds: ['pooled#1', 'pooled#2'],
    authenticatedAt: STAGED_AT + 1_000,
    exec: async (command) => {
      ran.push(command)
      if (command.includes('SP_M=')) {
        const code = over.disarmCode ?? 0
        return {
          ok: true,
          code,
          stdout: code === 0 ? `${ACCESS_COMMITTED_PREFIX}${KEY_PATH}\n` : '',
          stderr: code === 0 ? '' : 'could not confirm the change'
        }
      }
      const code = over.verifyCode ?? 0
      return {
        ok: true,
        code,
        stdout: over.verifyOut ?? (code === 0 ? `${ACCESS_VERIFIED_PREFIX}${TOKEN}\n` : ''),
        stderr: over.verifyErr ?? ''
      }
    },
    close: () => {
      f.closes += 1
    }
  }
  if (over.connectionId !== undefined) f.connectionId = over.connectionId
  if (over.pooledConnectionIds !== undefined) f.pooledConnectionIds = over.pooledConnectionIds
  if (over.authenticatedAt !== undefined) f.authenticatedAt = over.authenticatedAt
  if (over.exec !== undefined) f.exec = over.exec
  return f
}

const committer = (s: Fake | Error, now = STAGED_AT + 2_000): AccessCommitter =>
  new AccessCommitter({
    openFresh: async () => {
      if (s instanceof Error) throw s
      return s
    },
    now: () => now
  })

const isDisarm = (c: string): boolean => c.includes(': > "$SP_M"')
const isVerify = (c: string): boolean => c.includes(ACCESS_VERIFIED_PREFIX)

describe('the disarm is issued only after an independent session', () => {
  it('confirms the change once a fresh session has proved the host still lets us in', async () => {
    const s = session()
    const report = await committer(s).confirm({}, req())

    expect(s.ran.filter(isVerify)).toHaveLength(1)
    expect(s.ran.filter(isDisarm)).toHaveLength(1)
    // The order is the rule: proved first, confirmed second, on the same
    // connection.
    expect(s.ran.findIndex(isVerify)).toBeLessThan(s.ran.findIndex(isDisarm))
    expect(report.outcome).toBe('committed')
    expect(report.backupPath).toBe('/home/ops/.ssh/authorized_keys.shellpilot-t42.bak')
  })

  it('issues nothing at all when no second session can be opened', async () => {
    // The host may have rejected the key the change just installed, or it may
    // be unreachable. Both mean the same thing, and the same thing is done:
    // nothing, and the host restores itself.
    const report = await committer(new Error('All configured authentication methods failed')).confirm({}, req())
    expect(report.outcome).toBe('reverted-verification-failed')
    expect(report.detail).toContain('All configured authentication methods failed')
    // The sentence no longer claims the previous file IS back — that is a
    // claim about something this process cannot see. It says the rollback was
    // proved running before anything was replaced, and where it restores from.
    expect(report.detail).toContain('armed and confirmed running')
    expect(report.detail).toContain('/home/ops/.ssh/authorized_keys.shellpilot-t42.bak')
  })

  it('does not confirm when the check fails on the host', async () => {
    const s = session({ verifyCode: 3, verifyErr: 'no staged change with this token is waiting here\n' })
    const report = await committer(s).confirm({}, req())
    expect(s.ran.filter(isDisarm)).toEqual([])
    expect(report.outcome).toBe('reverted-verification-failed')
    expect(report.detail).toContain('no staged change with this token is waiting here')
  })

  it('does not confirm when the session authenticated BEFORE the change was written', async () => {
    // The exact shape a "verify" step on the job engine's pooled transport
    // would have had: a session that was already open, answering a command.
    const s = session({ authenticatedAt: STAGED_AT - 1 })
    const report = await committer(s).confirm({}, req())
    expect(s.ran.filter(isDisarm)).toEqual([])
    expect(report.outcome).toBe('reverted-verification-failed')
    expect(report.detail).toContain('authenticated before the change was written')
  })

  it('does not confirm when the session is one the pool is holding', async () => {
    const s = session({ connectionId: 'pooled#2' })
    const report = await committer(s).confirm({}, req())
    expect(s.ran.filter(isDisarm)).toEqual([])
    expect(report.outcome).toBe('reverted-verification-failed')
    expect(report.detail).toContain('the same already-authenticated transport that wrote the file')
  })

  it('does not confirm a change staged on some other host', async () => {
    // A session that landed somewhere else answers, and answers about a
    // different change. The token in the output is what ties the two together.
    const s = session({ verifyOut: `${ACCESS_VERIFIED_PREFIX}t99\n` })
    const report = await committer(s).confirm({}, req())
    expect(s.ran.filter(isDisarm)).toEqual([])
    expect(report.outcome).toBe('reverted-verification-failed')
    expect(report.detail).toContain('not the host and account the change was made on')
  })

  it('does not confirm after the window has closed, however well the check went', async () => {
    const s = session({ authenticatedAt: STAGED_AT + 400_000 })
    const report = await committer(s, STAGED_AT + 400_000).confirm({}, req())
    expect(s.ran).toEqual([])
    expect(report.outcome).toBe('reverted-unconfirmed')
    expect(report.detail).toContain('300-second window closed')
  })

  it('reports a confirmation that could not be written as unconfirmed, not as a failure', async () => {
    // Verified, and then the marker could not be created. Nothing is wrong with
    // the change; the host is simply about to undo it.
    const s = session({ disarmCode: 3 })
    const report = await committer(s).confirm({}, req())
    expect(s.ran.filter(isDisarm)).toHaveLength(1)
    expect(report.outcome).toBe('reverted-unconfirmed')
    expect(report.detail).toContain('could not be written')
  })

  it('closes its session on every path, so a confirmation leaves no way in behind it', async () => {
    for (const s of [session(), session({ verifyCode: 3 }), session({ connectionId: 'pooled#1' })]) {
      await committer(s).confirm({}, req())
      expect(s.closes).toBe(1)
    }
  })

  it('answers rather than throwing when the session dies mid-check', async () => {
    const s = session()
    s.exec = async () => {
      throw new Error('Not connected')
    }
    const report = await committer(s).confirm({}, req())
    expect(report.outcome).toBe('reverted-verification-failed')
    expect(report.detail).toContain('Not connected')
  })
})

describe('the three outcomes read as three different things', () => {
  const base = { serverName: 'web-1', user: 'ops', backupPath: '/b.bak', rollbackSeconds: 300 }

  it('says committed, says rejected and says unconfirmed in three distinct sentences', async () => {
    const committed = describeAccessOutcome({ ...base, outcome: 'committed', reason: '' })
    const failed = describeAccessOutcome({ ...base, outcome: 'reverted-verification-failed', reason: 'the host said no.' })
    const unconfirmed = describeAccessOutcome({ ...base, outcome: 'reverted-unconfirmed', reason: 'nobody was there.' })

    expect(committed).toBe(
      "Committed on web-1. A second session authenticated after the change and called off the host's rollback, so ops's authorized_keys is now permanent. The previous file is at /b.bak until the 300-second window closes, after which the host removes it."
    )
    expect(failed).toBe(
      "Reverted on web-1: the check failed. the host said no. The host's rollback was armed and confirmed running before anything was replaced, and was left armed, so ops's previous authorized_keys should be back within 300s of the change. It is restored from /b.bak; if you can still reach the host, that is where to look."
    )
    expect(unconfirmed).toBe(
      "Reverted on web-1: nothing confirmed it in time. nobody was there. That is the dead-man's switch doing its job rather than the change failing — ops's previous authorized_keys is back, the host is exactly as it was, and it can be staged again."
    )
    expect(new Set([committed, failed, unconfirmed]).size).toBe(3)
  })

  it('does not call the third one a failure', async () => {
    // An operator taught that the safety net is a fault is an operator who will
    // want it turned off.
    const unconfirmed = describeAccessOutcome({ ...base, outcome: 'reverted-unconfirmed', reason: 'x.' })
    expect(unconfirmed).toContain('rather than the change failing')
    expect(unconfirmed).toContain('can be staged again')
    expect(unconfirmed).not.toContain('the check failed')
  })
})

describe('the judgement itself', () => {
  const evidence = (over: Partial<AccessCommitEvidence> = {}): AccessCommitEvidence => ({
    session: {
      connectionId: 'fresh#1',
      pooledConnectionIds: ['pooled#1'],
      authenticatedAt: STAGED_AT + 1
    },
    verify: { ok: true, code: 0, stdout: `${ACCESS_VERIFIED_PREFIX}${TOKEN}`, stderr: '' },
    ...over
  })

  const judge = (over: Partial<Parameters<typeof judgeAccessVerification>[0]> = {}): ReturnType<typeof judgeAccessVerification> =>
    judgeAccessVerification({
      token: TOKEN,
      stagedAt: STAGED_AT,
      rollbackSeconds: 300,
      now: STAGED_AT + 2_000,
      evidence: evidence(),
      ...over
    })

  it('commits only when every one of the four conditions holds', async () => {
    expect(judge()).toEqual({ commit: true, outcome: 'committed', reason: '' })
  })

  it('checks the deadline first, because past it nothing else can be true', async () => {
    // The host has already put the old file back and deleted the backup. A
    // marker written now confirms nothing, and reporting `committed` off it
    // would be a lie told to the one person who needs the truth.
    const v = judge({ now: STAGED_AT + 300_000 })
    expect(v.commit).toBe(false)
    expect(v.outcome).toBe('reverted-unconfirmed')
  })

  it('treats a session with no evidence at all as a failed check, never as a pass', async () => {
    expect(judge({ evidence: { session: null, verify: null } }).outcome).toBe('reverted-verification-failed')
    expect(judge({ evidence: evidence({ verify: null }) }).commit).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// The confirmation, actually run against a staged file
// ---------------------------------------------------------------------------
//
// The harness that found five bugs in the write half. Asserting on the text of
// a `[ -f ]` proves nothing about whether a late confirmation can resurrect a
// change the host has already put back.

const trees: string[] = []
afterAll(() => {
  for (const t of trees) rmSync(t, { recursive: true, force: true })
})

const A = 'AAAAC3NzaC1lZDI1NTE5AAAAIJp0kFqDkGDMEnCH7mFY3sBRb+tSVEyKvJhLhZ+SHDdw'
const B = 'AAAAC3NzaC1lZDI1NTE5AAAAIN+Qq8Z0mHqxr4RMlBFPHU6JmsFvNzZYuHkWkQrgnJ2s'

interface Host {
  home: string
  file: string
  run: (command: string) => { code: number; out: string }
  read: () => string
}

function fakeHome(lines: string[]): Host {
  const home = mkdtempSync(join(tmpdir(), 'sp-confirm-'))
  trees.push(home)
  mkdirSync(join(home, '.ssh'), { recursive: true })
  const file = join(home, '.ssh/authorized_keys')
  writeFileSync(file, lines.join('\n'))
  return {
    home,
    file,
    run: (command) => {
      try {
        const out = execFileSync('/bin/sh', ['-c', command], {
          encoding: 'utf8',
          env: { HOME: home, PATH: '/usr/bin:/bin' },
          stdio: ['ignore', 'pipe', 'pipe']
        })
        return { code: 0, out }
      } catch (e) {
        const err = e as { status?: number; stdout?: string; stderr?: string }
        return { code: err.status ?? -1, out: `${err.stdout ?? ''}${err.stderr ?? ''}` }
      }
    },
    read: () => readFileSync(file, 'utf8')
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

describe.skipIf(process.platform === 'win32')('the confirmation, run for real', () => {
  it('finds the staged change and then makes it permanent', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 'c1', expectRemoved: 1, rollbackSeconds: 2 }))

    const v = h.run(accessVerifyCommand('c1'))
    expect(v.code).toBe(0)
    expect(v.out).toContain(`${ACCESS_VERIFIED_PREFIX}c1`)

    const d = h.run(accessDisarmCommand(h.file, 'c1'))
    expect(d.code).toBe(0)
    await sleep(3000)
    expect(h.read()).not.toContain(A)
    expect(h.read()).toContain(B)
  })

  it('refuses to confirm a change that was never staged here', async () => {
    // What a session that landed on the wrong host looks like: it authenticates
    // fine and there is nothing of this change to find.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, ''])
    const v = h.run(accessVerifyCommand('c2'))
    expect(v.code).toBe(3)
    expect(v.out).toContain('no staged change with this token is waiting here')
  })

  it('cannot resurrect a change the host has already put back', async () => {
    // The property the deadline check in judgeAccessVerification mirrors, here
    // on disk. Once the watchdog has fired it deletes the backup, so a late
    // verification fails on the host as well — two independent reasons a
    // confirmation cannot arrive after the fact.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 'c3', expectRemoved: 1, rollbackSeconds: 1 }))
    expect(existsSync(accessBackupPath(h.file, 'c3'))).toBe(true)
    await sleep(2500)
    expect(h.read()).toContain(A)

    const v = h.run(accessVerifyCommand('c3'))
    expect(v.code).toBe(3)
    expect(v.out).toContain('no staged change with this token is waiting here')
  })

  it('refuses to build either command from a token it has not validated', async () => {
    // Both interpolate into a command that runs against authorized_keys. "The
    // only caller passes digits" is a property of this week's callers.
    expect(() => accessVerifyCommand('c3"; rm -rf /; "')).toThrow(/unvalidated/)
    expect(() => accessDisarmCommand('/x', '$(id)')).toThrow(/unvalidated/)
  })

  it('uses no sudo in either', async () => {
    expect(accessVerifyCommand('c4')).not.toMatch(/\bsudo\b/)
    expect(accessDisarmCommand('/x', 'c4')).not.toMatch(/\bsudo\b/)
  })
})
