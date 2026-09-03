import { describe, it, expect, afterAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  ACCESS_ROLLBACK_SECONDS,
  ACCESS_STATUS_MARKER,
  accessCommitMarker,
  accessDisarmCommand,
  buildAddKeyCommand,
  buildRevokeKeyCommand,
  parseAccessCollection,
  planAccessChange,
  type AccessChangeTarget,
  type HostAccess,
  type Sha256
} from '../src/shared/access'
import type { JobSpec, JobTargetRef } from '../src/shared/jobs'

// The write half — roadmap item 23, stage 2.
//
// This is the highest-consequence write the app can make: a bad one locks you
// out of the host you would use to fix it, and rolled across a selection it
// locks you out of all of them in the order they were healthy.
//
// So there are three rules and each of them has its own test here, and none of
// those tests asserts on the text of a command where it could assert on what
// the command DID. Rules 2 and 3 are exercised by running the real staged
// write against a real file and watching the host put it back.

const sha256: Sha256 = (data) => new Uint8Array(createHash('sha256').update(data).digest())

const A = 'AAAAC3NzaC1lZDI1NTE5AAAAIJp0kFqDkGDMEnCH7mFY3sBRb+tSVEyKvJhLhZ+SHDdw'
const A_FP = 'SHA256:wVlk8sEGn2qqP1yFjdkoYGu+eWPmKJ/koiL8zATTjxI'
const B = 'AAAAC3NzaC1lZDI1NTE5AAAAIN+Qq8Z0mHqxr4RMlBFPHU6JmsFvNzZYuHkWkQrgnJ2s'
const B_FP = 'SHA256:Kh/dB+J46zzk3b+72O1DqnLW16xNkYitzUOrofTSSL8'

const OK_STATUS = [
  'accounts ok -',
  'sshd-config ok - /etc/ssh/sshd_config',
  'account-status ok -',
  'sudoers ok -',
  'last-login ok - lastlog'
]

/** A collection, through the real parser. Two keys on `ops`, sshd on the
 *  default key file, and by default the host does not say which key we are on —
 *  which is what most hosts actually do. */
function host(over: { authinfo?: string; self?: string; user?: string; keysStatus?: string } = {}): HostAccess {
  const user = over.user ?? 'ops'
  return parseAccessCollection(
    [
      'V tz +0000',
      `V self ${over.self ?? 'ops'}`,
      ...(over.authinfo ? [`V authinfo ${over.authinfo}`] : []),
      'V keyfile AuthorizedKeysFile .ssh/authorized_keys',
      `U 1 keys ${over.keysStatus ?? 'ok'} -`,
      `U 1 path /home/${user}/.ssh/authorized_keys`,
      `U 1 name ${user}`,
      `K 1 1 90 ssh-ed25519 ${A} alice@laptop`,
      `K 1 2 90 ssh-ed25519 ${B} bob@desktop`,
      ACCESS_STATUS_MARKER,
      ...OK_STATUS
    ].join('\n'),
    { sha256, now: 1_800_000_000_000 }
  )
}

const target = (access: HostAccess, user = 'ops'): AccessChangeTarget => ({
  serverId: 'a',
  serverName: 'web-1',
  access,
  user
})

const revoke = (o: Partial<Parameters<typeof planAccessChange>[0]> = {}): ReturnType<typeof planAccessChange> =>
  planAccessChange({
    kind: 'revoke',
    fingerprint: A_FP,
    targets: [target(host())],
    now: 1_800_000_000_000,
    ...o
  })

// ---------------------------------------------------------------------------
// Rule 1
// ---------------------------------------------------------------------------

describe('rule 1 — never remove the key this session is on', () => {
  it('refuses when the host says that key is the one we authenticated with', async () => {
    // sshd's own answer, via SSH_AUTH_INFO_0. The only authoritative source, and
    // where it exists the check is exact rather than a guess.
    const plan = revoke({ targets: [target(host({ authinfo: `publickey ssh-ed25519 ${A}` }))] })
    expect(plan.spec).toBeNull()
    expect(plan.blocks.map((b) => b.kind)).toEqual(['is-session-key'])
    expect(plan.blocks[0].reason).toContain('own way back into the host')
  })

  it('refuses a fingerprint the caller named as protected', async () => {
    const plan = revoke({ protect: [A_FP] })
    expect(plan.spec).toBeNull()
    expect(plan.blocks.map((b) => b.kind)).toEqual(['is-session-key'])
  })

  it('is a block, not a warning — there is no shape here that can be clicked past', async () => {
    // A rule with an override is a default. `planAccessChange` returns blocks
    // and nothing else: there is no severity, no acknowledgement, no field a
    // caller could set to proceed anyway.
    const plan = revoke({ targets: [target(host({ authinfo: `publickey ssh-ed25519 ${A}` }))] })
    expect(Object.keys(plan.blocks[0]).sort()).toEqual(['kind', 'reason', 'serverId', 'serverName', 'user'])
    expect(plan.targets).toEqual([])
    expect(plan.disarm).toEqual([])
  })

  it('refuses to touch the connecting account at all when the host will not say', async () => {
    // ExposeAuthInfo is off by default, so this is what most hosts look like.
    // Without that fact nothing can prove the key being removed is not the one
    // holding the connection open — so the account ShellPilot connects as is
    // off limits.
    const plan = revoke({ fingerprint: B_FP, targets: [target(host({ self: 'ops' }), 'ops')] })
    expect(plan.spec).toBeNull()
    expect(plan.blocks.map((b) => b.kind)).toEqual(['session-key-unknown'])
    expect(plan.blocks[0].reason).toContain('ExposeAuthInfo')
  })

  it('does NOT over-block: another account’s key cannot lock this session out', async () => {
    // The other half of the rule, and the half that keeps it from being either
    // useless or a lie. If the rule blocked every revoke on a host with
    // ExposeAuthInfo off, the feature would not exist on most hosts — and the
    // reason to block is lockout, which another account's keys cannot cause.
    const plan = revoke({
      fingerprint: B_FP,
      targets: [target(host({ self: 'root', user: 'ops' }), 'ops')]
    })
    expect(plan.blocks).toEqual([])
    expect(plan.spec).not.toBeNull()
    expect(plan.targets.map((t) => t.serverId)).toEqual(['a'])
  })

  it('still refuses that other account when the host names the key and it matches', async () => {
    // The authoritative check is not scoped to the connecting account: a key
    // shared between accounts is still the key this session is on.
    const plan = revoke({
      targets: [target(host({ self: 'root', user: 'ops', authinfo: `publickey ssh-ed25519 ${A}` }), 'ops')]
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['is-session-key'])
  })
})

// ---------------------------------------------------------------------------
// Rule 2
// ---------------------------------------------------------------------------

describe('rule 2 — nothing is committed without a second, independent session', () => {
  it('ships no caller for the disarm anywhere in the source tree', async () => {
    // The refusal, in the shape docker.ts uses for `prune`. Rule 2 is only real
    // if the disarm happens over a connection that authenticated AFTER the
    // write, and the job engine cannot provide one — its steps share a pooled,
    // already-authenticated transport. A disarm wired up as another job step
    // would turn this rule into a comment, so the disarm exists, is tested, and
    // is called by nothing.
    const root = resolve(__dirname, '..', 'src')
    const hits: string[] = []
    const walk = async (dir: string): Promise<void> => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name)
        if (e.isDirectory()) await walk(p)
        else if (/\.tsx?$/.test(e.name)) {
          const text = await readFile(p, 'utf8')
          // The definition itself is in shared/access.ts; any OTHER mention is a
          // caller and this test is why it has to be argued for.
          if (text.includes('accessDisarmCommand') && !p.endsWith('shared/access.ts')) hits.push(p)
        }
      }
    }
    await walk(root)
    expect(hits, `something now issues the disarm: ${hits.join(', ')}`).toEqual([])
  })

  it('puts nothing permanent in the job the engine would run', async () => {
    const plan = revoke({ targets: [target(host({ self: 'root' }))] , fingerprint: B_FP })
    const command = plan.spec!.steps[0].command
    expect(command).not.toContain(accessCommitMarker(plan.token) + '"\n: >')
    // The job stages and arms. The only thing that makes the change permanent
    // is the marker, and the job never creates it.
    expect(command).toContain('rm -f "$SP_M"')
    expect(command).not.toMatch(/^: > "\$SP_M"/m)
    expect(accessDisarmCommand('/home/ops/.ssh/authorized_keys', plan.token)).toContain(': > "$SP_M"')
  })

  it('arms the watchdog BEFORE the file is replaced', async () => {
    // Ordering is the whole safety property. Armed after the `mv`, a session
    // that dies in the instant between them leaves the new file in place with
    // nothing watching it — which is the exact failure the watchdog exists for.
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).spec!.steps[0]
      .command
    expect(command.indexOf('nohup sh -c')).toBeLessThan(command.indexOf('mv "$SP_T" "$SP_F"'))
    expect(command.indexOf('nohup sh -c')).toBeGreaterThan(command.indexOf('cp -p "$SP_F" "$SP_B"'))
  })

  it('tells the operator in the job output that the change is not permanent', async () => {
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).spec!.steps[0]
      .command
    expect(command).toContain('STAGED:')
    expect(command).toContain('will be put back automatically')
    expect(command).toContain(`${ACCESS_ROLLBACK_SECONDS}s`)
  })

  it('is a real JobSpec, checked here because access.ts may not import one', async () => {
    // src/shared/access.ts declares the spec shape structurally: it is reached
    // from the fleet sampler, which the MCP bridge reads, and
    // tests/jobsNotExposed.test.ts fails if anything in that closure imports the
    // job engine. This file is allowed to import both, so the two shapes are
    // reconciled here — a drift between them is a compile error rather than a
    // spec the runner would reject at three in the morning.
    const plan = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP })
    const spec: JobSpec = plan.spec!
    const targets: JobTargetRef[] = plan.targets
    expect(spec.kind).toBe('command')
    expect(targets).toHaveLength(1)
  })

  it('runs one host at a time', async () => {
    // A key change rolled across a selection in parallel is the case where a
    // mistake reaches every machine before the first failure is visible.
    const plan = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP })
    expect(plan.spec!.concurrency).toBe(1)
  })

  it('is one command for the whole job, so the approval record can be compared', async () => {
    // verifyApproval compares step text. A spec whose command was substituted
    // per host could not be checked against the record at all, so the path is
    // resolved from $HOME on the host rather than interpolated here.
    const plan = revoke({
      fingerprint: B_FP,
      targets: [
        target(host({ self: 'root' })),
        { ...target(host({ self: 'root' })), serverId: 'b', serverName: 'web-2' }
      ]
    })
    expect(plan.spec!.steps).toHaveLength(1)
    expect(plan.spec!.steps[0].command).toContain('SP_F="$HOME/.ssh/authorized_keys"')
    expect(plan.spec!.steps[0].command).not.toContain('/home/ops')
    expect(plan.targets.map((t) => t.serverId)).toEqual(['a', 'b'])
  })
})

// ---------------------------------------------------------------------------
// Rule 3
// ---------------------------------------------------------------------------

describe('rule 3 — always leave a timestamped backup on the host', () => {
  it('copies the file before anything else touches it', async () => {
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).spec!.steps[0]
      .command
    const backup = command.indexOf('cp -p "$SP_F" "$SP_B"')
    expect(backup).toBeGreaterThan(-1)
    expect(backup).toBeLessThan(command.indexOf('grep -v -F'))
    expect(backup).toBeLessThan(command.indexOf('mv "$SP_T" "$SP_F"'))
    // Named with the change's own token, so two changes cannot overwrite each
    // other's backup and a person can tell which is which in a shell.
    expect(command).toContain('.shellpilot-1800000000000.bak')
  })
})

// ---------------------------------------------------------------------------
// What the planner refuses
// ---------------------------------------------------------------------------

describe('what a change refuses to be', () => {
  it('refuses to edit an account whose file was not read', async () => {
    const plan = revoke({ targets: [target(host({ self: 'root', keysStatus: 'denied' }))] })
    expect(plan.spec).toBeNull()
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-read'])
  })

  it('refuses when sshd is not known to read the file being edited', async () => {
    // A revocation that is reported as done and did nothing is worse than none.
    const a = parseAccessCollection(
      [
        'V self root',
        'V keycmd AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys',
        'U 1 keys ok -',
        'U 1 path /home/ops/.ssh/authorized_keys',
        'U 1 name ops',
        `K 1 1 90 ssh-ed25519 ${A} alice@laptop`,
        ACCESS_STATUS_MARKER,
        ...OK_STATUS
      ].join('\n'),
      { sha256, now: 1 }
    )
    const plan = revoke({ targets: [target(a)] })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-the-file-sshd-reads'])
  })

  it('leaves out a host the key is not on rather than counting it as revoked', async () => {
    const plan = revoke({
      fingerprint: 'SHA256:notonanyhostanywhere',
      targets: [target(host({ self: 'root' }))]
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-present'])
    expect(plan.spec).toBeNull()
  })

  it('refuses to add a key that is already there', async () => {
    const plan = planAccessChange({
      kind: 'add',
      keyLine: `ssh-ed25519 ${A} alice@laptop`,
      targets: [target(host({ self: 'root' }))],
      now: 1
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['already-present'])
  })

  it('refuses a key line carrying anything that could change meaning in a shell', async () => {
    for (const bad of [
      `ssh-ed25519 ${A} a"b`,
      `ssh-ed25519 ${A} $(whoami)`,
      "ssh-ed25519 " + A + " a'; rm -rf /; '",
      `ssh-ed25519 ${A} \`id\``,
      `command="x" ssh-ed25519 ${A} c`
    ]) {
      const plan = planAccessChange({
        kind: 'add',
        keyLine: bad,
        targets: [target(host({ self: 'root' }))],
        now: 1
      })
      expect(plan.spec, bad).toBeNull()
      expect(plan.blocks[0].kind, bad).toBe('not-read')
    }
  })

  it('refuses to build a removal from a body it has not validated', async () => {
    // The last line of defence, at the point the value reaches a command. It
    // throws rather than returning a plan, because a caller that got here has a
    // bug and a bug that writes authorized_keys should not degrade quietly.
    expect(() =>
      buildRevokeKeyCommand({ path: '/x', blob: "AAAA'; rm -rf /; '", token: '1', expectRemoved: 1 })
    ).toThrow(/unvalidated/)
    expect(() => buildAddKeyCommand({ path: '/x', line: 'ssh-ed25519 $(id) x', token: '1' })).toThrow(
      /unvalidated/
    )
  })

  it('uses no sudo anywhere in a write', async () => {
    // The read half escalates because reading another account's key file is
    // normal. An escalated WRITE is one nobody watching the sudo log can tell
    // from an attacker with the same access.
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).spec!.steps[0]
      .command
    expect(command).not.toMatch(/\bsudo\b/)
    expect(accessDisarmCommand('/x', '1')).not.toMatch(/\bsudo\b/)
  })
})

// ---------------------------------------------------------------------------
// The staged write, actually run
// ---------------------------------------------------------------------------
//
// Rules 2 and 3 are about what happens on disk, and asserting on the text of a
// `cp` proves nothing about whether the backup landed. These run the real
// command through /bin/sh against a real file, with the rollback deadline
// shortened so the watchdog can be watched.

const trees: string[] = []
afterAll(() => {
  for (const t of trees) rmSync(t, { recursive: true, force: true })
})

interface Fake {
  home: string
  file: string
  run: (command: string) => { code: number; out: string }
  read: () => string
  backups: () => string[]
}

function fakeHome(lines: string[]): Fake {
  const home = mkdtempSync(join(tmpdir(), 'sp-write-'))
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
    read: () => readFileSync(file, 'utf8'),
    backups: () => readdirSync(join(home, '.ssh')).filter((n) => n.endsWith('.bak'))
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

describe.skipIf(process.platform === 'win32')('the staged write, run for real', () => {
  it('removes exactly the key asked for and leaves a backup of the old file', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 't1', expectRemoved: 1, rollbackSeconds: 60 })
    )
    expect(r.code).toBe(0)
    expect(h.read()).toContain(B)
    expect(h.read()).not.toContain(A)
    // RULE 3, on disk rather than in a string.
    expect(h.backups()).toEqual(['authorized_keys.shellpilot-t1.bak'])
    expect(readFileSync(join(h.home, '.ssh', h.backups()[0]), 'utf8')).toContain(A)
  })

  it('puts the file back by itself when nobody confirms the change', async () => {
    // RULE 2, watched rather than asserted. This is the only property that
    // survives ShellPilot being the thing that is locked out.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't2', expectRemoved: 1, rollbackSeconds: 1 }))
    expect(h.read()).not.toContain(A)
    await sleep(2500)
    expect(h.read()).toContain(A)
    expect(h.read()).toContain(B)
    // And it cleans up after itself: no backup left behind once it has been used.
    expect(existsSync(join(h.home, '.ssh/authorized_keys.shellpilot-t2.bak'))).toBe(false)
  })

  it('leaves the change alone once a confirmation lands', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't3', expectRemoved: 1, rollbackSeconds: 1 }))
    const d = h.run(accessDisarmCommand(h.file, 't3'))
    expect(d.code).toBe(0)
    expect(d.out).toContain('COMMITTED')
    await sleep(2500)
    expect(h.read()).not.toContain(A)
    expect(h.read()).toContain(B)
  })

  it('appends without gluing itself onto a file that has no trailing newline', async () => {
    // Plenty of authorized_keys files ship without one. Appending to such a file
    // without adding it first makes one malformed line out of two keys — which
    // silently removes the key that was already working.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`])
    expect(h.read().endsWith('\n')).toBe(false)
    const r = h.run(
      buildAddKeyCommand({ path: h.file, line: `ssh-ed25519 ${B} bob@desktop`, token: 't4', rollbackSeconds: 60 })
    )
    expect(r.code).toBe(0)
    const lines = h.read().split('\n').filter((l) => l !== '')
    expect(lines).toHaveLength(2)
    expect(lines[0]).toContain(A)
    expect(lines[1]).toContain(B)
  })

  it('changes nothing when the resulting file is the wrong size', async () => {
    // The count is checked BEFORE the replacement, so a filter that did
    // something nobody asked for never becomes the live file at all.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${A} alice@second-machine`, ''])
    const before = h.read()
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 't5', expectRemoved: 1, rollbackSeconds: 60 })
    )
    expect(r.code).toBe(4)
    expect(r.out).toContain('nothing was changed')
    expect(h.read()).toBe(before)
  })

  it('revokes the last key on an account, leaving it trusting nobody', async () => {
    // `grep -v` exits 1 when it selects no lines, which is exactly what this
    // looks like. Treated as a failure it turns the most final revocation there
    // is into "the new file could not be built" — and the count check that
    // would have caught a real problem never runs.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, ''])
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 't9', expectRemoved: 1, rollbackSeconds: 60 })
    )
    expect(r.code).toBe(0)
    expect(h.read().trim()).toBe('')
    expect(readFileSync(join(h.home, '.ssh/authorized_keys.shellpilot-t9.bak'), 'utf8')).toContain(A)
  })

  it('changes nothing when the backup cannot be written', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, ''])
    const before = h.read()
    chmodSync(join(h.home, '.ssh'), 0o500)
    try {
      const r = h.run(
        buildRevokeKeyCommand({ path: h.file, blob: A, token: 't6', expectRemoved: 1, rollbackSeconds: 60 })
      )
      expect(r.code).toBe(3)
      expect(r.out).toContain('nothing was changed')
      expect(h.read()).toBe(before)
    } finally {
      chmodSync(join(h.home, '.ssh'), 0o700)
    }
  })

  it('changes nothing when there is no authorized_keys to change', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} x`, ''])
    rmSync(h.file)
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 't7', expectRemoved: 1, rollbackSeconds: 60 })
    )
    expect(r.code).toBe(3)
    expect(existsSync(h.file)).toBe(false)
  })

  it('leaves the new file private', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} a`, `ssh-ed25519 ${B} b`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't8', expectRemoved: 1, rollbackSeconds: 60 }))
    const mode = execFileSync('/bin/sh', ['-c', `ls -l "${h.file}" | cut -c1-10`], { encoding: 'utf8' }).trim()
    expect(mode).toBe('-rw-------')
  })
})
