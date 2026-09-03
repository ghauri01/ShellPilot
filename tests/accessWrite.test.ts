import { describe, it, expect, afterAll } from 'vitest'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  ACCESS_ROLLBACK_SECONDS,
  ACCESS_WRITE_DISABLED_REASON,
  ACCESS_WRITE_ENABLED,
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
import { JOB_KINDS } from '../src/shared/jobs'
import type { JobSpec, JobTargetRef } from '../src/shared/jobs'

describe('the gate that keeps the write half out of this build', () => {
  // GATED OFF, deliberately, and this block is what makes that a property
  // rather than an accident. Adversarial review found five blockers in the plan
  // path and concluded it must not reach an operator testing on a real estate;
  // the read half is close and safe to run today, so the write half is switched
  // off at one named constant and the read half ships.
  //
  // Everything BELOW this block still runs. The builders, the staged write, the
  // rollback and the judgement are all still tested against real files — they
  // are being fixed next, and these tests are the record of what is wrong with
  // them. Deleting them along with the button would delete the evidence.

  it('is off, and turning it on is a decision somebody makes here', () => {
    expect(
      ACCESS_WRITE_ENABLED,
      'ACCESS_WRITE_ENABLED is true. Flipping it re-exposes access:plan and ' +
        'access:run to the UI. The five blockers adversarial review found in ' +
        'the plan path have to be fixed and this test deliberately rewritten ' +
        'first — the point of the constant is that the change cannot happen ' +
        'as a side effect of something else.'
    ).toBe(false)
    // A reason an operator can read, not a boolean on its own. "The buttons
    // vanished" is not an explanation, and an operator who is told nothing
    // assumes the feature is coming rather than that it was withdrawn.
    expect(ACCESS_WRITE_DISABLED_REASON.length).toBeGreaterThan(80)
    expect(ACCESS_WRITE_DISABLED_REASON).toMatch(/roll ?back/i)
  })

  it('is checked in main, in both handlers, before anything is derived', async () => {
    // THE guard that makes this real. The renderer hiding a button is a
    // courtesy; main refusing is the gate, and it covers every caller — a
    // renderer that lies about what it can do, a resumed job, a future bridge.
    //
    // Asserted against the source because the alternative is asserting against
    // an Electron main process, and a check that is deleted from main while the
    // constant stays false is exactly the regression this exists to catch.
    const main = await readFile(resolve(__dirname, '..', 'src/main/index.ts'), 'utf8')
    for (const channel of ['access:plan', 'access:run']) {
      const at = main.indexOf(`ipcMain.handle('${channel}'`)
      expect(at, channel).toBeGreaterThan(-1)
      // Within the first few lines of the handler, before any plan is derived.
      const head = main.slice(at, at + 900)
      expect(head, channel).toContain('ACCESS_WRITE_ENABLED')
      const body = main.slice(at)
      const gate = body.indexOf('ACCESS_WRITE_ENABLED')
      const derive = body.indexOf('deriveAccessPlan')
      expect(
        derive === -1 || gate < derive,
        `${channel} derives a plan before it checks the gate`
      ).toBe(true)
    }
  })
})

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
function host(
  over: {
    /** One entry per factor, exactly as sshd would put it on its own line. */
    authinfo?: string[]
    /** Override the length recorded for every factor, so a truncated blob can
     *  be staged without generating a 2049-character key. */
    authinfoLen?: number
    self?: string
    user?: string
    keysStatus?: string
    /** The AuthorizedKeysFile value sshd is configured with. */
    keyfile?: string
    /** The status the sshd-config source reports. `partial` is a config this
     *  collection read only part of. */
    sshdStatus?: string
    /** What the account's authorized_keys2 probe said. */
    keys2?: 'present' | 'unknown'
  } = {}
): HostAccess {
  const user = over.user ?? 'ops'
  return parseAccessCollection(
    [
      'V tz +0000',
      `V self ${over.self ?? 'ops'}`,
      // `A <length-before-truncation> <factor>`, one per line of
      // SSH_AUTH_INFO_0, which is the record the collector actually emits. The
      // length is what tells a factor that fitted from one that was cut, and
      // passing the real length here is what makes the fixtures below able to
      // lie about it deliberately.
      ...(over.authinfo ?? []).map((f) => `A ${over.authinfoLen ?? f.length} ${f}`),
      `V keyfile AuthorizedKeysFile ${over.keyfile ?? '.ssh/authorized_keys'}`,
      `U 1 keys ${over.keysStatus ?? 'ok'} -`,
      `U 1 path /home/${user}/.ssh/authorized_keys`,
      `U 1 name ${user}`,
      ...(over.keys2 ? [`U 1 keys2 ${over.keys2}`] : []),
      `K 1 1 90 ssh-ed25519 ${A} alice@laptop`,
      `K 1 2 90 ssh-ed25519 ${B} bob@desktop`,
      ACCESS_STATUS_MARKER,
      ...OK_STATUS.map((l) =>
        over.sshdStatus && l.startsWith('sshd-config ')
          ? `sshd-config ${over.sshdStatus} - /etc/ssh/sshd_config`
          : l
      )
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
    const plan = revoke({ targets: [target(host({ authinfo: [`publickey ssh-ed25519 ${A}`] }))] })
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
    const plan = revoke({ targets: [target(host({ authinfo: [`publickey ssh-ed25519 ${A}`] }))] })
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

  it('refuses when the session key is the SECOND factor the host named', async () => {
    // `AuthenticationMethods publickey,publickey`. sshd reports one factor per
    // line of SSH_AUTH_INFO_0, and only the first was ever looked at — so on a
    // two-factor host the second key was unprotected and revocable.
    const plan = revoke({
      fingerprint: B_FP,
      targets: [
        target(host({ self: 'root', user: 'ops', authinfo: [`publickey ssh-ed25519 ${A}`, `publickey ssh-ed25519 ${B}`] }), 'ops')
      ]
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['is-session-key'])
    expect(plan.spec).toBeNull()
  })

  it('refuses conservatively when the key the host named was cut, rather than trusting the stump', async () => {
    // THE BYPASS, at the level it mattered. A blob cut by the collector still
    // decodes — to a different key — so `is-session-key` did not fire, and the
    // list was non-empty so the conservative branch did not fire either. Both
    // rules stepped aside for the same value.
    const cut = host({
      self: 'ops',
      user: 'ops',
      authinfo: [`publickey ssh-ed25519 ${A}`],
      authinfoLen: 9999
    })
    expect(cut.sessionKeyFingerprints).toEqual([])
    expect(cut.sessionKeysCertain).toBe(false)
    const plan = revoke({ fingerprint: B_FP, targets: [target(cut, 'ops')] })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['session-key-unknown'])
    expect(plan.spec).toBeNull()
  })

  it('still refuses that other account when the host names the key and it matches', async () => {
    // The authoritative check is not scoped to the connecting account: a key
    // shared between accounts is still the key this session is on.
    const plan = revoke({
      targets: [target(host({ self: 'root', user: 'ops', authinfo: [`publickey ssh-ed25519 ${A}`] }), 'ops')]
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['is-session-key'])
  })
})

// ---------------------------------------------------------------------------
// Rule 2
// ---------------------------------------------------------------------------

describe('rule 2 — nothing is committed without a second, independent session', () => {
  it('lets exactly one place issue the disarm, and only behind an independent session', async () => {
    // THIS TEST REPLACES ONE THAT FORBADE THE DISARM ENTIRELY, and the reason
    // for the change is the reason the old one was right.
    //
    // What it said: rule 2 is only real if the disarm happens over a connection
    // that authenticated AFTER the write, the job engine cannot provide one
    // because its steps share a pooled transport, and a disarm wired up as
    // another job step would prove only that the writer can still write. All of
    // that is still true. What has changed is that a session which cannot be
    // the pooled one now exists (`sshOpenFresh`), so the invariant is no longer
    // "nothing calls the disarm" — it is "nothing calls the disarm without a
    // fresh session first".
    //
    // Deleting the guard instead of replacing it would have left the strongest
    // argument in this feature enforced by nothing.
    const root = resolve(__dirname, '..', 'src')
    const hits: string[] = []
    const walk = async (dir: string): Promise<void> => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name)
        if (e.isDirectory()) await walk(p)
        else if (/\.tsx?$/.test(e.name)) {
          const text = await readFile(p, 'utf8')
          if (text.includes('accessDisarmCommand')) hits.push(p.slice(root.length + 1))
        }
      }
    }
    await walk(root)
    // Where it is defined, and the one file allowed to issue it. Anything else
    // — a job step, an IPC handler, a renderer button — fails here.
    expect(hits.sort()).toEqual(['main/services/access.ts', 'shared/access.ts'])

    const caller = await readFile(join(root, 'main/services/access.ts'), 'utf8')

    // One call site, so "only behind the judgement" is a statement about one
    // place rather than about whichever place a reader happens to look at.
    expect(caller.split('accessDisarmCommand(')).toHaveLength(2)

    // And it is behind the judgement, in source order: the check is run, the
    // judgement rules on it, and the disarm sits inside the branch that ruling
    // opens. Nothing may be written to the host between the ruling and the
    // confirmation.
    const verify = caller.indexOf('accessVerifyCommand(')
    const judge = caller.indexOf('judgeAccessVerification({')
    const gate = caller.indexOf('if (verdict.commit')
    const disarm = caller.indexOf('accessDisarmCommand(')
    expect(verify).toBeGreaterThan(-1)
    // `judge` is the FIRST occurrence and it is deliberately before the check:
    // the deadline is ruled on before a session is opened at all, because past
    // it the host has already restored itself and a new session would
    // authenticate against the old file. What matters is that both the check
    // and a ruling come before the disarm.
    expect(judge).toBeGreaterThan(-1)
    expect(gate).toBeGreaterThan(verify)
    expect(gate).toBeGreaterThan(judge)
    expect(disarm).toBeGreaterThan(gate)

    // The half the ordering cannot express: this file has no way to REACH a
    // pooled connection. The session arrives injected, so there is no
    // expression here that could confirm a change over the transport that made
    // it — and an edit that wanted to would have to add an import, which is
    // exactly what this sees.
    //
    // Comments are stripped first, because this file ARGUES about `sshExec` and
    // `acquire()` at length and a check that could not tell prose from code
    // would have had to be written weaker or deleted.
    const code = caller.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
    expect(code).not.toMatch(/from '\.\/ssh'/)
    expect(code).not.toMatch(/\bsshExec\b|\bsshExecStream\b|\bacquire\(|\bpoolList\b|\bPooledConnection\b/)
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

  it('arms the watchdog BEFORE the file is replaced, and gates the replacement on it', async () => {
    // Ordering is the whole safety property. Armed after the `mv`, a session
    // that dies in the instant between them leaves the new file in place with
    // nothing watching it — which is the exact failure the watchdog exists for.
    //
    // And ordering ALONE is not enough, which is what the earlier version of
    // this test could not see: the launch was a bare line whose failure was
    // discarded. So the `mv` must also come after the check that the watchdog
    // wrote its arming sentinel.
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).spec!.steps[0]
      .command
    const backup = command.indexOf('cp -p "$SP_F" "$SP_B"')
    const launch = command.indexOf('$SP_L sh -c')
    const proof = command.indexOf('[ -f "$SP_ARM" ] || {')
    const replace = command.indexOf('mv "$SP_T" "$SP_F"')
    expect(backup).toBeGreaterThan(-1)
    expect(launch).toBeGreaterThan(backup)
    expect(proof).toBeGreaterThan(launch)
    expect(replace).toBeGreaterThan(proof)
    // The watchdog's first action is the sentinel, so the sentinel existing
    // means a process is running that holds the backup path and the deadline.
    expect(command).toContain(`sh -c ': > "$3"; sleep`)
    // `disown` is a bashism, and this runs under whatever /bin/sh is there.
    expect(command).not.toMatch(/\bdisown\b/)
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
    expect(spec.steps).toHaveLength(1)
    expect(targets).toHaveLength(1)
  })

  it('is filed as an access change, not as somebody typing a command', async () => {
    // A key change that came back from history indistinguishable from an ad-hoc
    // `systemctl restart nginx` would make the audit trail this whole item
    // exists to produce unfilterable.
    //
    // Asserted against the VALUE list rather than against a type annotation:
    // neither tsconfig includes `tests/`, so a `const k: JobKind = 'access'`
    // here is erased by esbuild and passes whatever `JobKind` says. JOB_KINDS
    // is a real array at runtime, so this fails if the kind is dropped from the
    // union — which is what the assertion is for.
    const plan = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP })
    expect(JOB_KINDS).toEqual(['command', 'patch', 'access'])
    expect(plan.spec!.kind).toBe('access')
    expect(JOB_KINDS).toContain(plan.spec!.kind)
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

  it('refuses a host whose sshd reads only authorized_keys2', async () => {
    // BLOCKER 4. Setting AuthorizedKeysFile REPLACES OpenSSH's default list
    // rather than adding to it. Every path this host names is a member of that
    // list, so the subset check said "the default is in force" and the gate
    // opened — and the staged write then edits `~/.ssh/authorized_keys`, which
    // sshd never opens. Staged, verified, committed, reported done, key still
    // trusted.
    const a = host({ self: 'root', keyfile: '.ssh/authorized_keys2' })
    expect(a.keyFileIsDefault).toBe(true)
    expect(a.readsTheFileWeRead).toBe(false)
    const plan = revoke({ fingerprint: B_FP, targets: [target(a)] })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-the-file-sshd-reads'])
    expect(plan.spec).toBeNull()
  })

  it('refuses a host whose sshd config could only be read in part', async () => {
    // BLOCKER 5's write half. The read half already downgrades this source to
    // `partial` and takes `keyFileIsDefault` to null; what matters here is that
    // the GATE consumes it rather than merely putting a banner on a screen.
    const a = host({ self: 'root', sshdStatus: 'partial' })
    expect(a.readsTheFileWeRead).toBeNull()
    const plan = revoke({ fingerprint: B_FP, targets: [target(a)] })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-the-file-sshd-reads'])
    expect(plan.spec).toBeNull()
  })

  it('refuses an account that has a legacy authorized_keys2 sshd also reads', async () => {
    // The same "reported done and did nothing" failure from the other side: on
    // a host that IS on the compiled-in default, sshd reads keys2 too, and a
    // key written into both files survives an edit to one of them.
    const plan = revoke({
      fingerprint: B_FP,
      targets: [
        target(host({ self: 'root', keys2: 'present', keyfile: '.ssh/authorized_keys .ssh/authorized_keys2' }))
      ]
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-the-file-sshd-reads'])
    expect(plan.blocks[0].reason).toContain('authorized_keys2')
  })

  it('refuses an account whose authorized_keys2 could not be checked', async () => {
    // "Nobody could look" is not "it is not there".
    const plan = revoke({
      fingerprint: B_FP,
      targets: [
        target(host({ self: 'root', keys2: 'unknown', keyfile: '.ssh/authorized_keys .ssh/authorized_keys2' }))
      ]
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-the-file-sshd-reads'])
    expect(plan.blocks[0].reason).toContain('could not be checked')
  })

  it('does not block a legacy file on a host whose sshd does not read one', async () => {
    // The over-block this would otherwise be. `AuthorizedKeysFile
    // .ssh/authorized_keys` alone means keys2 is not read, so its presence
    // changes nothing about who can log in.
    const plan = revoke({
      fingerprint: B_FP,
      targets: [target(host({ self: 'root', keys2: 'present', keyfile: '.ssh/authorized_keys' }))]
    })
    expect(plan.blocks).toEqual([])
    expect(plan.spec).not.toBeNull()
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
    // The ADD path, which this test never fed to the regex — so prefixing
    // `sudo -n true; ` to buildAddKeyCommand's staged write passed it, and
    // passed every other test in this file too. Both builders are reached
    // directly rather than through a plan, because the plan is one `if` away
    // from only ever producing the revoke half.
    expect(
      buildAddKeyCommand({ path: '/x', line: `ssh-ed25519 ${B} added`, token: '1' })
    ).not.toMatch(/\bsudo\b/)
    expect(
      buildRevokeKeyCommand({ path: '/x', blob: B, token: '1', expectRemoved: 1 })
    ).not.toMatch(/\bsudo\b/)
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
  run: (command: string, opts?: { shim?: Record<string, string>; onlyShim?: boolean }) => {
    code: number
    out: string
  }
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
    // `shim` puts a directory of stub programs in FRONT of the real PATH, which
    // is how a host that cannot detach a surviving process is reproduced here:
    // a `nohup` that exits 127 is exactly what a busybox image without it looks
    // like, and it stands in for the case that actually happens —
    // systemd-logind with KillUserProcesses=yes, where the watchdog is
    // SIGKILLed with the session rather than never starting.
    //
    // `onlyShim` drops the real PATH entirely except for the handful of tools
    // the staged write itself needs, so "this host has no launcher at all" can
    // be told from "its launcher failed".
    run: (command, { shim = {}, onlyShim = false } = {}) => {
      const dir = mkdtempSync(join(tmpdir(), 'sp-shim-'))
      trees.push(dir)
      for (const [name, body] of Object.entries(shim)) {
        writeFileSync(join(dir, name), `#!/bin/sh\n${body}\n`)
        chmodSync(join(dir, name), 0o755)
      }
      if (onlyShim) {
        for (const tool of ['cp', 'mv', 'rm', 'grep', 'chmod', 'sleep', 'cmp', 'tail', 'ls']) {
          for (const from of [`/bin/${tool}`, `/usr/bin/${tool}`]) {
            if (existsSync(from) && !existsSync(join(dir, tool))) symlinkSync(from, join(dir, tool))
          }
        }
      }
      try {
        const out = execFileSync('/bin/sh', ['-c', command], {
          encoding: 'utf8',
          env: { HOME: home, PATH: onlyShim ? dir : `${dir}:/usr/bin:/bin` },
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

  // -------------------------------------------------------------------------
  // The watchdog has to be PROVED armed, not merely launched
  // -------------------------------------------------------------------------
  //
  // The launch used to be a bare line in a `\n`-joined script with no `set -e`
  // and no `&&`, so its failure was discarded and the `mv` ran regardless. The
  // realistic trigger is not a missing `nohup`: it is systemd-logind with
  // KillUserProcesses=yes — the upstream default on RHEL 8/9, CentOS Stream and
  // Fedora — which SIGKILLs the whole user slice when the exec channel closes.
  // On those hosts the dead-man's switch died with the session every time,
  // while `describeAccessOutcome` went on telling the operator their previous
  // file was back.

  it('changes nothing when the watchdog cannot be started', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w1', expectRemoved: 1, rollbackSeconds: 60 }),
      { shim: { nohup: 'exit 127', setsid: 'exit 127', 'systemd-run': 'exit 127' } }
    )
    expect(r.code).not.toBe(0)
    expect(r.out).toContain('nothing was changed')
    // THE assertion. Not "it printed a warning" — the file is untouched, and
    // the STAGED line that promises a rollback was never printed.
    expect(h.read()).toBe(before)
    expect(r.out).not.toContain('STAGED:')
    // And it does not leave the half-built replacement behind.
    expect(readdirSync(join(h.home, '.ssh')).filter((n) => n.endsWith('.new'))).toEqual([])
  })

  it('changes nothing when the watchdog starts and is killed before it can arm', async () => {
    // What KillUserProcesses actually looks like: the launcher works, the
    // process starts, and something kills it. The arming sentinel is the
    // watchdog's own first action, so a watchdog that is not running has not
    // written one.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w2', expectRemoved: 1, rollbackSeconds: 60 }),
      { shim: { nohup: 'exit 0', setsid: 'exit 0', 'systemd-run': 'exit 0' } }
    )
    expect(r.code).not.toBe(0)
    expect(h.read()).toBe(before)
    expect(r.out).not.toContain('STAGED:')
  })

  it('changes nothing on a host with no way to detach a process at all', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w3', expectRemoved: 1, rollbackSeconds: 60 }),
      { onlyShim: true }
    )
    expect(r.code).not.toBe(0)
    expect(r.out).toMatch(/no way to leave a process running/)
    expect(h.read()).toBe(before)
  })

  it('says in the job output how the rollback was detached', async () => {
    // The strength of the guarantee differs between launchers and the
    // difference is recorded rather than smoothed over, exactly as the detached
    // job engine records it. An operator reading the pane can tell a scope that
    // survives a logind kill from a `nohup` that only survives SIGHUP.
    const h = fakeHome([`ssh-ed25519 ${A} a`, `ssh-ed25519 ${B} b`, ''])
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w4', expectRemoved: 1, rollbackSeconds: 60 })
    )
    expect(r.code).toBe(0)
    expect(r.out).toMatch(/STAGED:/)
    expect(r.out).toMatch(/rollback is running under (systemd-run|setsid|nohup)/)
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
