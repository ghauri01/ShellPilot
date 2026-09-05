import { describe, it, expect, afterAll, afterEach, vi } from 'vitest'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  lstatSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  ACCESS_ROLLBACK_SECONDS,
  ACCESS_WRITE_DISABLED_REASON,
  ACCESS_WRITE_OPT_IN_NOTE,
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

  it('ships off, so nothing turns it on by upgrading', () => {
    expect(
      ACCESS_WRITE_ENABLED,
      'ACCESS_WRITE_ENABLED is true, which would expose adding and revoking ' +
        'keys to every install on upgrade rather than to the operator who ' +
        'chose it. It is the DEFAULT now, not the whole gate — the opt-in is ' +
        'settings.accessWriteEnabled and main enforces that, so this staying ' +
        'false is what keeps the decision an operator’s rather than a release’s.'
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
      // The symbol changed from the build constant to the main-side gate that
      // also reads the operator's setting. What is asserted is unchanged: the
      // check is IN main, in both handlers, before anything is derived.
      expect(head, channel).toContain('isAccessWriteEnabled()')
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
/** A certificate issued over A, from `ssh-keygen -s`. `ssh-keygen -l` prints
 *  A_FP for it, because the identity a certificate carries is the key inside
 *  it — which is what makes one account trusting a key both ways two lines for
 *  one fingerprint. */
const A_CERT =
  'AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIE5sEAlyPV1++W59JEopEdVFkHQoYhIBHwPFqhLWRsG8AAAAIJp0kFqDkGDMEnCH7mFY3sBRb+tSVEyKvJhLhZ+SHDdwAAAAAAAAAAAAAAABAAAABWFsaWNlAAAABwAAAANvcHMAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgC1t8okOlkmDdbBmTjonaV3e1b/UQXSOqXUeUB1CLC6EAAABTAAAAC3NzaC1lZDI1NTE5AAAAQL7SnZp8XxA+3UK/Er7VX+slWP8Cl8Fm2rF2PJaXKixm8fFVC36Rv9iYu6vhJJIcv5BfSxQ7FZ9Fnw96EiddVwY='

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
  it('refuses when the server says that key is the one we authenticated with', async () => {
    // sshd's own answer, via SSH_AUTH_INFO_0. The only authoritative source, and
    // where it exists the check is exact rather than a guess.
    const plan = revoke({ targets: [target(host({ authinfo: [`publickey ssh-ed25519 ${A}`] }))] })
    expect(plan.write).toBeNull()
    expect(plan.blocks.map((b) => b.kind)).toEqual(['is-session-key'])
    expect(plan.blocks[0].reason).toContain('own way back into the server')
  })

  it('refuses a fingerprint the caller named as protected', async () => {
    const plan = revoke({ protect: [A_FP] })
    expect(plan.write).toBeNull()
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

  it('refuses to touch the connecting account at all when the server will not say', async () => {
    // ExposeAuthInfo is off by default, so this is what most hosts look like.
    // Without that fact nothing can prove the key being removed is not the one
    // holding the connection open — so the account ShellPilot connects as is
    // off limits.
    const plan = revoke({ fingerprint: B_FP, targets: [target(host({ self: 'ops' }), 'ops')] })
    expect(plan.write).toBeNull()
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
    expect(plan.write).not.toBeNull()
    expect(plan.targets.map((t) => t.serverId)).toEqual(['a'])
  })

  it('refuses when the session key is the SECOND factor the server named', async () => {
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
    expect(plan.write).toBeNull()
  })

  it('refuses conservatively when the key the server named was cut, rather than trusting the stump', async () => {
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
    expect(plan.write).toBeNull()
  })

  it('still refuses that other account when the server names the key and it matches', async () => {
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
    const command = plan.write!.command
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
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).write!.command
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
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).write!.command
    expect(command).toContain('STAGED:')
    expect(command).toContain('will be put back automatically')
    expect(command).toContain(`${ACCESS_ROLLBACK_SECONDS}s`)
  })

  it('runs one server at a time', async () => {
    // A key change rolled across a selection in parallel is the case where a
    // mistake reaches every machine before the first failure is visible;
    // serialised, the second host is still reachable while the first is being
    // looked at.
    //
    // Asserted against main rather than against a `concurrency: 1` on a spec no
    // runner was ever handed. The serialisation is a `for` loop with an `await`
    // in it, and the thing that would break it is somebody reaching for
    // `Promise.all` — which is what this sees.
    const main = await readFile(resolve(__dirname, '..', 'src/main/index.ts'), 'utf8')
    const at = main.indexOf("ipcMain.handle('access:run'")
    const body = main.slice(at, main.indexOf('ipcMain.handle(', at + 10))
    expect(body).toContain('for (const target of plan.targets)')
    expect(body).toContain('await sshExec(')
    expect(body).not.toMatch(/Promise\.(all|allSettled|race)/)
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
    expect(plan.write!.command).toContain('SP_F="$HOME/.ssh/authorized_keys"')
    expect(plan.write!.command).not.toContain('/home/ops')
    expect(plan.targets.map((t) => t.serverId)).toEqual(['a', 'b'])
  })
})

// ---------------------------------------------------------------------------
// Rule 3
// ---------------------------------------------------------------------------

describe('rule 3 — always leave a timestamped backup on the server', () => {
  it('copies the file before anything else touches it', async () => {
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).write!.command
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
    expect(plan.write).toBeNull()
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

  it('refuses a server whose sshd reads only authorized_keys2', async () => {
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
    expect(plan.write).toBeNull()
  })

  it('refuses a server whose sshd config could only be read in part', async () => {
    // BLOCKER 5's write half. The read half already downgrades this source to
    // `partial` and takes `keyFileIsDefault` to null; what matters here is that
    // the GATE consumes it rather than merely putting a banner on a screen.
    const a = host({ self: 'root', sshdStatus: 'partial' })
    expect(a.readsTheFileWeRead).toBeNull()
    const plan = revoke({ fingerprint: B_FP, targets: [target(a)] })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-the-file-sshd-reads'])
    expect(plan.write).toBeNull()
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

  it('does not block a legacy file on a server whose sshd does not read one', async () => {
    // The over-block this would otherwise be. `AuthorizedKeysFile
    // .ssh/authorized_keys` alone means keys2 is not read, so its presence
    // changes nothing about who can log in.
    const plan = revoke({
      fingerprint: B_FP,
      targets: [target(host({ self: 'root', keys2: 'present', keyfile: '.ssh/authorized_keys' }))]
    })
    expect(plan.blocks).toEqual([])
    expect(plan.write).not.toBeNull()
  })

  it('leaves out a server the key is not on rather than counting it as revoked', async () => {
    const plan = revoke({
      fingerprint: 'SHA256:notonanyhostanywhere',
      targets: [target(host({ self: 'root' }))]
    })
    expect(plan.blocks.map((b) => b.kind)).toEqual(['not-present'])
    expect(plan.write).toBeNull()
  })

  it('refuses a key trusted both plainly and through a certificate, and says which', async () => {
    // A certificate line fingerprints to the key INSIDE it and deliberately
    // keeps no body, so an account trusting a key both ways has two lines for
    // one fingerprint and one removable body. Removing the plain line would
    // leave the certificate — and the key still trusted — while the report said
    // revoked.
    const a = parseAccessCollection(
      [
        'V self root',
        'V keyfile AuthorizedKeysFile .ssh/authorized_keys',
        'U 1 keys ok -',
        'U 1 path /home/ops/.ssh/authorized_keys',
        'U 1 name ops',
        `K 1 1 90 ssh-ed25519 ${A} alice@laptop`,
        `K 1 2 700 ssh-ed25519-cert-v01@openssh.com ${A_CERT} alice@laptop`,
        ACCESS_STATUS_MARKER,
        ...OK_STATUS
      ].join('\n'),
      { sha256, now: 1 }
    )
    // The fixture is only worth anything if both lines really do carry the one
    // fingerprint.
    expect(a.accounts[0].keys!.map((k) => k.fingerprint)).toEqual([A_FP, A_FP])
    const plan = revoke({ targets: [target(a)] })
    expect(plan.write).toBeNull()
    expect(plan.blocks[0].reason).toContain('certificate')
    expect(plan.blocks[0].reason).not.toContain('not in a form')
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
      expect(plan.write, bad).toBeNull()
      expect(plan.blocks[0].kind, bad).toBe('not-read')
    }
  })

  it('refuses to build a removal from a body it has not validated', async () => {
    // The last line of defence, at the point the value reaches a command. It
    // throws rather than returning a plan, because a caller that got here has a
    // bug and a bug that writes authorized_keys should not degrade quietly.
    expect(() =>
      buildRevokeKeyCommand({ path: '/x', blob: "AAAA'; rm -rf /; '", token: '1' })
    ).toThrow(/unvalidated/)
    expect(() => buildAddKeyCommand({ path: '/x', line: 'ssh-ed25519 $(id) x', token: '1' })).toThrow(
      /unvalidated/
    )
  })

  it('refuses to build a write from a token it has not validated', async () => {
    // The token is interpolated into four paths in a command that replaces
    // `authorized_keys`. `TOKEN_RE` was applied to the two READ-ONLY commands
    // and not to the two that write, which is precisely backwards: the doc
    // comment argues for validating it and then guards the harmless pair.
    for (const bad of ["1; rm -rf ~", '../../../etc/ssh/x', 'a b', '', 'x'.repeat(33)]) {
      expect(() => buildRevokeKeyCommand({ path: '/x', blob: B, token: bad }), bad).toThrow(
        /unvalidated/
      )
      expect(
        () => buildAddKeyCommand({ path: '/x', line: `ssh-ed25519 ${B} n`, token: bad }),
        bad
      ).toThrow(/unvalidated/)
    }
  })

  it('reports the window it actually armed, not the default one', async () => {
    // A caller passing `rollbackSeconds` would otherwise have every deadline
    // judgement made against 300 — wrong by an order of magnitude, and the
    // deadline is what decides whether a change may be confirmed at all.
    const plan = revoke({
      targets: [target(host({ self: 'root' }))],
      fingerprint: B_FP,
      rollbackSeconds: 30
    })
    expect(plan.rollbackSeconds).toBe(30)
    expect(plan.write!.command).toContain('sleep 30')
    expect(revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).rollbackSeconds).toBe(
      ACCESS_ROLLBACK_SECONDS
    )
  })

  it('is not a job, and there is no job kind pretending it is one', async () => {
    // NOTHING ever created a job of kind `access`: `access:run` issues the
    // staged write itself, in a hand-rolled serial loop, because the protocol
    // needs a fresh session per host between the write and the confirmation and
    // the job engine cannot provide one. A kind in the vocabulary that nothing
    // produces is a filter that never matches and an audit trail that never
    // fills.
    expect(JOB_KINDS).toEqual(['command', 'patch'])
    const plan = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP })
    expect(Object.keys(plan.write!).sort()).toEqual(['command', 'title'])
  })

  it('uses no sudo anywhere in a write', async () => {
    // The read half escalates because reading another account's key file is
    // normal. An escalated WRITE is one nobody watching the sudo log can tell
    // from an attacker with the same access.
    const command = revoke({ targets: [target(host({ self: 'root' }))], fingerprint: B_FP }).write!.command
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
      buildRevokeKeyCommand({ path: '/x', blob: B, token: '1' })
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
        for (const tool of ['cp', 'mv', 'rm', 'rmdir', 'mkdir', 'grep', 'chmod', 'sleep', 'cmp', 'tail', 'ls']) {
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
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 't1', rollbackSeconds: 60 })
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
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't2', rollbackSeconds: 1 }))
    expect(h.read()).not.toContain(A)
    await sleep(2500)
    expect(h.read()).toContain(A)
    expect(h.read()).toContain(B)
    // And it cleans up after itself: no backup left behind once it has been used.
    expect(existsSync(join(h.home, '.ssh/authorized_keys.shellpilot-t2.bak'))).toBe(false)
  })

  it('leaves the change alone once a confirmation lands', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't3', rollbackSeconds: 1 }))
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

  it('removes every line carrying the key, however many this server has', async () => {
    // The expected count is computed ON THE HOST now. It used to be taken from
    // the FIRST target in the selection and baked into the one command every
    // host runs, so the order the operator happened to select hosts in decided
    // what ran on all of them — and a host holding the key on two lines failed
    // a count check about a different machine.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${A} alice@second-machine`, `ssh-ed25519 ${B} bob`, ''])
    const r = h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't5', rollbackSeconds: 60 }))
    expect(r.code).toBe(0)
    expect(h.read()).not.toContain(A)
    expect(h.read()).toContain(B)
  })

  it('refuses when the key is not in the file this server actually has', async () => {
    // A collection that has gone stale, where the key is already gone. That
    // used to surface as "the new file has 2 lines and 1 was expected", which
    // is the truth about the wrong thing.
    const h = fakeHome([`ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't5b', rollbackSeconds: 60 }))
    expect(r.code).toBe(4)
    expect(r.out).toMatch(/that key is not in this account/)
    expect(h.read()).toBe(before)
    expect(h.backups()).toEqual([])
  })

  it('changes nothing when the resulting file is the wrong size', async () => {
    // The count is checked BEFORE the replacement, so a filter that did
    // something nobody asked for never becomes the live file at all. Forced
    // here with a `grep` whose `-v` drops one line more than its `-c` counted,
    // because with the host doing its own counting the two now have to be made
    // to disagree deliberately.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't5c', rollbackSeconds: 60 }), {
      shim: {
        grep: 'if [ "$1" = "-v" ]; then shift 3; /usr/bin/grep -v -F -- "$@" | tail -n +2; exit 0; fi\nexec /usr/bin/grep "$@"'
      }
    })
    expect(r.code).toBe(4)
    expect(r.out).toContain('nothing was changed')
    expect(h.read()).toBe(before)
    expect(h.backups()).toEqual([])
  })

  it('revokes the last key on an account, leaving it trusting nobody', async () => {
    // `grep -v` exits 1 when it selects no lines, which is exactly what this
    // looks like. Treated as a failure it turns the most final revocation there
    // is into "the new file could not be built" — and the count check that
    // would have caught a real problem never runs.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, ''])
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 't9', rollbackSeconds: 60 })
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
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w1', rollbackSeconds: 60 }),
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
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w2', rollbackSeconds: 60 }),
      { shim: { nohup: 'exit 0', setsid: 'exit 0', 'systemd-run': 'exit 0' } }
    )
    expect(r.code).not.toBe(0)
    expect(h.read()).toBe(before)
    expect(r.out).not.toContain('STAGED:')
  })

  it('changes nothing on a server with no way to detach a process at all', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w3', rollbackSeconds: 60 }),
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
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'w4', rollbackSeconds: 60 })
    )
    expect(r.code).toBe(0)
    expect(r.out).toMatch(/STAGED:/)
    expect(r.out).toMatch(/rollback is running under (systemd-run|setsid|nohup)/)
  })

  // -------------------------------------------------------------------------
  // One staged change at a time
  // -------------------------------------------------------------------------
  //
  // Each stage arms an INDEPENDENT watchdog holding its own copy of whatever
  // the file was at ITS start, and the disarm marker is per-token, so disarming
  // change 2 says nothing at all to change 1's watchdog. Two revokes a second
  // apart, change 2 verified and disarmed: the file was correct after the
  // commit, and change 1's watchdog then restored BOTH revoked keys — including
  // the one the audit trail said was revoked.
  //
  // The likely path is not two operators racing. It is one: a revoke reports
  // verification-failed, the operator fixes the plan and restages inside the
  // window.

  it('refuses to stage a second change while the first is still waiting', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const first = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'x1', rollbackSeconds: 2 })
    )
    expect(first.code).toBe(0)
    const after = h.read()

    const second = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: B, token: 'x2', rollbackSeconds: 2 })
    )
    expect(second.code).not.toBe(0)
    expect(second.out).toMatch(/still waiting for its rollback window/)
    // The one case that does not clear itself is a host whose watchdog was
    // killed after it armed — rare now, not impossible — and there the change
    // is live and unprotected. Refusing is right and a person has to look, so
    // the message names the file and says what looking at it means.
    expect(second.out).toContain('authorized_keys.shellpilot-x1.bak')
    expect(second.out).toMatch(/remove it by hand/)
    // Untouched, and — the part that matters — the first change's backup is
    // still the only one on the host, so its watchdog still holds the file it
    // was armed to restore.
    expect(h.read()).toBe(after)
    expect(h.backups()).toEqual(['authorized_keys.shellpilot-x1.bak'])
  })

  it('stages again once the first change’s window has closed', async () => {
    // The refusal has to be temporary, or one failed change would lock a host
    // out of this feature for good.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 'x3', rollbackSeconds: 1 }))
    await sleep(2500)
    // The host put it back by itself and cleaned up after the change.
    expect(h.read()).toContain(A)
    expect(h.backups()).toEqual([])
    const again = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: B, token: 'x4', rollbackSeconds: 60 })
    )
    expect(again.code).toBe(0)
    expect(again.out).toContain('STAGED:')
  })

  it('leaves no backup behind when it refuses after writing one', async () => {
    // A backup left by a change that did not happen would refuse every future
    // change on the host under the rule above, for ever.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const r = h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 'x5', rollbackSeconds: 60 }), {
      shim: { chmod: 'exit 1' }
    })
    expect(r.code).toBe(3)
    expect(h.backups()).toEqual([])
    // And the next change is not refused because of it.
    const next = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'x6', rollbackSeconds: 60 })
    )
    expect(next.code).toBe(0)
  })

  it('changes nothing when the backup cannot be written', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, ''])
    const before = h.read()
    chmodSync(join(h.home, '.ssh'), 0o500)
    try {
      const r = h.run(
        buildRevokeKeyCommand({ path: h.file, blob: A, token: 't6', rollbackSeconds: 60 })
      )
      expect(r.code).toBe(3)
      expect(r.out).toContain('nothing was changed')
      expect(h.read()).toBe(before)
    } finally {
      chmodSync(join(h.home, '.ssh'), 0o700)
    }
  })

  it('refuses a truncated backup rather than arming a watchdog to restore one', async () => {
    // `cp -p` on a full filesystem writes what it can and leaves a non-empty
    // file, and `[ -s ]` accepts it. The watchdog would then restore the
    // MUTILATED version over the live file, losing keys that were never part of
    // the change. Deleting that guard passed all 141 tests this item had.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'c1', rollbackSeconds: 60 }),
      { shim: { cp: 'head -c 20 "$2" > "$3" 2>/dev/null || head -c 20 "$1" > "$2"' } }
    )
    expect(r.code).toBe(3)
    expect(r.out).toMatch(/not a faithful copy/)
    expect(h.read()).toBe(before)
    expect(h.backups()).toEqual([])
  })

  it('adds the first key to an account whose authorized_keys is empty', async () => {
    // A freshly provisioned account, and the first thing anyone will try. The
    // emptiness check refused it with the wrong reason — "the backup is empty"
    // — for a file that had simply never had a key in it.
    const h = fakeHome([''])
    expect(h.read()).toBe('')
    const r = h.run(
      buildAddKeyCommand({ path: h.file, line: `ssh-ed25519 ${B} bob@desktop`, token: 'c2', rollbackSeconds: 60 })
    )
    expect(r.code).toBe(0)
    expect(h.read().split('\n').filter((l) => l !== '')).toEqual([`ssh-ed25519 ${B} bob@desktop`])
  })

  it('refuses a symlinked authorized_keys rather than replacing it with a file', async () => {
    // `~/.ssh/authorized_keys -> /etc/ssh/authorized_keys.d/$USER` is a common
    // config-managed pattern. `[ -f ]` follows the link, so the `mv` replaced
    // the LINK with a regular file — permanently destroying the indirection
    // while the real file kept the key.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const real = join(h.home, 'managed_keys')
    writeFileSync(real, `ssh-ed25519 ${A} alice@laptop\nssh-ed25519 ${B} bob@desktop\n`)
    rmSync(h.file)
    symlinkSync(real, h.file)
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'c3', rollbackSeconds: 60 })
    )
    expect(r.code).toBe(3)
    expect(r.out).toMatch(/symbolic link/)
    expect(lstatSync(h.file).isSymbolicLink()).toBe(true)
    expect(readFileSync(real, 'utf8')).toContain(A)
  })

  it('changes nothing when the new file cannot be made private', async () => {
    // The one permission-critical step in the whole command, and its failure
    // was swallowed by `2>/dev/null || true`. sshd's StrictModes rejects a
    // group-writable authorized_keys OUTRIGHT — every key on the account, not
    // just the one being changed.
    const h = fakeHome([`ssh-ed25519 ${A} alice@laptop`, `ssh-ed25519 ${B} bob@desktop`, ''])
    const before = h.read()
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 'c4', rollbackSeconds: 60 }),
      { shim: { chmod: 'exit 1' } }
    )
    expect(r.code).toBe(3)
    expect(r.out).toMatch(/could not be made private/)
    expect(h.read()).toBe(before)
  })

  it('leaves the new file private even under a permissive umask', async () => {
    // `grep > file` creates 0664 under umask 002, which is what a host with a
    // per-user group actually has. The add path gets this right by copying the
    // original with `cp -p`; the revoke path has to do it deliberately.
    const h = fakeHome([`ssh-ed25519 ${A} a`, `ssh-ed25519 ${B} b`, ''])
    const r = h.run(
      `umask 002\n${buildRevokeKeyCommand({ path: h.file, blob: A, token: 'c5', rollbackSeconds: 60 })}`
    )
    expect(r.code).toBe(0)
    expect((statSync(h.file).mode & 0o777).toString(8)).toBe('600')
  })

  it('changes nothing when there is no authorized_keys to change', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} x`, ''])
    rmSync(h.file)
    const r = h.run(
      buildRevokeKeyCommand({ path: h.file, blob: A, token: 't7', rollbackSeconds: 60 })
    )
    expect(r.code).toBe(3)
    expect(existsSync(h.file)).toBe(false)
  })

  it('leaves the new file private', async () => {
    const h = fakeHome([`ssh-ed25519 ${A} a`, `ssh-ed25519 ${B} b`, ''])
    h.run(buildRevokeKeyCommand({ path: h.file, blob: A, token: 't8', rollbackSeconds: 60 }))
    const mode = execFileSync('/bin/sh', ['-c', `ls -l "${h.file}" | cut -c1-10`], { encoding: 'utf8' }).trim()
    expect(mode).toBe('-rw-------')
  })
})

// ---------------------------------------------------------------------------

import {
  isAccessWriteEnabled,
  setAccessWriteEnabledForTests,
  syncAccessWriteEnabled
} from '../src/main/services/accessWriteGate'

describe('the operator opt-in, which main enforces rather than the renderer', () => {
  afterEach(() => setAccessWriteEnabledForTests(false))

  it('is off when nobody has said anything', () => {
    syncAccessWriteEnabled(null)
    expect(isAccessWriteEnabled()).toBe(false)
  })

  it('is off on a FRESH import, before any settings have arrived', async () => {
    // The window between the process starting and the first data:save. Every
    // other test in this block calls sync() first, which overwrites whatever
    // the module started as -- so none of them can see the initial value, and a
    // mutation setting it to `true` passed all of them. Loaded fresh here so
    // the pristine default is actually observed.
    vi.resetModules()
    const fresh = await import('../src/main/services/accessWriteGate')
    expect(fresh.isAccessWriteEnabled()).toBe(false)
  })

  it('is off for a settings blob written before this key existed', () => {
    // The upgrade path, and the one that must not open the gate. Every install
    // that has ever run this app has a data file with no such key in it.
    syncAccessWriteEnabled({ settings: {} })
    expect(isAccessWriteEnabled()).toBe(false)
    syncAccessWriteEnabled({ settings: { localTerminalEnabled: true } })
    expect(isAccessWriteEnabled()).toBe(false)
  })

  it('needs the exact boolean, not merely something truthy', () => {
    // `=== true`, not `!== false`. This is the INVERSE of localTerminalEnabled
    // next door, and the inversion is the point: that one is a convenience
    // whose safe state is available, this is a gate whose safe state is shut.
    // A corrupt blob must not be able to open it.
    for (const v of ['true', 1, {}, [], 'yes']) {
      syncAccessWriteEnabled({ settings: { accessWriteEnabled: v } })
      expect(isAccessWriteEnabled(), String(v)).toBe(false)
    }
  })

  it('turns on only for a real, explicit true', () => {
    syncAccessWriteEnabled({ settings: { accessWriteEnabled: true } })
    expect(isAccessWriteEnabled()).toBe(true)
  })

  it('goes off again when the operator turns it off', () => {
    syncAccessWriteEnabled({ settings: { accessWriteEnabled: true } })
    syncAccessWriteEnabled({ settings: { accessWriteEnabled: false } })
    expect(isAccessWriteEnabled()).toBe(false)
  })

  it('names the one thing that is unproven, rather than warning in general', () => {
    // "This may be unsafe" is advice nobody can act on. The operator is told
    // which sentence has never been observed, so they can decide whether they
    // are the person who can observe it.
    expect(ACCESS_WRITE_OPT_IN_NOTE).toMatch(/KillUserProcesses/)
    expect(ACCESS_WRITE_OPT_IN_NOTE).toMatch(/second session/i)
  })
})
