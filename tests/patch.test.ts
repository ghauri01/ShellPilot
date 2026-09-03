import { describe, it, expect } from 'vitest'
import {
  FACT_SOURCE_IDS,
  FACT_SOURCE_LABEL,
  type FactSourceId,
  type FactSourceReport,
  type FactStatus,
  type HostFacts
} from '../src/shared/hostFacts'
import { GAP_LABEL } from '../src/renderer/src/lib/inventory'
import {
  PATCH_GAP_LABEL,
  PATCH_NO_AUTOMATION_NOTE,
  REBOOT_BOOT_ID_MARK,
  buildPatchRow,
  buildRebootStep,
  buildRebootVerify,
  evaluateGate,
  gateTimeoutReason,
  parseRebootBootId,
  parseRebootVerify,
  patchCommandFor,
  planPatch,
  planWaves,
  summarisePatch,
  verifyReboot,
  wavesToTargets,
  type GateHost,
  type PatchHostInput
} from '../src/shared/patch'
import { planJob } from '../src/shared/jobs'

// Item 17's decisions, tested where they are made.
//
// Everything that decides anything about a patch run lives in shared/patch.ts
// so that it can be tested without a DOM and so that main can call the same
// function the panel calls. The panel test (tests/patchPanel.test.tsx) proves
// the screen shows these answers; this file proves the answers.

const sources = (over: Partial<Record<FactSourceId, FactStatus>> = {}): FactSourceReport[] =>
  FACT_SOURCE_IDS.map((id) => ({ id, label: FACT_SOURCE_LABEL[id], status: over[id] ?? 'ok' }))

const facts = (over: Partial<HostFacts> = {}): HostFacts => ({
  distroId: 'ubuntu',
  distroVersion: '24.04',
  prettyName: 'Ubuntu 24.04.1 LTS',
  arch: 'x86_64',
  cpuModel: 'AMD EPYC',
  packageManager: 'apt',
  pendingUpdates: 0,
  securityUpdates: 0,
  rebootRequired: false,
  rebootReason: null,
  virtualisation: 'kvm',
  metadataAt: 900,
  collectedAt: 1_000,
  sources: sources(),
  ...over
})

const input = (name: string, f: HostFacts | null, over: Partial<PatchHostInput> = {}): PatchHostInput => ({
  serverId: name,
  serverName: name,
  facts: f,
  factsAt: f ? 1_000 : null,
  factsError: null,
  ...over
})

/** An Arch box: pending updates are countable, security updates never are. */
const arch = (): HostFacts =>
  facts({
    distroId: 'arch',
    packageManager: 'pacman',
    securityUpdates: null,
    sources: sources({ 'security-updates': 'unsupported' })
  })

// =========================================================================
// The honesty requirement inherited from item C
// =========================================================================

describe('a host that cannot report security updates', () => {
  it('is excluded from the total and never counted as zero', () => {
    const rows = [
      buildPatchRow(input('ubuntu', facts({ securityUpdates: 4 }))),
      buildPatchRow(input('archbox', arch()))
    ]
    const s = summarisePatch(rows)
    expect(s.securityTotal).toBe(4)
    expect(s.securityUnanswerable).toBe(1)
    // The row itself must not carry a number for it. `unsupported` is rendered
    // as words, never as a count and never as a dash.
    expect(rows[1].security.value).toBeNull()
    expect(rows[1].security.gap).toBe('unsupported')
    expect(PATCH_GAP_LABEL.unsupported).toBe('cannot be answered')
  })

  it('is excluded from "all clear" even when every answer that exists is zero', () => {
    // THE REGRESSION THIS FILE EXISTS FOR. Two hosts, nothing pending on
    // either as far as anyone can tell — but one of them can never report a
    // security count, so the estate is NOT clear. An implementation that
    // compared totals to zero would say it was.
    const clean = summarisePatch([buildPatchRow(input('ubuntu', facts()))])
    expect(clean.allClear).toBe(true)

    const withArch = summarisePatch([
      buildPatchRow(input('ubuntu', facts())),
      buildPatchRow(input('archbox', arch()))
    ])
    expect(withArch.securityTotal).toBe(0)
    expect(withArch.allClear).toBe(false)
    expect(withArch.allClearNote).toContain('not an all-clear')
    expect(withArch.allClearNote).toContain('unknown, not clean')
  })

  it('keeps "cannot answer permanently" apart from "did not answer this time"', () => {
    // A permission problem is fixable by a different account; Arch's missing
    // security channel is not fixable at all. Folding them into one number
    // tells an operator that one is the other.
    const denied = facts({ securityUpdates: null, sources: sources({ 'security-updates': 'denied' }) })
    const s = summarisePatch([buildPatchRow(input('a', arch())), buildPatchRow(input('b', denied))])
    expect(s.securityUnanswerable).toBe(1)
    expect(s.securityUnknown).toBe(1)
  })

  it('will not answer "no work" for a host that could not answer', () => {
    // THE NULL-IS-NOT-ZERO RULE, APPLIED TO hasWork. A boolean has no room for
    // "cannot say", so it spends "cannot say" as "no" — and "select everything
    // with work" then silently omits precisely the hosts nobody can vouch for,
    // which are the ones an operator most needs to see.
    expect(buildPatchRow(input('archbox', arch())).hasWork).toBe('unknown')
    expect(buildPatchRow(input('never-collected', null)).hasWork).toBe('unknown')

    const denied = facts({ securityUpdates: null, sources: sources({ 'security-updates': 'denied' }) })
    expect(buildPatchRow(input('denied', denied)).hasWork).toBe('unknown')

    const noReboot = facts({ rebootRequired: null, sources: sources({ 'reboot-required': 'no-tool' }) })
    expect(buildPatchRow(input('no-tool', noReboot)).hasWork).toBe('unknown')
  })

  it('still says yes and no where there is an answer', () => {
    expect(buildPatchRow(input('clean', facts())).hasWork).toBe('no')
    expect(buildPatchRow(input('pending', facts({ pendingUpdates: 3 }))).hasWork).toBe('yes')
    expect(buildPatchRow(input('sec', facts({ securityUpdates: 1 }))).hasWork).toBe('yes')
    expect(buildPatchRow(input('reboot', facts({ rebootRequired: true }))).hasWork).toBe('yes')
  })

  it('says yes over unknown when one answer is a real number', () => {
    // A host with 4 pending updates and an unreadable security count has work.
    // "Unknown" is for a host where nothing positive was established at all.
    const half = facts({
      pendingUpdates: 4,
      securityUpdates: null,
      sources: sources({ 'security-updates': 'denied' })
    })
    expect(buildPatchRow(input('a', half)).hasWork).toBe('yes')
  })

  it('agrees with the summary about an estate nobody can vouch for', () => {
    // The contradiction this fixes: the summary line says "that is not an
    // all-clear: those hosts are unknown, not clean", while the button beside
    // it is disabled because every host answered `hasWork: false`.
    const rows = [buildPatchRow(input('archbox', arch())), buildPatchRow(input('b', null))]
    expect(summarisePatch(rows).allClear).toBe(false)
    expect(rows.every((r) => r.hasWork === 'no')).toBe(false)
  })

  it('uses the same words as the inventory panel for the same fact', () => {
    // The two screens sit next to each other. A user who learns "cannot be
    // answered" in one must not meet a synonym for it in the other.
    for (const gap of ['unsupported', 'denied', 'no-tool', 'absent', 'unknown', 'not-collected', 'probe-failed', 'stale-metadata'] as const) {
      expect(PATCH_GAP_LABEL[gap], gap).toBe(GAP_LABEL[gap])
    }
  })

  it('does not blank a host whose count came from a stale cache', () => {
    const stale = facts({ pendingUpdates: 12, sources: sources({ 'package-metadata': 'stale-metadata' }) })
    const row = buildPatchRow(input('a', stale))
    expect(row.pending.value).toBe(12)
    expect(row.pending.staleMetadata).toBe(true)
    expect(summarisePatch([row]).staleMetadata).toBe(1)
  })

  it('treats a missing reboot answer as unknown rather than as "no"', () => {
    const f = facts({ rebootRequired: null, sources: sources({ 'reboot-required': 'no-tool' }) })
    const row = buildPatchRow(input('a', f))
    expect(row.rebootRequired).toBeNull()
    expect(row.rebootGap).toBe('no-tool')
    const s = summarisePatch([row])
    expect(s.rebootsOwed).toBe(0)
    expect(s.rebootUnknown).toBe(1)
    expect(s.allClear).toBe(false)
  })

  it('says which reason a host has no facts at all', () => {
    const never = buildPatchRow(input('a', null))
    const failed = buildPatchRow(input('b', null, { factsError: 'Connection refused' }))
    expect(never.pending.gap).toBe('not-collected')
    expect(failed.pending.gap).toBe('probe-failed')
    expect(failed.pending.help).toContain('Connection refused')
  })
})

// =========================================================================
// What it will not do
// =========================================================================

describe('the refusal to automate', () => {
  it('is written down, the way docker.ts writes its refusal to ship prune', () => {
    expect(PATCH_NO_AUTOMATION_NOTE).toContain('does not patch on a schedule')
    expect(PATCH_NO_AUTOMATION_NOTE).toContain('unattended-upgrades')
  })
})

describe('the upgrade command for each package manager', () => {
  it('never asks a question a detached job cannot answer', () => {
    // A detached job has no tty and no stdin. Without the non-interactive
    // frontend apt stops at the first modified conffile and waits for a person
    // who is not there, and the job times out with dpkg half-configured.
    const apt = patchCommandFor('apt', 'all')
    expect(apt.ok).toBe(true)
    expect(apt.ok && apt.command).toContain('DEBIAN_FRONTEND=noninteractive')
    expect(apt.ok && apt.command).toContain('--force-confold')
    for (const m of ['dnf', 'zypper', 'pacman'] as const) {
      const c = patchCommandFor(m, 'all')
      expect(c.ok, m).toBe(true)
      expect(c.ok && /(-y|--non-interactive|--noconfirm)/.test(c.command), m).toBe(true)
    }
    // apk is the exception and needs no flag: it has no prompt to suppress.
    // Asserting one would be asserting a flag that does not exist rather than
    // the property that matters.
    expect(patchCommandFor('apk', 'all')).toMatchObject({ ok: true, command: 'sudo -n apk upgrade' })
  })

  it('never removes packages', () => {
    // `dist-upgrade` / `full-upgrade` remove packages to satisfy dependencies.
    // A patch run that can uninstall things is not a patch run.
    for (const m of ['apt', 'dnf', 'yum', 'zypper', 'pacman', 'apk'] as const) {
      const c = patchCommandFor(m, 'all')
      if (!c.ok) continue
      expect(c.command, m).not.toContain('dist-upgrade')
      expect(c.command, m).not.toContain('full-upgrade')
      expect(c.command, m).not.toContain('autoremove')
      expect(c.command, m).not.toContain(' dup')
    }
  })

  it('refuses a security-only run where the distribution has no such thing', () => {
    for (const m of ['pacman', 'apk'] as const) {
      const c = patchCommandFor(m, 'security')
      expect(c.ok, m).toBe(false)
      expect(!c.ok && c.reason, m).toMatch(/security/)
    }
    // apt too, and for a different reason worth stating: every recipe that
    // claims to do it installs dependencies the operator did not ask for.
    const apt = patchCommandFor('apt', 'security')
    expect(apt.ok).toBe(false)
    expect(!apt.ok && apt.reason).toContain('wider change')
  })

  it('offers the real thing where the distribution has one', () => {
    expect(patchCommandFor('zypper', 'security')).toMatchObject({
      ok: true,
      command: expect.stringContaining('--category security')
    })
    expect(patchCommandFor('dnf', 'security')).toMatchObject({
      ok: true,
      command: expect.stringContaining('--security')
    })
  })
})

// =========================================================================
// Waves
// =========================================================================

describe('waves', () => {
  const hosts = ['a', 'b', 'c', 'd', 'e'].map((n) => ({ serverId: n, serverName: n }))

  it('keeps the caller order and does not reorder anything', () => {
    const w = planWaves(hosts, 2)
    expect(w.map((x) => x.hosts.map((h) => h.serverId))).toEqual([['a', 'b'], ['c', 'd'], ['e']])
  })

  it('sizes the confirmation on the largest wave, not on the total', () => {
    // Rolling slowly must not cost more friction than doing it all at once —
    // that would teach people the careful version is the expensive one.
    // Six hosts, because TYPE_ABOVE_HOSTS is five and the point of the test is
    // the difference between one at a time and all of them.
    const six = [...hosts, { serverId: 'f', serverName: 'f' }]
    const staged = planJob(
      { kind: 'patch', title: 't', steps: [{ command: 'apt-get -y upgrade' }] },
      wavesToTargets(planWaves(six, 1))
    )
    const together = planJob(
      { kind: 'patch', title: 't', steps: [{ command: 'apt-get -y upgrade' }] },
      wavesToTargets(planWaves(six, 0))
    )
    expect(staged.blastRadius).toBe(1)
    expect(staged.totalHosts).toBe(6)
    expect(together.blastRadius).toBe(6)
    expect(staged.confirmation.kind).not.toBe('type-to-confirm')
    expect(together.confirmation.kind).toBe('type-to-confirm')
  })
})

// =========================================================================
// The plan
// =========================================================================

const servers = [
  { id: 'bastion', name: 'bastion', route: [] },
  { id: 'web', name: 'web-1', route: [{ serverId: 'bastion', host: 'b', port: 22, username: 'ops' }] }
]

describe('planning a patch run', () => {
  it('refuses to restart a jump host, as a block rather than as a warning', () => {
    const plan = planPatch({
      scope: 'all',
      hosts: [
        { serverId: 'bastion', serverName: 'bastion', packageManager: 'apt' },
        { serverId: 'web', serverName: 'web-1', packageManager: 'apt' }
      ],
      waveSize: 2,
      reboot: true,
      healthGate: true,
      servers
    })
    expect(plan.blocks.map((b) => b.serverName)).toEqual(['bastion'])
    expect(plan.blocks[0].kind).toBe('jump-host')
  })

  it('does not refuse when nothing is being restarted', () => {
    // The refusal is about the reboot, not about the host. Upgrading a bastion
    // without restarting it is an ordinary thing to want.
    const plan = planPatch({
      scope: 'all',
      hosts: [{ serverId: 'bastion', serverName: 'bastion', packageManager: 'apt' }],
      waveSize: 1,
      reboot: false,
      healthGate: true,
      servers
    })
    expect(plan.blocks).toEqual([])
  })

  it('only restarts the hosts that say they need it', () => {
    const plan = planPatch({
      scope: 'all',
      hosts: [
        { serverId: 'web', serverName: 'web-1', packageManager: 'apt' },
        { serverId: 'app', serverName: 'app-1', packageManager: 'apt' }
      ],
      waveSize: 1,
      reboot: true,
      healthGate: false,
      rebootWanted: (id) => id === 'web',
      servers: [{ id: 'web', name: 'web-1' }, { id: 'app', name: 'app-1' }]
    })
    // One spec with a reboot step, one without: the step list IS the spec, so
    // they cannot be the same job.
    expect(plan.jobs).toHaveLength(2)
    // BOTH jobs are checked, not only the one `.find` happened to land on.
    // Asking the reboot-carrying job who its targets are proves web reboots; it
    // does not prove app-1 does NOT, and putting a reboot step on both specs
    // passed that assertion while restarting a host that never asked for one.
    const rebooting = plan.jobs.filter((j) => j.spec.steps.some((s) => s.reboot === true))
    const quiet = plan.jobs.filter((j) => !j.spec.steps.some((s) => s.reboot === true))
    expect(rebooting).toHaveLength(1)
    expect(quiet).toHaveLength(1)
    expect(rebooting[0].targets.map((t) => t.serverId)).toEqual(['web'])
    expect(quiet[0].targets.map((t) => t.serverId)).toEqual(['app'])
    // And nothing that merely LOOKS like a restart is hiding in the quiet
    // job's command text either — `reboot: true` is a declaration, not a
    // guarantee that the other step list is inert.
    expect(quiet[0].spec.steps.map((s) => s.command).join('\n')).not.toMatch(/reboot|shutdown -r/)
    expect(plan.hosts.find((h) => h.serverId === 'app')!.reboot).toBe(false)
  })

  it('splits by package manager rather than substituting a command per host', () => {
    // `verifyApproval` compares the step TEXT, so a spec whose command changed
    // per host could not be checked against the record at all.
    const plan = planPatch({
      scope: 'all',
      hosts: [
        { serverId: 'a', serverName: 'deb', packageManager: 'apt' },
        { serverId: 'b', serverName: 'rocky', packageManager: 'dnf' }
      ],
      waveSize: 2,
      reboot: false,
      healthGate: false,
      servers: [{ id: 'a', name: 'deb' }, { id: 'b', name: 'rocky' }]
    })
    expect(plan.jobs.map((j) => j.packageManager).sort()).toEqual(['apt', 'dnf'])
    for (const j of plan.jobs) expect(j.spec.steps).toHaveLength(1)
  })

  it('excludes a host it has no command for, by name and with a reason', () => {
    const plan = planPatch({
      scope: 'security',
      hosts: [
        { serverId: 'a', serverName: 'archbox', packageManager: 'pacman' },
        { serverId: 'b', serverName: 'unknown', packageManager: null }
      ],
      waveSize: 2,
      reboot: false,
      healthGate: false,
      servers: [{ id: 'a', name: 'archbox' }, { id: 'b', name: 'unknown' }]
    })
    expect(plan.jobs).toEqual([])
    expect(plan.excluded.map((e) => e.serverName).sort()).toEqual(['archbox', 'unknown'])
    expect(plan.excluded.find((e) => e.serverName === 'unknown')!.reason).toContain('Nothing is guessed')
  })

  it('carries the topology hole into the plan rather than dropping it', () => {
    const plan = planPatch({
      scope: 'all',
      hosts: [{ serverId: 'w', serverName: 'web', packageManager: 'apt' }],
      waveSize: 1,
      reboot: true,
      healthGate: false,
      servers: [{ id: 'w', name: 'web', route: [{ host: 'jump.example', port: 22, username: 'ops' }] }]
    })
    expect(plan.blocks).toEqual([])
    expect(plan.unmatchedNote).toContain('1 hop is not backed by a saved server')
  })

  it('refuses the reboot when an "unmatched" hop is a host in this very run', () => {
    // The one case where the hole is not hypothetical, and the one the counted
    // note handled worst: web-1 routes through bare bastion.example, that
    // machine IS saved as `bastion`, and this run is about to restart it. The
    // note said "1 hop is not backed by a saved server (on web-1)" and never
    // named the host standing in front of the operator.
    const plan = planPatch({
      scope: 'all',
      hosts: [{ serverId: 'b', serverName: 'bastion', packageManager: 'apt' }],
      waveSize: 1,
      reboot: true,
      healthGate: false,
      servers: [
        { id: 'b', name: 'bastion', host: 'bastion.example', port: 22 },
        {
          id: 'w',
          name: 'web-1',
          host: 'web.example',
          port: 22,
          route: [{ host: 'bastion.example', port: 22, username: 'ops' }]
        }
      ]
    })
    expect(plan.blocks.map((b) => b.serverName)).toEqual(['bastion'])
    expect(plan.blocks[0].reason).toContain('web-1')
    expect(plan.blocks[0].reason).toContain('bastion.example:22')
    // Resolved, so it is no longer part of the hole. A note claiming a blind
    // spot next to a refusal that just proved there is none teaches an
    // operator to skip the note.
    expect(plan.unmatchedNote).toBeNull()
  })

  it('refuses the reboot of a second saved record for the same machine', () => {
    const plan = planPatch({
      scope: 'all',
      hosts: [{ serverId: 'id2', serverName: 'bastion-b', packageManager: 'apt' }],
      waveSize: 1,
      reboot: true,
      healthGate: false,
      servers: [
        { id: 'id1', name: 'bastion-a', host: 'bastion.example', port: 22 },
        { id: 'id2', name: 'bastion-b', host: 'bastion.example', port: 22 },
        { id: 'x', name: 'x-1', host: 'x.example', port: 22, route: [{ serverId: 'id1' }] }
      ]
    })
    expect(plan.blocks.map((b) => b.serverName)).toEqual(['bastion-b'])
    expect(plan.blocks[0].reason).toContain('x-1')
  })

  it('sets the gate on the spec only when the operator asked for one', () => {
    const of = (healthGate: boolean) =>
      planPatch({
        scope: 'all',
        hosts: [{ serverId: 'a', serverName: 'a', packageManager: 'apt' }],
        waveSize: 1,
        reboot: false,
        healthGate,
        servers: [{ id: 'a', name: 'a' }]
      }).jobs[0].spec.gate
    expect(of(true)).toBe('health')
    expect(of(false)).toBe('none')
  })
})

// =========================================================================
// Reboot-and-wait
// =========================================================================

describe('the reboot step', () => {
  it('records a boot id before it goes down', () => {
    const step = buildRebootStep()
    expect(step).toContain(REBOOT_BOOT_ID_MARK)
    expect(step).toContain('boot_id')
    // The output is flushed before the machine goes, or the boot id we are
    // about to compare against is never written down.
    //
    // PRESENCE BEFORE ORDERING, and it is not pedantry: `indexOf` on an absent
    // needle is -1, and -1 is less than everything. Asserting only the order
    // meant deleting `sync;` from buildRebootStep left this green — the flush
    // the whole reboot-verification story rests on was protected by nothing.
    const flush = step.indexOf('sync;')
    const restart = step.indexOf('systemctl reboot')
    expect(flush, 'the reboot step does not flush before it goes down').toBeGreaterThanOrEqual(0)
    expect(restart, 'the reboot step does not restart the machine').toBeGreaterThanOrEqual(0)
    expect(flush).toBeLessThan(restart)
    // And the fallback for a host without systemd is on the far side of the
    // same flush, or half the estate gets the bug the ordering above forbids.
    const fallback = step.indexOf('shutdown -r now')
    expect(fallback).toBeGreaterThanOrEqual(0)
    expect(flush).toBeLessThan(fallback)
    expect(parseRebootBootId(`some output\n${REBOOT_BOOT_ID_MARK}abc-123\nmore\n`)).toBe('abc-123')
    expect(parseRebootBootId('nothing here')).toBeNull()
  })

  it('reads the post-boot check, keeping "no systemd" apart from "nothing failed"', () => {
    expect(buildRebootVerify()).toContain('shellpilot-postboot/1')
    const withSystemd = parseRebootVerify(
      'shellpilot-postboot/1\nboot-id=new\nuptime=42\nunit-state=running\nfailed=\n'
    )
    expect(withSystemd.failed).toEqual([])
    const without = parseRebootVerify('shellpilot-postboot/1\nboot-id=new\nuptime=42\nunit-state=\nfailed=\n')
    // null, not []. "Nothing has failed" and "we cannot see whether anything
    // has failed" are different answers and must never read the same.
    expect(without.failed).toBeNull()
  })

  it('proves the machine restarted, rather than assuming it from a dropped link', () => {
    const after = parseRebootVerify('shellpilot-postboot/1\nboot-id=new\nuptime=9\nunit-state=running\nfailed=\n')
    expect(verifyReboot('old', after)).toMatchObject({ kind: 'rebooted', ok: true })
    // Same boot id: the host is answering and never restarted. The reboot was
    // issued and something swallowed it.
    expect(verifyReboot('new', after)).toMatchObject({ kind: 'not-rebooted', ok: false })
  })

  it('refuses to claim a restart it cannot prove', () => {
    const noBootId = parseRebootVerify('shellpilot-postboot/1\nboot-id=\nuptime=9\nunit-state=running\nfailed=\n')
    const v = verifyReboot(null, noBootId)
    expect(v.kind).toBe('unverifiable')
    expect(v.ok).toBe(false)
    expect(v.reason).toContain('cannot prove')
  })

  it('calls a host that came back with failed units degraded, not ok', () => {
    const after = parseRebootVerify(
      'shellpilot-postboot/1\nboot-id=new\nuptime=9\nunit-state=degraded\nfailed=nginx.service postgresql.service \n'
    )
    const v = verifyReboot('old', after)
    expect(v.kind).toBe('degraded')
    expect(v.reason).toContain('nginx.service')
  })
})

// =========================================================================
// The wave gate
// =========================================================================

const gh = (name: string, over: Partial<GateHost> = {}): GateHost => ({
  serverId: name,
  serverName: name,
  sampledAt: 2_000,
  unreachable: false,
  unreachableError: null,
  failedUnits: [],
  ...over
})

describe('the health gate between waves', () => {
  it('will not pass on a sample taken before the wave ran', () => {
    // THE MISTAKE THIS PREVENTS: a gate that accepted a stale sample would pass
    // instantly, every time, on data from before the upgrade — which is worse
    // than no gate, because it looks like one.
    const v = evaluateGate([gh('a', { sampledAt: 999 })], { since: 1_000 })
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.kind).toBe('stale')
    expect(v.ok === false && v.reason).toContain('cannot say what the wave did')
  })

  it('treats a host that has never been sampled as stale, not as healthy', () => {
    const v = evaluateGate([gh('a', { sampledAt: null })], { since: 1_000 })
    expect(v.ok).toBe(false)
  })

  it('stops on a failed unit and names it', () => {
    const v = evaluateGate([gh('a'), gh('b', { failedUnits: ['nginx.service'] })], { since: 1_000 })
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.kind).toBe('unhealthy')
    expect(v.ok === false && v.reason).toContain('nginx.service')
  })

  it('stops on a host that stopped answering', () => {
    const v = evaluateGate([gh('a', { unreachable: true, unreachableError: 'Connection refused' })], {
      since: 1_000
    })
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.reason).toContain('Connection refused')
  })

  it('reports a host that cannot report unit state without blocking on it', () => {
    // Blocking would make a host without systemd permanently unpatchable in a
    // staged run. Saying nothing would let it vouch for itself.
    const v = evaluateGate([gh('a'), gh('b', { failedUnits: null })], { since: 1_000 })
    expect(v.ok).toBe(true)
    expect(v.ok === true && v.unverified).toEqual(['b'])
    expect(v.ok === true && v.note).toContain('nothing here vouches for it')
  })

  it('passes a clean wave', () => {
    const v = evaluateGate([gh('a'), gh('b')], { since: 1_000 })
    expect(v.ok).toBe(true)
  })

  it('names the sampler when it gives up, because that is the setting that fixes it', () => {
    // THE FAILURE THIS SENTENCE IS FOR. Background checking is off by default.
    // With it off there is no health observation of any kind, so every host is
    // `stale`, the gate polls for five minutes and halts — and the operator is
    // told there was "no health check newer than the wave" with no hint that
    // the thing which would have produced one is a switch in Settings. Naming
    // the wave and the symptom without naming the cause turns a two-click fix
    // into a support question.
    const msg = gateTimeoutReason('wave-1', 'No health check newer than this wave for web-1.')
    expect(msg).toContain('wave-1')
    expect(msg).toContain('Check servers in the background')
    expect(msg).toContain('Settings')
  })
})
