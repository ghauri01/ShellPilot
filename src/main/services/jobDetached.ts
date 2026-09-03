import type { JobExecRequest, JobExecResult, JobExecutor } from './jobRunner'
import type { JobDetachedHandle, JobHostCapability, JobHostCapabilityReport } from '../../shared/jobs'
import {
  JOB_INSTANCE_NOTE,
  JOB_LAUNCH_FAILED_ERROR,
  JOB_ORPHANED_ERROR,
  JOB_POLL_BYTES,
  JOB_POLL_MS,
  JOB_RECONNECT_GLOBAL_MAX,
  buildJobLaunch,
  buildJobPoll,
  buildJobProbe,
  buildJobReap,
  buildJobSignal,
  classifyJobPoll,
  jobMarkerDir,
  nextRetryDelay,
  parseJobLaunch,
  parseJobPoll,
  parseJobProbe,
  restartsTheMachine
} from '../../shared/jobs'

// The detached executor — roadmap item B2.
//
// ---------------------------------------------------------------------------
// The one thing this exists to fix
// ---------------------------------------------------------------------------
// On the attached path a dying socket means sshd sends SIGHUP, and `apt` and
// `dpkg` do not ignore it. Nine minutes into an estate upgrade, closing the lid
// is not lost output: it is DPKG INTERRUPTED ON EVERY HOST, with
// `sudo dpkg --configure -a` waiting on each of them. That is not a smaller
// version of the feature, it is a harmful one, and it is why item 17 —
// patching, the flagship — cannot ship on B1.
//
// So the command is launched into its own session with `setsid`, the channel
// that launched it closes immediately, and everything after that is a POLL of
// five small files. The link may drop, the laptop may sleep, ShellPilot may be
// restarted; none of it reaches the process doing the work.
//
// What lands on the host, why that is defensible, and why `/tmp` is not in the
// candidate list is written out at the head of shared/jobs.ts, next to the
// builders that produce it. It is written THERE rather than here on purpose:
// that file is what the test fake reads, so the promise and the thing that
// keeps it cannot drift apart.
//
// ---------------------------------------------------------------------------
// Degrade, do not pretend
// ---------------------------------------------------------------------------
// A host with no writable state directory, or without `setsid` and `nohup`,
// cannot do this. It falls back to B1's attached executor FOR THAT HOST, and
// the fallback is reported per host rather than logged: an estate where one
// busybox appliance degrades is an estate where fourteen hosts survive the lid
// closing and one does not, and an operator who is not told which is the one
// has been handed a guarantee that is false for a machine they cannot name.

/** What ssh.ts's `sshExec` gives back, restated so this module is testable
 *  without a socket. A connection that never came up is `ok: false` with an
 *  `error`, exactly as sshExec reports it — nothing here throws for that. */
export interface JobRunResult {
  ok: boolean
  code: number | null
  stdout: string
  stderr: string
  error?: string
}

export interface DetachedDeps {
  /** One command, buffered result out. `sshExec` bound with secret resolution. */
  run: (cfg: unknown, command: string, timeoutMs: number) => Promise<JobRunResult>
  /**
   * This ShellPilot's id, stable across restarts on this machine.
   *
   * Stable is the requirement, not unique-per-launch: a job launched before a
   * restart must be OURS after it, or every reclaim would report `foreign` and
   * refuse to reap its own markers.
   */
  instanceId: string
  /** The attached executor, for hosts that cannot detach and for when the
   *  Settings switch is off. */
  attached: JobExecutor
  /** The Settings switch. Read per launch, so flipping it never disturbs a job
   *  already running. */
  enabled: () => boolean
  /**
   * Whether credentials can be resolved at all right now.
   *
   * A locked vault must PARK the poll loop, the way fleetSampler parks its
   * sweep — not error out. Erroring would end a job that is still running
   * perfectly well on fifteen hosts, and would do it because of something local
   * and temporary. See the park branch in `poll`.
   */
  vaultUnlocked?: () => boolean
  now?: () => number
  /** Injected so the test suite advances time rather than sleeping through it. */
  sleep?: (ms: number) => Promise<void>
  /** Injected so the backoff schedule is asserted rather than sampled. */
  random?: () => number
  /** Called whenever a host's capability is learned, for the Settings row. */
  onCapability?: (report: JobHostCapabilityReport) => void
  pollMs?: number
  pollBytes?: number
  /** How long one poll command may take before it counts as a dropped link. */
  pollTimeoutMs?: number
  /** How long the loop waits between checks while the vault is locked. */
  parkMs?: number
}

const DEFAULT_POLL_TIMEOUT_MS = 30_000
const DEFAULT_PARK_MS = 10_000

/**
 * A global cap on hosts dialling at once.
 *
 * The case is a laptop waking: fifteen detached jobs notice the dead link in
 * the same millisecond and all reconnect to the same bastion. Per-host backoff
 * does not help, because they are synchronised by the wake and not by each
 * other. So the gate is across the app, not per job — one instance of this
 * class per executor, which main constructs once.
 */
class Gate {
  private inFlight = 0
  private readonly waiting: (() => void)[] = []

  constructor(private readonly max: number) {}

  async acquire(): Promise<() => void> {
    if (this.inFlight < this.max) {
      this.inFlight++
      return () => this.releaseOne()
    }
    await new Promise<void>((resolve) => this.waiting.push(resolve))
    return () => this.releaseOne()
  }

  private releaseOne(): void {
    const next = this.waiting.shift()
    // Handed straight on rather than decremented and re-acquired: a released
    // slot that went back on the counter would let a host which arrived later
    // overtake one that has been waiting, and under a wake-up stampede that is
    // the difference between fifteen hosts draining in order and fifteen hosts
    // taking turns at random.
    if (next) next()
    else this.inFlight--
  }

  get busy(): number {
    return this.inFlight
  }
}

export interface DetachedExecutor extends JobExecutor {
  /** What each host was found capable of. Drives the Settings row that names
   *  the hosts running attached and why. */
  capabilities(): JobHostCapabilityReport[]
  /** Forget a host's probe result, so the next job asks again. Called when a
   *  server's configuration changes underneath us. */
  forget(serverId: string): void
}

export function detachedJobExecutor(deps: DetachedDeps): DetachedExecutor {
  const now = (): number => (deps.now ?? Date.now)()
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms).unref?.()))
  const random = deps.random ?? Math.random
  const pollMs = deps.pollMs ?? JOB_POLL_MS
  const pollBytes = deps.pollBytes ?? JOB_POLL_BYTES
  const pollTimeoutMs = deps.pollTimeoutMs ?? DEFAULT_POLL_TIMEOUT_MS
  const parkMs = deps.parkMs ?? DEFAULT_PARK_MS
  const gate = new Gate(JOB_RECONNECT_GLOBAL_MAX)

  /** Probe results, one per server, for the life of this app run. Not
   *  persisted: a host that gained setsid since yesterday should not have to
   *  wait for a cache to expire, and the probe is one exec. */
  const caps = new Map<string, JobHostCapability>()
  const reports = new Map<string, JobHostCapabilityReport>()

  async function capabilityFor(req: JobExecRequest): Promise<JobHostCapability> {
    const cached = caps.get(req.serverId)
    if (cached) return cached
    const r = await deps.run(req.cfg, buildJobProbe(), pollTimeoutMs)
    // A probe that could not run at all is not "this host cannot detach" — it
    // is "this host did not answer", and the attached executor is about to say
    // so with a better error than anything invented here. Cached anyway, so a
    // three-step job does not probe an unreachable host three times.
    const cap: JobHostCapability = r.ok
      ? parseJobProbe(r.stdout)
      : { root: null, launcher: 'none', base64: false, uid: null, ok: false, reason: r.error ?? 'the host did not answer the capability probe' }
    caps.set(req.serverId, cap)
    const report: JobHostCapabilityReport = {
      serverId: req.serverId,
      serverName: req.serverName,
      at: now(),
      detached: cap.ok,
      reason: cap.reason,
      root: cap.root,
      launcher: cap.launcher
    }
    reports.set(req.serverId, report)
    deps.onCapability?.(report)
    return cap
  }

  /**
   * Record that a host cannot detach after all, so the next step and the next
   * job take the attached path without paying for the discovery again.
   *
   * Keeps whatever the probe learned about the root and the launcher, because
   * "we found a writable /var/tmp and setsid, and it still did not detach" is
   * more useful to look at than a blanked row.
   */
  function degrade(req: JobExecRequest, reason: string): void {
    const cap = caps.get(req.serverId)
    caps.set(req.serverId, {
      root: cap?.root ?? null,
      launcher: cap?.launcher ?? 'none',
      base64: cap?.base64 ?? false,
      uid: cap?.uid ?? null,
      ok: false,
      reason
    })
    const report: JobHostCapabilityReport = {
      serverId: req.serverId,
      serverName: req.serverName,
      at: now(),
      detached: false,
      reason,
      root: cap?.root ?? null,
      launcher: cap?.launcher ?? 'none'
    }
    reports.set(req.serverId, report)
    deps.onCapability?.(report)
  }

  const exec: JobExecutor = async (req) => {
    // The switch, and the resume path, before anything else.
    //
    // A job being RECLAIMED is never sent down the attached path even when the
    // switch has since been turned off: there is a process running on that host
    // right now and a marker directory recording it, and the honest thing is to
    // finish watching it and reap it. Turning detached execution off means "do
    // not launch any more of these", not "abandon the ones already out there".
    if (req.resume) return await watch(req, req.resume)
    if (!deps.enabled()) return await deps.attached(req)

    const cap = await capabilityFor(req)
    if (!cap.ok || cap.root === null || cap.launcher === 'none') {
      req.onState?.({ degraded: cap.reason ?? 'this host cannot run a detached job' })
      return await deps.attached(req)
    }

    const dir = jobMarkerDir(cap.root, req.jobId, req.step)
    const handle: JobDetachedHandle = {
      v: 1,
      dir,
      step: req.step,
      instanceId: deps.instanceId,
      launcher: cap.launcher,
      base64: cap.base64,
      launchedAt: now(),
      readOffset: 0,
      command: req.command
    }

    const launch = await deps.run(
      req.cfg,
      buildJobLaunch({
        dir,
        jobId: req.jobId,
        instanceId: deps.instanceId,
        command: req.command,
        launcher: cap.launcher
      }),
      pollTimeoutMs
    )
    if (!launch.ok) {
      return { ok: false, code: null, error: launch.error ?? 'the launch command did not complete' }
    }
    const parsed = parseJobLaunch(launch.stdout)
    if (!parsed.ok) {
      return { ok: false, code: null, error: parsed.error ?? 'the launch did not take' }
    }

    // PERSISTED BEFORE THE FIRST POLL, and this ordering is the whole of "a
    // ShellPilot that never saw it start can pick it up". A crash between the
    // launch and the first write would leave a running command with nothing
    // recording where its marker is — reclaimable by nobody, swept a week
    // later, its output lost. The write costs one row.
    req.onState?.({ state: 'detached', detached: handle })
    return await watch(req, handle)
  }

  /**
   * Follow a detached step until it has an answer.
   *
   * Everything below is a loop over one poll, and the loop is the same whether
   * this instance launched the job a second ago or is picking up a marker
   * written by a ShellPilot that has since been restarted. That is deliberate:
   * a reclaim path that is a different code path from the live one is a reclaim
   * path that is exercised only in the failure people report.
   */
  async function watch(req: JobExecRequest, handle: JobDetachedHandle): Promise<JobExecResult> {
    let carry: Buffer = Buffer.alloc(0)
    let attempts = 0
    /** The state last reported, so a steady link does not rewrite the row every
     *  three seconds. */
    let reported: string | null = req.resume ? null : 'detached'
    let signalled = false
    /** Set when this pass knows there is more to read: poll again at once
     *  rather than at the next tick. A job producing megabytes drains at
     *  connection speed instead of at one window per poll interval. */
    let immediate = false
    const expectsReboot = restartsTheMachine(handle.command)
    const deadline = handle.launchedAt + req.timeoutMs

    const say = (state: 'running' | 'detached' | 'rebooting' | 'foreign', error?: string): void => {
      if (reported === state) return
      reported = state
      req.onState?.({ state, error })
    }
    const persist = (): void => req.onState?.({ detached: { ...handle } })

    for (;;) {
      // The run that owns this host has gone — the window closed, or a second
      // run took the id. Stop polling and leave the row saying `detached`: the
      // command is still going, the marker records where, and adopt() picks it
      // up at the next launch. Nothing terminal may be written here; that is
      // BLOCKER 1's rule and it is more load-bearing now than it was, because
      // now there really is something on the other end.
      if (req.alive && !req.alive()) {
        return { ok: false, code: null, detachedHandle: { ...handle }, finalState: 'detached' }
      }

      // PARK, do not error. `credentialResolver` throws VaultLockedError and a
      // loop that let that through would end a job which is running perfectly
      // well on fifteen hosts, because of something local and temporary. This
      // is fleetSampler's rule; the difference is that a parked SAMPLE loses a
      // data point and a parked JOB loses nothing at all, because the byte
      // offset makes the next poll pick up exactly where this one would have.
      if (deps.vaultUnlocked && !deps.vaultUnlocked()) {
        say('detached', 'Paused: the vault is locked, so this host cannot be polled. The job is ' +
          'still running on it and polling resumes when the vault is unlocked.')
        await sleep(parkMs)
        continue
      }

      if (immediate) immediate = false
      else await sleep(attempts === 0 ? pollMs : nextRetryDelay(attempts, random))

      // Only a RETRY goes through the gate. A healthy estate polls on its own
      // cadence and never queues; a wake-up, where every host retries at once,
      // is exactly what the cap is for.
      const release = attempts === 0 ? null : await gate.acquire()
      let r: JobRunResult
      try {
        r = await deps.run(
          req.cfg,
          buildJobPoll({ dir: handle.dir, offset: handle.readOffset, maxBytes: pollBytes, base64: handle.base64 }),
          pollTimeoutMs
        )
      } catch (e) {
        r = { ok: false, code: null, stdout: '', stderr: '', error: e instanceof Error ? e.message : String(e) }
      } finally {
        release?.()
      }

      if (!r.ok) {
        // THE LINK IS DOWN, THE JOB IS NOT. This is the state the whole item
        // exists to be able to express: `detached`, not `unreachable` and not
        // `failed`. A host that stopped answering while running a step that
        // restarts the machine is `rebooting`, which is the roadmap's example
        // of today's vocabulary getting a fact exactly backwards.
        attempts++
        say(expectsReboot ? 'rebooting' : 'detached', r.error)
        continue
      }

      const poll = parseJobPoll(r.stdout, { base64: handle.base64, carry })
      carry = poll.carry
      attempts = 0

      if (poll.sent > 0 && poll.text !== '') req.onOutput('out', poll.text)
      if (poll.sent > 0) {
        handle.readOffset += poll.sent
        persist()
      }

      const verdict = classifyJobPoll(poll, {
        instanceId: deps.instanceId,
        launchedAt: handle.launchedAt,
        now: now()
      })

      if (verdict.foreign) say('foreign', JOB_INSTANCE_NOTE)

      switch (verdict.phase) {
        case 'finished': {
          // Drain before answering. `rc` is read before the output on the host,
          // so a poll that reports it has already read everything the command
          // wrote — but the WINDOW is capped, so there may be more than one
          // poll's worth of it waiting. Ending here would truncate the tail of
          // the run, which is exactly where the answer to "did it work" is.
          if (poll.size > handle.readOffset) {
            immediate = true
            continue
          }
          if (!verdict.foreign) await reap(req, handle)
          return {
            ok: true,
            code: poll.rc,
            // Everything the command wrote came back on one stream, because the
            // wrapper redirects stderr into stdout: that is what keeps the two
            // in ORDER, which on an apt run is the difference between a
            // readable log and two shuffled halves. The cost is that the
            // runner's classifier cannot look at stderr alone, so it is told to
            // classify from the merged tail instead. `missing-command` and exit
            // 126 still resolve; the "permission denied and no stdout" rule
            // cannot, because there is no separate stdout to be empty.
            mergedOutput: true,
            detachedHandle: verdict.foreign ? { ...handle } : null
          }
        }
        case 'orphaned': {
          if (poll.size > handle.readOffset) {
            immediate = true
            continue
          }
          if (!verdict.foreign) await reap(req, handle)
          return {
            ok: false,
            code: null,
            error: JOB_ORPHANED_ERROR,
            finalState: 'orphaned',
            finalOutcome: 'orphaned',
            mergedOutput: true,
            detachedHandle: null
          }
        }
        case 'failed-launch': {
          // The marker is there and nothing ever wrote a pid, so the launcher
          // this host advertised does not actually detach anything. That is a
          // CAPABILITY failure found late rather than a job failure: the
          // marker is removed, the host is recorded as unable to detach with
          // the reason, and the step runs on the attached path — the same
          // outcome as a host that failed the probe up front, arrived at from
          // the other direction. Anything else would report a job failure for
          // something the operator can neither see nor fix.
          if (!verdict.foreign) await reap(req, handle)
          degrade(req, JOB_LAUNCH_FAILED_ERROR)
          req.onState?.({ state: 'running', detached: null, degraded: JOB_LAUNCH_FAILED_ERROR })
          return await deps.attached(req)
        }
        case 'missing': {
          // The directory is gone and we did not remove it. Either another
          // instance reaped it, or something cleared the state directory.
          // Whatever the command did is not knowable from here, and `orphaned`
          // is precisely that: no exit status will ever be read for this host.
          return {
            ok: false,
            code: null,
            error:
              'The marker directory for this job is no longer on the host, so its exit status ' +
              'cannot be read. Another ShellPilot may have reaped it, or the state directory was ' +
              'cleared underneath it.',
            finalState: 'orphaned',
            finalOutcome: 'orphaned',
            detachedHandle: null
          }
        }
        default: {
          // starting, or running.
          say('running')
          if (poll.more || poll.size > handle.readOffset) {
            immediate = true
            continue
          }
          if (now() > deadline) {
            // A timeout that leaves the command running has decided nothing —
            // jobExec's rule, and it costs more here, where "still running"
            // means a real process that outlives this app. Signalled once, then
            // one more pass to collect whatever it printed on the way down.
            if (!signalled) {
              signalled = true
              await deps.run(req.cfg, buildJobSignal({ dir: handle.dir }), pollTimeoutMs)
              immediate = true
              continue
            }
            return {
              ok: false,
              code: null,
              error:
                `Command timed out after ${req.timeoutMs}ms. SIGTERM was sent to the remote ` +
                `process; its marker directory is left in place so the exit status can still be ` +
                `read from ${handle.dir}.`,
              mergedOutput: true,
              detachedHandle: { ...handle }
            }
          }
          continue
        }
      }
    }
  }

  /**
   * Remove the marker directory, once its answer is in hand.
   *
   * Never for a foreign instance — that is the one operation which destroys
   * something another reader still needs, and it is the whole of what "detect
   * and degrade, do not lock" costs us. A reap that fails is not an error worth
   * failing a job over: the probe's sweep removes it a week later.
   */
  async function reap(req: JobExecRequest, handle: JobDetachedHandle): Promise<void> {
    try {
      await deps.run(req.cfg, buildJobReap({ dir: handle.dir }), pollTimeoutMs)
    } catch {
      /* the sweep in buildJobProbe is the backstop; see JOB_MARKER_SWEEP_DAYS */
    }
  }

  const executor = exec as DetachedExecutor
  executor.capabilities = (): JobHostCapabilityReport[] => [...reports.values()]
  executor.forget = (serverId: string): void => {
    caps.delete(serverId)
    reports.delete(serverId)
  }
  return executor
}
