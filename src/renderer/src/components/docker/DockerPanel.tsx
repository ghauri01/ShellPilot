import { useMemo, useRef, useState } from 'react'
import {
  Activity,
  Container,
  HardDrive,
  Info,
  Play,
  RefreshCw,
  RotateCw,
  ScrollText,
  Square,
  SquareTerminal,
  TriangleAlert
} from 'lucide-react'
import { useApp } from '../../store/app'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import {
  DOCKER_FAILURE_HELP,
  formatDockerEngineAge,
  groupByComposeProject,
  planDockerAction,
  validateContainerRef,
  type DockerAction,
  type DockerActionPlan,
  type DockerActionResult,
  type DockerBridge,
  type DockerContainer,
  type DockerDiskDetailProbe,
  type DockerDiskProbe,
  type DockerInspectProbe,
  type DockerProbe,
  type DockerStat
} from '../../../../shared/docker'
import type { Server } from '../../types'
import { ComposePanel } from './ComposePanel'

// Containers on a server, and what an operator does with them.
//
// Two jobs, and the second one only earns its place because the first is done
// properly:
//
//  1. Do not lie when docker cannot be read. A missing binary, a stopped daemon
//     and a permissions problem all produce "nothing" from a naive
//     implementation, and they have three different fixes. That rule holds for
//     every read here, not only the container list: a `docker system df` that
//     renders four zeroes because the socket refused us is the same lie in a
//     more expensive place, since disk-full is the incident people come here
//     during.
//  2. Change state only through the approval model. `planDockerAction` in
//     shared/docker.ts decides how hard the user has to press, and this file
//     obeys it — it never decides for itself that something is safe enough to
//     skip. The dialog below is deliberately the same shape as the broadcast
//     one, because it is the same model and a second dialect of it would be a
//     second thing to reason about.
//
// The MCP bridge cannot reach any of this. An agent gets `execute_command`
// gated per server against an access group; restarting a container is a
// different risk with a different consent story.

function stateTone(state: string): string {
  if (state === 'running') return ''
  if (state === 'exited' || state === 'dead') return 'danger'
  return 'warn'
}

function healthTone(health: string | null): string {
  if (health === 'healthy') return ''
  if (health === 'unhealthy') return 'danger'
  return 'warn'
}

/**
 * The bridge, treated as possibly-not-there.
 *
 * `DockerBridge` is declared in shared/docker.ts and the preload is annotated
 * with it, so the two halves type-check against one contract. `Partial` here is
 * not superstition: the renderer and the preload land in separate diffs, and a
 * panel that throws `undefined is not a function` on a channel that has not been
 * wired yet is worse than one with a button that says so.
 */
function bridge(): Partial<DockerBridge> | undefined {
  return (window.shellpilot as unknown as { docker?: Partial<DockerBridge> } | undefined)?.docker
}

/** Bytes as docker would have written them, for the totals docker does not total. */
function humanBytes(bytes: number): string {
  const units = ['B', 'kB', 'MB', 'GB', 'TB']
  let n = bytes
  let i = 0
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000
    i++
  }
  return `${n < 10 && i > 0 ? n.toFixed(2) : Math.round(n)}${units[i]}`
}

export function DockerPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [serverId, setServerId] = useState<string>('')
  const [probe, setProbe] = useState<DockerProbe | null>(null)
  const [loading, setLoading] = useState(false)
  const [logs, setLogs] = useState<{ name: string; output: string } | null>(null)
  const [logLines, setLogLines] = useState(200)
  const [logTimestamps, setLogTimestamps] = useState(false)
  // Sticky per panel: an operator who knows this account is not in the docker
  // group should not pay a failed round trip on every refresh.
  const [useSudo, setUseSudo] = useState(false)
  // null = not asked yet. Probed only when a permission failure makes it
  // relevant, so an ordinary host never runs a sudo probe at all.
  const [sudoAvailable, setSudoAvailable] = useState<boolean | null>(null)

  const [disk, setDisk] = useState<DockerDiskProbe | null>(null)
  const [diskLoading, setDiskLoading] = useState(false)
  // The itemised form, asked for separately: `docker system df -v` walks every
  // image and volume on the host, so an operator who only wanted the four
  // category totals should not pay for it.
  const [diskItems, setDiskItems] = useState<DockerDiskDetailProbe | null>(null)
  const [diskItemsLoading, setDiskItemsLoading] = useState(false)
  const [stats, setStats] = useState<Record<string, DockerStat> | null>(null)
  const [statsError, setStatsError] = useState<string | null>(null)
  const [statsLoading, setStatsLoading] = useState(false)
  const [detail, setDetail] = useState<{ id: string; probe: DockerInspectProbe | null } | null>(null)

  const [pending, setPending] = useState<{ plan: DockerActionPlan; refs: string[]; labels: string[] } | null>(null)
  const [phrase, setPhrase] = useState('')
  const [acting, setActing] = useState(false)
  const [actionResult, setActionResult] = useState<{ action: DockerAction; result: DockerActionResult } | null>(null)

  const openContainerShell = useApp((st) => st.openContainerShell)
  // True when this host's containers are being read as root — either because
  // the user pinned it, or because the automatic retry had to. Line 426 already
  // uses exactly this pair to draw the "reading as root" banner; the shell has
  // to make the same decision or it opens a session that cannot reach the
  // socket the listing just used.
  const usedSudoNow = useSudo || (probe?.ok && probe.usedSudo === true)

  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])
  const server = eligible.find((s) => s.id === serverId) ?? eligible[0]

  const cfgFor = (s: Server): unknown => ({
    sessionId: `docker-${s.id}`,
    cols: 80,
    rows: 24,
    serverId: s.id,
    host: s.host,
    port: s.port,
    username: s.username,
    auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
    hops: sshHopsFor(s)
  })

  // Commands are built from the container ID, never the display name.
  //
  // An id is hex, so it always passes the reference validator, it cannot
  // collide with another container's, and it cannot be a prefix of one — which
  // matters because the action parser attributes docker's error lines by
  // looking for the reference inside them. The name is what the user reads; the
  // id is what the host is told.
  const refOf = (c: DockerContainer): string => c.id

  // Every read below is a round trip that outlives the click that started it —
  // `Itemise` is allowed sixty seconds, and the panel stays fully usable while
  // it is in the air. If the operator switches server in that window, the
  // answer that eventually lands is about a host they are no longer looking
  // at: repository names, volume names and container names belonging to
  // somewhere else, rendered under the new server's heading with nothing to
  // say so — and the Itemise button hides itself once a listing exists, so
  // there is no way to notice or correct it. Each read stamps the generation
  // it started in; `clearReads` ends that generation, and an answer from a
  // dead one is dropped instead of shown.
  const generation = useRef(0)

  const clearReads = (): void => {
    generation.current++
    setLogs(null)
    setDisk(null)
    setDiskItems(null)
    setStats(null)
    setStatsError(null)
    setDetail(null)
    setActionResult(null)
    // The reads being abandoned owned these. Left set, the new server's
    // buttons sit disabled until a request about the old one comes back.
    setDiskLoading(false)
    setDiskItemsLoading(false)
    setStatsLoading(false)
  }

  const load = async (sudoOverride?: boolean): Promise<void> => {
    if (!server) return
    setLoading(true)
    clearReads()
    const gen = generation.current
    try {
      const r = await bridge()?.list?.(cfgFor(server), { sudo: sudoOverride ?? useSudo })
      if (generation.current !== gen) return
      setProbe(r ?? null)
      // Only ask about sudo once something has actually been refused by it —
      // and only when the automatic retry did not already solve it, which it
      // usually does.
      if (r && !r.ok && r.reason === 'permission-denied') {
        const can = await bridge()?.canSudo?.(cfgFor(server))
        if (generation.current !== gen) return
        setSudoAvailable(can ?? false)
      } else {
        setSudoAvailable(null)
      }
    } catch (e) {
      if (generation.current !== gen) return
      setProbe({ ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) })
    } finally {
      // In a finally, so a rejected invoke leaves a button the user can press
      // again rather than one that spins forever.
      setLoading(false)
    }
  }

  const openLogs = async (c: DockerContainer): Promise<void> => {
    if (!server) return
    // `docker:logs` is one of the handlers that can reject: the builder refuses
    // a reference it cannot prove safe rather than escaping it. Asking first
    // turns an unhandled rejection and a pane stuck on "Loading…" into a
    // sentence saying what happened.
    if (!validateContainerRef(refOf(c))) {
      setLogs({ name: c.name, output: 'This container has an id logs cannot be requested for safely.' })
      return
    }
    setLogs({ name: c.name, output: 'Loading…' })
    try {
      const r = await bridge()?.logs?.(cfgFor(server), refOf(c), logLines, {
        sudo: useSudo,
        timestamps: logTimestamps
      })
      setLogs({ name: c.name, output: r?.output || r?.error || 'No output.' })
    } catch (e) {
      setLogs({ name: c.name, output: e instanceof Error ? e.message : String(e) })
    }
  }

  const loadDisk = async (): Promise<void> => {
    if (!server) return
    setDiskLoading(true)
    const gen = generation.current
    try {
      const r = await bridge()?.disk?.(cfgFor(server), { sudo: useSudo })
      if (generation.current !== gen) return
      setDisk(r ?? { ok: false, reason: 'unknown', detail: 'Disk usage is not wired up in this build.' })
    } catch (e) {
      if (generation.current !== gen) return
      setDisk({ ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) })
    } finally {
      setDiskLoading(false)
    }
  }

  const loadDiskItems = async (): Promise<void> => {
    if (!server) return
    setDiskItemsLoading(true)
    const gen = generation.current
    try {
      const r = await bridge()?.diskDetail?.(cfgFor(server), { sudo: useSudo })
      if (generation.current !== gen) return
      setDiskItems(
        r ?? { ok: false, reason: 'unknown', detail: 'The itemised disk view is not wired up in this build.' }
      )
    } catch (e) {
      if (generation.current !== gen) return
      setDiskItems({ ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) })
    } finally {
      setDiskItemsLoading(false)
    }
  }

  const running = probe?.ok ? probe.containers.filter((c) => c.state === 'running') : []

  const loadStats = async (): Promise<void> => {
    if (!server || running.length === 0) return
    setStatsLoading(true)
    setStatsError(null)
    const gen = generation.current
    try {
      const r = await bridge()?.stats?.(cfgFor(server), running.map(refOf), { sudo: useSudo })
      if (generation.current !== gen) return
      if (!r) setStatsError('CPU and memory are not wired up in this build.')
      else if (!r.ok) setStatsError(`${DOCKER_FAILURE_HELP[r.reason]} ${r.detail}`)
      else {
        // docker keys stats by NAME, not by the reference it was given, so the
        // map is built on the name and read back through it.
        const byName: Record<string, DockerStat> = {}
        for (const s of r.stats) byName[s.name] = s
        setStats(byName)
      }
    } catch (e) {
      if (generation.current !== gen) return
      setStatsError(e instanceof Error ? e.message : String(e))
    } finally {
      setStatsLoading(false)
    }
  }

  const toggleDetail = async (c: DockerContainer): Promise<void> => {
    if (detail?.id === c.id) {
      setDetail(null)
      return
    }
    if (!server) return
    setDetail({ id: c.id, probe: null })
    const gen = generation.current
    try {
      const r = await bridge()?.inspect?.(cfgFor(server), refOf(c), { sudo: useSudo })
      if (generation.current !== gen) return
      setDetail({
        id: c.id,
        probe: r ?? { ok: false, reason: 'unknown', detail: 'Inspect is not wired up in this build.' }
      })
    } catch (e) {
      if (generation.current !== gen) return
      setDetail({
        id: c.id,
        probe: { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
      })
    }
  }

  // ---- state changes ----

  const runAction = async (action: DockerAction, refs: string[]): Promise<void> => {
    if (!server) return
    setPending(null)
    setPhrase('')
    setActing(true)
    setActionResult(null)
    try {
      const r = await bridge()?.act?.(cfgFor(server), action, refs, { sudo: useSudo })
      setActionResult({
        action,
        result: r ?? { ok: false, reason: 'unknown', detail: 'Container actions are not wired up in this build.' }
      })
      // The list is now stale whatever happened — including when it failed,
      // because a partial fan-out leaves some containers changed.
      if (r?.ok) await load()
    } catch (e) {
      setActionResult({
        action,
        result: { ok: false, reason: 'unknown', detail: e instanceof Error ? e.message : String(e) }
      })
    } finally {
      setActing(false)
    }
  }

  /**
   * Ask for an action, at whatever strength the plan says.
   *
   * The plan is never second-guessed here. `{ kind: 'none' }` runs on click
   * because the model says a single additive verb has already been approved by
   * the click; anything else opens the dialog. A panel that decided for itself
   * that some case was safe enough would be the model quietly ending.
   */
  const requestAction = (action: DockerAction, containers: DockerContainer[]): void => {
    const usable = containers.filter((c) => validateContainerRef(refOf(c)))
    if (usable.length === 0) return
    const refs = usable.map(refOf)
    const plan = planDockerAction(action, refs)
    if (plan.confirmation.kind === 'none') void runAction(action, refs)
    else setPending({ plan, refs, labels: usable.map((c) => c.name) })
  }

  const canConfirm =
    pending === null ||
    pending.plan.confirmation.kind !== 'type-to-confirm' ||
    phrase.trim() === pending.plan.confirmation.phrase

  const groups = probe?.ok ? groupByComposeProject(probe.containers) : []
  const diskTotalReclaimable =
    disk?.ok === true
      ? disk.rows.reduce((sum, r) => sum + (r.reclaimableBytes ?? 0), 0)
      : null

  const actionButtons = (c: DockerContainer): React.JSX.Element => (
    <>
      {c.state !== 'running' && (
        <button
          className="icon-btn sm"
          title={`Start ${c.name}`}
          disabled={acting}
          onClick={() => requestAction('start', [c])}
        >
          <Play size={13} />
        </button>
      )}
      {c.state === 'running' && (
        <>
          <button
            className="icon-btn sm"
            title={`Restart ${c.name}. Every connection it is serving is interrupted.`}
            disabled={acting}
            onClick={() => requestAction('restart', [c])}
          >
            <RotateCw size={13} />
          </button>
          <button
            className="icon-btn sm"
            title={`Stop ${c.name}. Every connection it is serving is interrupted.`}
            disabled={acting}
            onClick={() => requestAction('stop', [c])}
          >
            <Square size={13} />
          </button>
        </>
      )}
    </>
  )

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Container size={14} className="faint" />
        <b className="grow">Containers</b>
        <select
          className="input"
          style={{ maxWidth: 200 }}
          value={server?.id ?? ''}
          onChange={(e) => {
            setServerId(e.target.value)
            setProbe(null)
            clearReads()
          }}
        >
          {eligible.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
        <button className="btn" disabled={loading || !server} onClick={() => void load()}>
          <RefreshCw size={13} className={clsx(loading && 'spin')} /> {probe ? 'Refresh' : 'Read containers'}
        </button>
      </div>

      {eligible.length === 0 && <div className="s-desc">No server in this workspace is online.</div>}

      {!probe && !loading && eligible.length > 0 && (
        <div className="s-desc">
          Runs <span className="mono">docker ps</span> on the selected server using the docker binary
          already installed there. Reading only — nothing is started, stopped or removed until you ask
          for it.
        </div>
      )}

      {/* Three different problems, three different fixes. A panel that shows
          an empty list for all of them is lying about two. */}
      {probe && !probe.ok && (
        <div className="s-desc danger">
          <TriangleAlert size={12} /> {DOCKER_FAILURE_HELP[probe.reason]}
          <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
            {probe.detail}
          </div>
          {/* Offered the moment a permission failure is seen, rather than left
              for the user to work out. `sudo -n` never prompts, so if it is not
              available that is said plainly instead of producing a button that
              hangs on a password prompt with no tty to type into. */}
          {probe.reason === 'permission-denied' && sudoAvailable === true && (
            <div className="row" style={{ gap: 8, marginTop: 8, alignItems: 'center' }}>
              <button
                className="btn sm"
                onClick={() => {
                  setUseSudo(true)
                  void load(true)
                }}
              >
                Retry with sudo
              </button>
              <span className="faint">
                This account has passwordless sudo on that host, so containers can be read as root.
              </span>
            </div>
          )}
          {probe.reason === 'permission-denied' && sudoAvailable === false && (
            <div className="faint" style={{ marginTop: 6 }}>
              sudo would need a password here, and there is no terminal to type it into. Add this
              user to the docker group on the host, or configure passwordless sudo for it.
            </div>
          )}
        </div>
      )}

      {/* Once root is in use, say so and leave a way back. A panel silently
          reading as root is the thing worth avoiding, not root itself. */}
      {(useSudo || (probe?.ok && probe.usedSudo)) && (
        <div className="s-desc warn">
          {probe?.ok && probe.usedSudo && !useSudo
            ? 'Read as root: the unprivileged attempt was refused and passwordless sudo was available.'
            : 'Reading as root on every refresh. Container actions will also run as root.'}{' '}
          <button
            className="btn ghost sm"
            onClick={() => {
              setUseSudo(false)
              void load(false)
            }}
          >
            Stop using sudo
          </button>
        </div>
      )}

      {probe?.ok && (
        <>
          <div className="row muted" style={{ fontSize: 11, marginTop: 8, gap: 12, alignItems: 'center' }}>
            {/* null when the host answered with something that was not a
                version — podman's docker shim, most often. Saying nothing
                beats printing "docker null". */}
            <span>{probe.version ? `docker ${probe.version}` : 'docker'}</span>
            <span>
              {probe.containers.length} container{probe.containers.length === 1 ? '' : 's'}
            </span>
            <span className="grow" />
            <button className="btn ghost sm" disabled={diskLoading} onClick={() => void loadDisk()}>
              <HardDrive size={12} className={clsx(diskLoading && 'spin')} /> Disk usage
            </button>
            <button
              className="btn ghost sm"
              disabled={statsLoading || running.length === 0}
              title={
                running.length === 0
                  ? 'Nothing is running to sample.'
                  : 'One-shot CPU and memory for every running container.'
              }
              onClick={() => void loadStats()}
            >
              <Activity size={12} className={clsx(statsLoading && 'spin')} /> CPU &amp; memory
            </button>
          </div>

          {/* Grouping that could not be read is said out loud. "No compose
              projects here" and "this runtime would not tell me" look identical
              on screen otherwise, and only one of them is true. */}
          {probe.composeLabels === 'unavailable' && (
            <div className="faint" style={{ fontSize: 11 }}>
              This runtime did not report compose labels, so containers are not grouped by project.
            </div>
          )}

          {/* The file half.
              The grouping above is read from container LABELS, which say what is
              running. This says what is declared — and therefore which declared
              service has no container at all, which is the one fact nothing on
              this panel could state before. It is a separate read behind a
              button because it costs a bounded filesystem search. */}
          <ComposePanel
            server={server}
            cfg={cfgFor(server)}
            containers={probe.containers}
            sudo={usedSudoNow === true}
          />

          {/* Disk. The reclaimable column is the one people came for: it is the
              answer to "the disk is full and I do not know what is using it".
              Nothing here offers to reclaim it — see the note in
              shared/docker.ts about prune. */}
          {disk && !disk.ok && (
            <div className="s-desc danger">
              <TriangleAlert size={12} /> {DOCKER_FAILURE_HELP[disk.reason]}
              <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
                {disk.detail}
              </div>
            </div>
          )}
          {disk?.ok && (
            <>
              <div className="row muted" style={{ fontSize: 11, marginTop: 8 }}>
                <span className="grow">Disk usage</span>
                <button
                  className="btn ghost sm"
                  onClick={() => {
                    setDisk(null)
                    setDiskItems(null)
                  }}
                >
                  Close
                </button>
              </div>
              {disk.rows.map((r) => (
                <div key={r.type} className="cron-row">
                  <span className="mono cron-when">{r.type}</span>
                  <span className="faint cron-desc">
                    {r.active ?? '?'} of {r.total ?? '?'} in use
                  </span>
                  <span className="grow" />
                  <span className="mono">{r.size}</span>
                  <span className={clsx('chip', (r.reclaimablePercent ?? 0) >= 50 && 'warn')}>
                    {r.reclaimable === '' ? '—' : `${r.reclaimable} reclaimable`}
                  </span>
                </div>
              ))}
              {diskTotalReclaimable !== null && diskTotalReclaimable > 0 && (
                <div className="faint" style={{ fontSize: 11 }}>
                  {humanBytes(diskTotalReclaimable)} could be reclaimed. Nothing here removes it — what
                  counts as unused depends on which containers happen to be stopped right now, and that
                  is a judgement a button cannot make for you.
                </div>
              )}

              {/* The itemised view.
                  The four rows above say WHICH CATEGORY is big. They cannot say
                  which image, and "images: 12.71GB" is not something an operator
                  can act on. It is a second read rather than a wider first one
                  because `-v` walks every image and volume on the host. */}
              {diskItems && !diskItems.ok && (
                <div className="s-desc danger">
                  <TriangleAlert size={12} /> {DOCKER_FAILURE_HELP[diskItems.reason]}
                  <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
                    {diskItems.detail}
                  </div>
                </div>
              )}
              {/* Offered until there is a listing to show — not until there is
                  a RESULT. Gating on `=== null` made a failed probe a dead
                  end: an SSH timeout is the most likely way this read fails,
                  it is the most transient, and the only way out of it was to
                  close the whole disk card. */}
              {!diskItems?.ok && (
                <div className="row" style={{ marginTop: 6, gap: 8, alignItems: 'center' }}>
                  <button className="btn ghost sm" disabled={diskItemsLoading} onClick={() => void loadDiskItems()}>
                    <HardDrive size={12} className={clsx(diskItemsLoading && 'spin')} />{' '}
                    {diskItems === null ? 'Itemise' : 'Try again'}
                  </button>
                  {diskItems === null ? (
                    <span className="faint" style={{ fontSize: 11 }}>
                      Every image, container, volume and cache entry, largest first. Read-only.
                    </span>
                  ) : (
                    <button className="btn ghost sm" onClick={() => setDiskItems(null)}>
                      Close
                    </button>
                  )}
                </div>
              )}
              {diskItems?.ok && <DiskItems probe={diskItems} onClose={() => setDiskItems(null)} />}
            </>
          )}

          {statsError && <div className="s-desc danger">{statsError}</div>}

          {probe.containers.length === 0 && (
            <div className="faint" style={{ fontSize: 12 }}>
              Docker is running and has no containers.
            </div>
          )}

          {groups.map((g) => (
            <div key={g.project ?? ' ungrouped'}>
              {/* Only worth a header when there is more than one bucket —
                  otherwise it is a heading over the whole list saying nothing. */}
              {groups.length > 1 && (
                <div className="row muted" style={{ fontSize: 11, marginTop: 8, alignItems: 'center' }}>
                  <span className="grow">
                    {g.project === null ? 'Not part of a compose project' : g.project}
                  </span>
                  {g.project !== null && g.containers.some((c) => c.state === 'running') && (
                    <button
                      className="btn ghost sm"
                      disabled={acting}
                      title={`Restart every running container in ${g.project}. This takes the stack down and back up.`}
                      onClick={() =>
                        requestAction(
                          'restart',
                          g.containers.filter((c) => c.state === 'running')
                        )
                      }
                    >
                      <RotateCw size={12} /> Restart project
                    </button>
                  )}
                </div>
              )}

              {g.containers.map((c) => {
                const stat = stats?.[c.name]
                const open = detail?.id === c.id
                return (
                  <div key={c.id}>
                    <div className="cron-row">
                      <span className={clsx('chip', stateTone(c.state))}>{c.state}</span>
                      <span className="mono cron-when">{c.composeService ?? c.name}</span>
                      <span className="faint cron-desc">{c.image}</span>
                      <span className="faint grow" title={c.ports}>
                        {c.status}
                      </span>
                      {stat && (
                        <span className="faint mono" title={`${stat.memUsage} · net ${stat.netIo}`}>
                          {stat.cpuPercent === null ? '—' : `${stat.cpuPercent.toFixed(1)}%`} cpu ·{' '}
                          {stat.memPercent === null ? '—' : `${stat.memPercent.toFixed(1)}%`} mem
                        </span>
                      )}
                      <button
                        className={clsx('icon-btn sm', open && 'on')}
                        title="Ports, mounts, restart policy, health"
                        onClick={() => void toggleDetail(c)}
                      >
                        <Info size={13} />
                      </button>
                      <button className="icon-btn sm" title={`Logs for ${c.name}`} onClick={() => void openLogs(c)}>
                        <ScrollText size={13} />
                      </button>
                      {actionButtons(c)}
                      {/* Only for a container that is actually running — `docker exec`
                          into a stopped one fails with a message the user then has to
                          go and read, and the button implies it would work.
                          Deliberately no confirmation dialog: the user picked this
                          container and pressed a button labelled shell, which is the
                          approval. A modal here would be the nag that teaches
                          click-through on the ones that matter. */}
                      {c.state === 'running' && validateContainerRef(c.name) && server && (
                        <button
                          className="icon-btn sm"
                          title={`Open a shell in ${c.name}. This runs commands inside the container, on ${server.name}.`}
                          // Carries the sudo decision the listing already made. Without it the
                  // panel lists containers as root and then opens a shell as an
                  // account that cannot reach the socket — one feature behaving
                  // as two, which is exactly what an operator reported.
                  onClick={() => openContainerShell(server.id, c.name, usedSudoNow)}
                        >
                          <SquareTerminal size={13} />
                        </button>
                      )}
                    </div>

                    {open && <InspectDetail probe={detail?.probe ?? null} />}
                  </div>
                )
              })}
            </div>
          ))}
        </>
      )}

      {/* The same dialog shape as broadcast's, because it is the same model.
          The plan decides its strength; this only renders it. */}
      {pending && (
        <div className="bc-confirm">
          <div className="s-title">
            {pending.plan.action[0].toUpperCase() + pending.plan.action.slice(1)}{' '}
            {pending.refs.length === 1 ? 'this container' : `${pending.refs.length} containers`}?
          </div>
          <div className="s-desc mono">{pending.labels.join(', ')}</div>
          {pending.plan.reasons.length > 0 && (
            <div className="s-desc warn">
              <TriangleAlert size={12} /> {pending.plan.reasons.join('; ')}.
            </div>
          )}
          {pending.plan.confirmation.kind === 'type-to-confirm' && (
            <div className="input-group" style={{ marginTop: 6 }}>
              <input
                className="input"
                placeholder={`Type ${pending.plan.confirmation.phrase} to continue`}
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                autoFocus
              />
            </div>
          )}
          <div className="row" style={{ gap: 8, marginTop: 8 }}>
            <button
              className="btn primary"
              disabled={!canConfirm || acting}
              onClick={() => void runAction(pending.plan.action, pending.refs)}
            >
              {pending.plan.action[0].toUpperCase() + pending.plan.action.slice(1)}
            </button>
            <button
              className="btn ghost"
              onClick={() => {
                setPending(null)
                setPhrase('')
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Per container, always. "The command exited 1" says nothing about which
          of five containers is still up, which is the only question afterwards. */}
      {actionResult && (
        <div className={clsx('s-desc', actionResult.result.ok ? '' : 'danger')}>
          {!actionResult.result.ok && (
            <>
              <TriangleAlert size={12} /> {DOCKER_FAILURE_HELP[actionResult.result.reason]}
              <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
                {actionResult.result.detail}
              </div>
              {actionResult.result.reason === 'permission-denied' && !useSudo && (
                <div className="faint" style={{ marginTop: 6 }}>
                  The socket refused this account. Nothing was retried as root on its own — an action
                  running as root is a decision to make deliberately, not one to discover afterwards.
                  Turn sudo on above and try again if that is what you want.
                </div>
              )}
            </>
          )}
          {actionResult.result.ok && (
            <>
              <div>
                {actionResult.action}:{' '}
                {actionResult.result.outcomes.filter((o) => o.ok).length} of{' '}
                {actionResult.result.outcomes.length} succeeded
                {actionResult.result.usedSudo ? ', as root' : ''}.
              </div>
              {actionResult.result.outcomes
                .filter((o) => !o.ok)
                .map((o) => (
                  <div key={o.ref} className="mono danger" style={{ fontSize: 11 }}>
                    {o.ref.slice(0, 12)}: {o.error}
                  </div>
                ))}
              {actionResult.result.unattributed.map((line, i) => (
                <div key={i} className="mono faint" style={{ fontSize: 11 }}>
                  {line}
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {logs && (
        <>
          <div className="row muted" style={{ fontSize: 11, marginTop: 10, gap: 8, alignItems: 'center' }}>
            <span className="grow">Logs · {logs.name}</span>
            <select
              className="input"
              style={{ maxWidth: 110 }}
              value={logLines}
              onChange={(e) => setLogLines(Number(e.target.value))}
            >
              <option value={200}>200 lines</option>
              <option value={1000}>1000 lines</option>
              <option value={5000}>5000 lines</option>
            </select>
            <label className="row" style={{ gap: 4, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={logTimestamps}
                onChange={(e) => setLogTimestamps(e.target.checked)}
              />
              Timestamps
            </label>
            <button className="btn ghost sm" onClick={() => setLogs(null)}>
              Close
            </button>
          </div>
          <pre className="bc-out" style={{ marginLeft: 0, maxHeight: 300 }}>
            {logs.output}
          </pre>
        </>
      )}
    </div>
  )
}

/**
 * What a container is wired to.
 *
 * Environment is a COUNT and nothing else. The values are never read off the
 * host — the remote template computes `len` — because a container's environment
 * is where its database password lives, and this app's whole thesis is that
 * credentials do not leak. A "show env" button would be a one-line change and
 * that is exactly why the reason for its absence is written down here.
 */
function InspectDetail({ probe }: { probe: DockerInspectProbe | null }): React.JSX.Element {
  if (probe === null) {
    return (
      <div className="faint" style={{ fontSize: 11, padding: '4px 0 8px 12px' }}>
        Reading…
      </div>
    )
  }
  if (!probe.ok) {
    return (
      <div className="s-desc danger" style={{ marginLeft: 12 }}>
        <TriangleAlert size={12} /> {DOCKER_FAILURE_HELP[probe.reason]}
        <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
          {probe.detail}
        </div>
      </div>
    )
  }
  const i = probe.inspect
  return (
    <div style={{ padding: '4px 0 10px 12px', fontSize: 11 }} className="faint">
      <div className="row wrap" style={{ gap: 8, marginBottom: 4 }}>
        {i.health !== null && <span className={clsx('chip', healthTone(i.health))}>{i.health}</span>}
        <span className="chip">restart: {i.restartPolicy === '' ? 'unset' : i.restartPolicy}</span>
        {/* A restart count climbing on its own is a crash loop, and it is the
            one number here that is a diagnosis rather than a fact. */}
        {(i.restartCount ?? 0) > 0 && (
          <span className={clsx('chip', (i.restartCount ?? 0) > 5 && 'warn')}>
            restarted {i.restartCount}×
          </span>
        )}
        {i.exitCode !== null && i.status !== 'running' && <span className="chip">exit {i.exitCode}</span>}
        <span className="chip">{i.envCount ?? '?'} env vars</span>
        <span className="chip">logs: {i.logDriver === '' ? 'unknown' : i.logDriver}</span>
      </div>
      <div className="mono">image {i.image}</div>
      {/* The reference and the digest disagree constantly, and that
          disagreement — "latest" is not the latest here — is frequently the
          bug being hunted. */}
      <div className="mono">digest {i.imageId.replace(/^sha256:/, '').slice(0, 19)}</div>
      <div className="mono">started {i.startedAt}</div>
      {i.ports.length > 0 && (
        <div className="mono">
          ports{' '}
          {i.ports
            .map((p) => (p.host === '' ? `${p.container} (not published)` : `${p.host} → ${p.container}`))
            .join(', ')}
        </div>
      )}
      {i.mounts.length > 0 && (
        <div>
          {i.mounts.map((m) => (
            <div key={`${m.type}:${m.destination}`} className="mono">
              {m.type} {m.source} → {m.destination} ({m.mode})
            </div>
          ))}
        </div>
      )}
      {i.networks.length > 0 && (
        <div className="mono">
          networks {i.networks.map((n) => (n.ip === '' ? n.name : `${n.name} ${n.ip}`)).join(', ')}
        </div>
      )}
    </div>
  )
}

/**
 * The disk, item by item — and NOTHING that removes any of it.
 *
 * The summary above answers "which category is big". This answers "which one",
 * which is the question an operator actually has at 2am, and it answers it by
 * handing over a list they take into a shell. There is no delete button here
 * and its absence is a decision: what is safe to remove depends on which
 * containers happen to be stopped right now, and a list rendered thirty seconds
 * ago cannot know that.
 *
 * THE NUMBER THIS COMPONENT DOES NOT COMPUTE: a total. Image SIZE counts layers
 * shared with other images, so adding the rows up overstates the disk, often by
 * a multiple — and it looks right in any fixture, because a fixture has no
 * shared layers. The headline stays with `docker system df`, which did the
 * arithmetic on the host and knows about the sharing.
 */
function DiskItems({
  probe,
  onClose
}: {
  probe: Extract<DockerDiskDetailProbe, { ok: true }>
  onClose: () => void
}): React.JSX.Element {
  const d = probe.disk
  // Largest first, per kind. Sorting is most of the reason to itemise at all:
  // the answer is nearly always in the first two rows.
  const images = [...d.images].sort((a, b) => (b.uniqueSizeBytes ?? 0) - (a.uniqueSizeBytes ?? 0))
  const containers = [...d.containers].sort((a, b) => (b.sizeBytes ?? 0) - (a.sizeBytes ?? 0))
  const volumes = [...d.volumes].sort((a, b) => (b.sizeBytes ?? 0) - (a.sizeBytes ?? 0))
  const cache = [...d.buildCache].sort((a, b) => (b.sizeBytes ?? 0) - (a.sizeBytes ?? 0))
  const empty = images.length === 0 && containers.length === 0 && volumes.length === 0 && cache.length === 0

  // `.cron-when` has a minimum width and no maximum, and an image reference is
  // unbounded: `registry.example.com/platform/team/service:2024-11-04-abcdef`
  // pushed the size and the chips off the end of the row. Clipped here rather
  // than in the shared rule, which the scheduled-jobs table relies on.
  const nameCell: React.CSSProperties = {
    maxWidth: 320,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap'
  }

  const heading = (text: string, count: number): React.JSX.Element => (
    <div className="row muted" style={{ fontSize: 11, marginTop: 8 }}>
      <span className="grow">
        {text} ({count})
      </span>
    </div>
  )

  return (
    <>
      <div className="row muted" style={{ fontSize: 11, marginTop: 8, alignItems: 'center' }}>
        <span className="grow">By item</span>
        {/* Absolute, and computed on the host rather than looked up in a table
            of release dates that would need an owner and would eventually be
            wrong. Absent on a runtime that will not answer — podman's docker
            shim fails `.Server.*` templates outright — and saying nothing is
            the honest form of that. */}
        {probe.engine && <span className="faint">{formatDockerEngineAge(probe.engine, Date.now())}</span>}
        {/* This read has its own sudo failover, and the banner above the panel
            is about the CONTAINER LIST. Without this, a listing that had to
            escalate to root to be readable said nothing about it. */}
        {probe.usedSudo === true && <span className="faint">read as root</span>}
        <button className="btn ghost sm" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="faint" style={{ fontSize: 11 }}>
        Nothing on this list can be removed from here. It is the list to take into a shell.
      </div>

      {images.length > 0 && heading('Images', images.length)}
      {images.map((i) => (
        <div key={`${i.id}:${i.repository}:${i.tag}`} className="cron-row">
          <span className="mono cron-when" style={nameCell} title={`${i.repository}:${i.tag}`}>
            {i.repository}:{i.tag}
          </span>
          <span className="faint cron-desc">
            {i.id} · {i.created}
          </span>
          <span className="grow" />
          {/* An untagged image with nothing running off it is the classic
              leftover — a previous build's layers, orphaned by the next one. */}
          {i.dangling && <span className="chip warn">dangling</span>}
          <span className={clsx('chip', i.containers === 0 && 'warn')}>
            {i.containers ?? '?'} container{i.containers === 1 ? '' : 's'}
          </span>
          {/* UNIQUE SIZE, not SIZE. SIZE includes layers other images share, so
              it is the number that makes a 300MB image look like 900MB. */}
          <span
            className="mono"
            title={
              i.uniqueSize === ''
                // No UNIQUE SIZE column from this runtime, so the number shown
                // IS the total. Repeating it as "x including shared layers"
                // said the same figure twice and implied a comparison that was
                // never made.
                ? `${i.size} in total; this runtime did not report how much of it is unique to this image`
                : `${i.size} including shared layers`
            }
          >
            {i.uniqueSize === '' ? i.size : i.uniqueSize}
          </span>
        </div>
      ))}

      {containers.length > 0 && heading('Containers', containers.length)}
      {containers.map((c) => (
        <div key={c.id} className="cron-row">
          <span className="mono cron-when" style={nameCell} title={c.name}>
            {c.name}
          </span>
          <span className="faint cron-desc">{c.image}</span>
          <span className="grow" />
          <span className={clsx('chip', stateTone(c.state))}>{c.status}</span>
          {/* The writable layer only. The image's bytes are in the table above,
              and adding the two together would count them twice. */}
          <span className="mono" title="Writable layer, not the image">
            {c.size}
          </span>
        </div>
      ))}

      {volumes.length > 0 && heading('Volumes', volumes.length)}
      {volumes.map((v) => (
        <div key={v.name} className="cron-row">
          {/* A generated 64-hex name is unreadable at full length and its first
              twelve characters are what `docker volume ls` shows anyway. A name
              a person typed is shown whole. */}
          <span className="mono cron-when" style={nameCell} title={v.name}>
            {v.anonymous ? v.name.slice(0, 12) : v.name}
          </span>
          <span className="faint cron-desc">{v.anonymous ? 'anonymous' : 'named'}</span>
          <span className="grow" />
          {/* No links is not the same as unwanted: an anonymous volume with no
              links is usually rubbish, a NAMED one with no links is usually the
              database of something that happens to be stopped. */}
          {v.links === 0 && <span className={clsx('chip', v.anonymous && 'warn')}>no containers</span>}
          {(v.links ?? 0) > 0 && <span className="chip">{v.links} linked</span>}
          <span className="mono">{v.size}</span>
        </div>
      ))}

      {cache.length > 0 && heading('Build cache', cache.length)}
      {cache.map((c) => (
        <div key={c.id} className="cron-row">
          <span className="mono cron-when">{c.id}</span>
          <span className="faint cron-desc">
            {c.type} · last used {c.lastUsed === '' ? 'never' : c.lastUsed}
          </span>
          <span className="grow" />
          <span className="mono">{c.size}</span>
        </div>
      ))}

      {/* An answer, and one worth printing: four headings with nothing under
          any of them renders as silence otherwise, which reads like a view
          that failed to load rather than a host holding nothing. */}
      {empty && (
        <div className="faint" style={{ fontSize: 11 }}>
          Docker answered, and every table it printed was empty: there is nothing stored on this
          host. That is the reading, not a read that failed.
        </div>
      )}

      {/* Absent and empty are different sentences, and only one of them is
          about this host. podman has historically not printed a build cache
          table at all. */}
      {!d.sections.buildCache && (
        <div className="faint" style={{ fontSize: 11 }}>
          This runtime did not report a build cache.
        </div>
      )}
      {d.unreadable > 0 && (
        <div className="faint" style={{ fontSize: 11 }}>
          {d.unreadable} row{d.unreadable === 1 ? '' : 's'} of this listing could not be read, so
          {d.unreadable === 1 ? ' it is' : ' they are'} missing above rather than guessed at.
        </div>
      )}
    </>
  )
}
