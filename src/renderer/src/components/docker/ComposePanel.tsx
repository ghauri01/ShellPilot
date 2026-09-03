import { useState } from 'react'
import { Download, FileText, KeyRound, Layers, Pencil, Play, TriangleAlert } from 'lucide-react'
import { clsx } from '../../lib/format'
import { jobApprovalFor, planJob } from '../../../../shared/jobs'
import {
  COMPOSE_ENV_DISCLOSURE,
  COMPOSE_REFUSALS,
  COMPOSE_FAILURE_HELP,
  composeJobSpec,
  joinComposeState,
  planComposeImageEdit,
  validateImageRef,
  type ComposeAction,
  type ComposeBridge,
  type ComposeConfigProbe,
  type ComposeEnvFileSummary,
  type ComposeListProbe,
  type ComposeProjectRef,
  type ComposeProjectView,
  type ComposeServiceRunState
} from '../../../../shared/compose'
import type { DockerContainer } from '../../../../shared/docker'
import type { Server } from '../../types'

// Compose, the file half, sitting under the container list that already groups
// by project.
//
// The one thing this panel must never do is put an environment VALUE on screen.
// It cannot: no bridge method returns one. `compose:env-names` runs an awk
// program on the remote host that prints `S NAME` or `E NAME`, so the values
// are gone before the connection sees them, and the config read passes
// `--no-interpolate --no-env-resolution` so the model that comes back holds
// variable names in place of secrets. COMPOSE_ENV_DISCLOSURE is rendered
// verbatim next to the list, because an operator who does not know the
// withholding is deliberate will assume it is a bug and go looking for a
// setting that turns it off.
//
// `down` is not a button here and is not going to be one. COMPOSE_REFUSALS
// carries the reason in words and this panel prints it, which is the shape
// docker.ts already uses for prune: a refusal an operator can read and disagree
// with is better than a dialog that makes the same action feel more serious.
//
// `pull` and `up -d` go through the job engine — `composeJobSpec` produces a
// JobSpec, `jobApprovalFor` mints the record the runner re-checks. There is no
// compose execution path in this file; there is a compose SPEC, handed to the
// engine that already knows how to run one.

function bridge(): Partial<ComposeBridge> | undefined {
  return (window as unknown as { shellpilot?: { compose?: Partial<ComposeBridge> } }).shellpilot
    ?.compose
}

function jobsBridge():
  | { run: (req: unknown) => Promise<unknown> }
  | undefined {
  return (
    window as unknown as { shellpilot?: { jobs?: { run: (req: unknown) => Promise<unknown> } } }
  ).shellpilot?.jobs
}

const STATE_TONE: Record<ComposeServiceRunState, string> = {
  running: 'ok',
  partial: 'warn',
  stopped: 'warn',
  missing: 'danger'
}

const STATE_WORD: Record<ComposeServiceRunState, string> = {
  running: 'running',
  partial: 'partly up',
  stopped: 'stopped',
  // The word this whole panel exists to be able to say. A stopped service has a
  // container in the list above; a missing one has nothing anywhere.
  missing: 'never created'
}

export function ComposePanel({
  server,
  cfg,
  containers,
  sudo
}: {
  server: Server | undefined
  cfg: unknown
  containers: DockerContainer[]
  sudo: boolean
}): React.JSX.Element | null {
  const [list, setList] = useState<ComposeListProbe | null>(null)
  const [loading, setLoading] = useState(false)
  const [open, setOpen] = useState<string | null>(null)
  const [config, setConfig] = useState<ComposeConfigProbe | null>(null)
  const [configLoading, setConfigLoading] = useState(false)
  const [envFiles, setEnvFiles] = useState<ComposeEnvFileSummary[] | null>(null)
  const [envError, setEnvError] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ service: string; from: string; to: string } | null>(null)
  const [editError, setEditError] = useState<string | null>(null)
  const [editDone, setEditDone] = useState<string | null>(null)
  const [launched, setLaunched] = useState<string | null>(null)

  if (!server) return null

  const projectFor = (name: string): ComposeProjectRef | null => {
    const found = list?.ok ? list.projects.find((p) => p.name === name) : undefined
    if (found && found.configFiles.length > 0) return { name, files: found.configFiles }
    // A project found on disk rather than by the daemon. The directory's
    // basename is what compose itself would call it, but the NAME is passed
    // explicitly all the same — see buildComposeActionCommand.
    const hit = list?.ok ? list.search?.files.find((f) => f.directory.endsWith(`/${name}`)) : undefined
    return hit ? { name, files: [hit.path] } : null
  }

  const load = async (): Promise<void> => {
    setLoading(true)
    setOpen(null)
    setConfig(null)
    setEnvFiles(null)
    setEditing(null)
    setEditDone(null)
    setLaunched(null)
    try {
      setList((await bridge()?.list?.(cfg, { sudo })) ?? null)
    } finally {
      setLoading(false)
    }
  }

  const openProject = async (name: string): Promise<void> => {
    if (open === name) {
      setOpen(null)
      return
    }
    const ref = projectFor(name)
    setOpen(name)
    setConfig(null)
    setEnvFiles(null)
    setEnvError(null)
    setEditing(null)
    setEditDone(null)
    if (ref === null) return
    setConfigLoading(true)
    try {
      const probe = (await bridge()?.config?.(cfg, ref, { sudo })) ?? null
      setConfig(probe)
      // The env files a service declares, by NAME only. Asked for separately so
      // a project with none costs no round trip, and so a refused read here
      // does not take the service list with it.
      const paths = probe?.ok
        ? [...new Set(probe.config.services.flatMap((s) => s.envFiles))].filter((p) =>
            p.startsWith('/')
          )
        : []
      if (paths.length > 0) {
        const env = await bridge()?.envNames?.(cfg, paths, { sudo })
        if (env?.ok) setEnvFiles(env.files)
        else setEnvError(env ? env.detail : 'the env files could not be read')
      }
    } finally {
      setConfigLoading(false)
    }
  }

  const runJob = async (action: ComposeAction, name: string): Promise<void> => {
    const ref = projectFor(name)
    if (ref === null || !server) return
    const plan = composeJobSpec(action, ref, { sudo })
    const targets = [{ serverId: server.id, serverName: server.name }]
    const jobPlan = planJob(plan.spec, targets)
    // The engine re-derives this same plan from the same spec and refuses the
    // run if the record disagrees, so the phrase has to be the one the plan
    // asked for rather than one this panel decided was enough.
    const phrase =
      jobPlan.confirmation.kind === 'type-to-confirm' ? jobPlan.confirmation.phrase : null
    const approval = jobApprovalFor(plan.spec, targets, { phrase, confirmedAt: Date.now() })
    await jobsBridge()?.run({
      jobId: crypto.randomUUID(),
      spec: plan.spec,
      approval,
      targets: [{ serverId: server.id, serverName: server.name, cfg }]
    })
    setLaunched(`${plan.spec.title} — running as a job. Watch it on the Jobs panel.`)
  }

  const view: ComposeProjectView | null =
    open !== null && config?.ok ? joinComposeState(open, config.config, containers) : null

  const startEdit = (service: string, from: string): void => {
    setEditError(null)
    setEditDone(null)
    setEditing({ service, from, to: from })
  }

  const commitEdit = async (): Promise<void> => {
    if (editing === null || open === null) return
    const ref = projectFor(open)
    // The tag is edited in the FIRST file, which is the base compose file. An
    // override file that also sets the image would win, and this panel says so
    // rather than editing a line that has no effect.
    const path = ref?.files[0]
    if (path === undefined) return
    setEditError(null)
    const read = await bridge()?.readFile?.(cfg, path, { sudo })
    if (!read?.ok || read.text === undefined) {
      setEditError(read?.error ?? 'the compose file could not be read')
      return
    }
    const plan = planComposeImageEdit(read.text, editing.service, editing.to)
    if (!plan.ok) {
      setEditError(plan.reason)
      return
    }
    const result = await bridge()?.writeImageTag?.(
      cfg,
      {
        path,
        service: editing.service,
        image: editing.to,
        // What the operator is agreeing to, sent so main can refuse if the file
        // moved. Main re-reads and re-plans; this is the comparison, not the edit.
        expect: { line: plan.line, before: plan.before }
      },
      { sudo }
    )
    if (!result?.ok) {
      setEditError(result?.reason ?? 'the compose file was not written')
      return
    }
    setEditing(null)
    setEditDone(
      `${result.plan.service}: ${result.plan.from} → ${result.plan.to} on line ${result.plan.line}. ` +
        `The file it replaced is at ${result.backup}. Nothing is running the new image until you pull and bring it up.`
    )
  }

  return (
    <div style={{ marginTop: 12 }}>
      <div className="row muted" style={{ fontSize: 11, alignItems: 'center' }}>
        <Layers size={12} />
        <span className="grow">Compose projects</span>
        <button className="btn ghost sm" disabled={loading} onClick={() => void load()}>
          {list === null ? 'Find compose files' : 'Refresh'}
        </button>
      </div>

      {list && !list.ok && (
        <div className="s-desc danger">
          <TriangleAlert size={12} /> {COMPOSE_FAILURE_HELP[list.reason]}
          <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
            {list.detail}
          </div>
        </div>
      )}

      {list?.ok && (
        <>
          {/* "This host runs no compose projects" and "this host could not be
              asked" are different statements, and only one of them is ever
              true. */}
          {list.projectsFrom === 'unavailable' && (
            <div className="s-desc">{COMPOSE_FAILURE_HELP['compose-unavailable']}</div>
          )}

          {list.projects.map((p) => (
            <div key={p.name}>
              <div className="cron-row">
                <button className="btn ghost sm" onClick={() => void openProject(p.name)}>
                  {open === p.name ? '▾' : '▸'} {p.name}
                </button>
                <span className="faint cron-desc mono">{p.status}</span>
                <span className="grow" />
                <button
                  className="icon-btn sm"
                  title={`docker compose pull for ${p.name}. Fetches images; nothing running changes.`}
                  onClick={() => void runJob('pull', p.name)}
                >
                  <Download size={13} />
                </button>
                <button
                  className="icon-btn sm"
                  title={`docker compose up -d for ${p.name}. Starts what is declared; removes nothing.`}
                  onClick={() => void runJob('up', p.name)}
                >
                  <Play size={13} />
                </button>
              </div>
              {open === p.name && (
                <div style={{ paddingLeft: 12 }}>
                  <div className="faint mono" style={{ fontSize: 11 }}>
                    {p.configFiles.join('  ')}
                  </div>
                  {configLoading && <div className="faint">Reading the file…</div>}
                  {config && !config.ok && (
                    <div className="s-desc danger">
                      <TriangleAlert size={12} /> {COMPOSE_FAILURE_HELP[config.reason]}
                      <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
                        {config.detail}
                      </div>
                    </div>
                  )}
                  {config?.ok && config.config.namesOnly && (
                    <div className="faint" style={{ fontSize: 11 }}>
                      This engine would only give the service NAMES, so images, ports and
                      environment are unknown here rather than absent.
                    </div>
                  )}
                  {view?.services.map((s) => (
                    <div key={s.declared.name} className="cron-row">
                      <span className="mono cron-when">{s.declared.name}</span>
                      <span className={clsx('chip', STATE_TONE[s.state])}>{STATE_WORD[s.state]}</span>
                      <span className="faint cron-desc mono">
                        {s.declared.image ?? (s.declared.build ? 'built from source' : '—')}
                      </span>
                      <span className="grow" />
                      {s.declared.image !== null && (
                        <button
                          className="icon-btn sm"
                          title={`Change ${s.declared.name}'s image tag in the compose file. Nothing is pulled or restarted.`}
                          onClick={() => startEdit(s.declared.name, s.declared.image!)}
                        >
                          <Pencil size={13} />
                        </button>
                      )}
                    </div>
                  ))}

                  {view !== null && view.missing.length > 0 && (
                    <div className="faint" style={{ fontSize: 11 }}>
                      Declared but never created: {view.missing.join(', ')}. These have no container
                      at all, so they do not appear in the list above.
                    </div>
                  )}
                  {view !== null && view.undeclared.length > 0 && (
                    <div className="faint" style={{ fontSize: 11 }}>
                      Running under this project but not declared in the file:{' '}
                      {view.undeclared.map((c) => c.name).join(', ')}.
                    </div>
                  )}

                  {/* Environment. NAMES, and the sentence saying why. */}
                  {config?.ok &&
                    config.config.services.some((s) => s.environment.length > 0) && (
                      <div style={{ marginTop: 6 }}>
                        <div className="row muted" style={{ fontSize: 11 }}>
                          <KeyRound size={12} />
                          <span>Environment</span>
                        </div>
                        {config.config.services
                          .filter((s) => s.environment.length > 0)
                          .map((s) => (
                            <div key={s.name} className="cron-row">
                              <span className="mono cron-when">{s.name}</span>
                              <span className="faint cron-desc mono">
                                {s.environment
                                  .map(
                                    (v) =>
                                      `${v.name}=${v.set ? '(set)' : v.origin === 'passthrough' ? '(from host)' : '(empty)'}`
                                  )
                                  .join('  ')}
                              </span>
                            </div>
                          ))}
                      </div>
                    )}

                  {envFiles !== null && (
                    <div style={{ marginTop: 6 }}>
                      {envFiles.map((f) => (
                        <div key={f.path} className="cron-row">
                          <FileText size={12} className="faint" />
                          <span className="mono cron-when">{f.path}</span>
                          <span className="faint cron-desc mono">
                            {!f.readable
                              ? 'could not be read'
                              : f.names.length === 0
                                ? 'declares nothing'
                                : f.names
                                    .map((n) => `${n.name}=${n.set ? '(set)' : '(empty)'}`)
                                    .join('  ')}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  {envError !== null && (
                    <div className="faint" style={{ fontSize: 11 }}>
                      The env files could not be read: {envError}
                    </div>
                  )}
                  {(envFiles !== null ||
                    (config?.ok === true &&
                      config.config.services.some((s) => s.environment.length > 0))) && (
                    <div className="faint" style={{ fontSize: 11 }}>
                      {COMPOSE_ENV_DISCLOSURE}
                    </div>
                  )}

                  {/* The refusal, in words, where the button would have been. */}
                  <div className="faint" style={{ fontSize: 11, marginTop: 6 }}>
                    {COMPOSE_REFUSALS.down}
                  </div>
                </div>
              )}
            </div>
          ))}

          {/* Files on disk the daemon did not account for. */}
          {list.search !== null && list.search.files.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div className="row muted" style={{ fontSize: 11 }}>
                <FileText size={12} />
                <span>Compose files on disk</span>
              </div>
              {list.search.files.map((f) => (
                <div key={f.path} className="cron-row">
                  <span className="mono cron-when">{f.path}</span>
                </div>
              ))}
            </div>
          )}
          {list.search !== null && (
            /* The bounds are printed, not implied. An empty result from a
               search whose limits are invisible cannot be interpreted: it
               might mean there is nothing, or it might mean nobody looked
               where the files are. */
            <div className="faint" style={{ fontSize: 11 }}>
              Looked in {list.search.bound.roots.join(', ')}, {list.search.bound.maxDepth} levels
              deep, on this filesystem only, stopping at {list.search.bound.maxResults} files.
              Nothing outside those directories was read.
              {list.search.truncated &&
                ' That limit was reached, so this list is a prefix rather than an inventory.'}
            </div>
          )}
        </>
      )}

      {editing !== null && (
        <div className="s-desc" style={{ marginTop: 8 }}>
          <div>
            <b>{editing.service}</b> — change the image in the compose file. This writes one line and
            nothing else: no image is pulled and no container is restarted.
          </div>
          <input
            className="input"
            value={editing.to}
            onChange={(e) => setEditing({ ...editing, to: e.target.value })}
          />
          <div className="row" style={{ gap: 6, marginTop: 6 }}>
            <button
              className="btn sm"
              disabled={editing.to === editing.from || !validateImageRef(editing.to)}
              onClick={() => void commitEdit()}
            >
              Write the file
            </button>
            <button className="btn ghost sm" onClick={() => setEditing(null)}>
              Cancel
            </button>
          </div>
          {editing.to !== editing.from && !validateImageRef(editing.to) && (
            <div className="faint" style={{ fontSize: 11 }}>
              That is not an image reference this will write into a file.
            </div>
          )}
          {editError !== null && (
            <div className="danger" style={{ fontSize: 11 }}>
              {editError}
            </div>
          )}
        </div>
      )}

      {editDone !== null && <div className="s-desc">{editDone}</div>}
      {launched !== null && <div className="s-desc">{launched}</div>}
    </div>
  )
}
