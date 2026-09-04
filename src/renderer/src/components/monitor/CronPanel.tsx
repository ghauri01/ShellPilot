import { useMemo, useState } from 'react'
import { CalendarClock, Pencil, Plus, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import { sshHopsFor } from '../../lib/ssh'
import { clsx } from '../../lib/format'
import {
  CRON_STATUS_HELP,
  cronEditRefusal,
  describeSchedule,
  isValidCronSchedule,
  summariseCronSources
} from '../../../../shared/cron'
import type {
  CronEditBridge,
  CronEditPlanReply,
  CronEditRequest,
  CronEditTargetRef,
  CronEntry,
  CronSourceReport
} from '../../../../shared/cron'
import { approvalFor, planBroadcast } from '../../../../shared/broadcast'
import type { Server } from '../../types'

// What is scheduled across the estate — currently unanswerable without visiting
// every box.
//
// Reading came first on purpose. Cron's traps are all silent misreads rather
// than errors, so the parser earned trust against real hosts before anything
// was allowed to write — and two misreads turned up while it did.
//
// ---------------------------------------------------------------------------
// EDITING: ONE SOURCE, AND THE OTHERS REFUSED BY NAME
// ---------------------------------------------------------------------------
// Only the connected account's own crontab can be changed here. /etc/crontab,
// /etc/cron.d, systemd timers and other accounts' crontabs each say why not, on
// the row, rather than simply having no button — "why can't I edit this one" is
// a question with an answer, and an absent control does not give it.
//
// Nothing in this file builds a command. The panel sends the change it wants,
// main reads the crontab, works out the exact bytes, and hands them back to be
// confirmed; the confirmation is the broadcast/job approval record, because a
// cron edit is a write to the file that decides what runs unattended.

interface HostCron {
  serverId: string
  serverName: string
  entries: CronEntry[]
  unparsed: number
  /**
   * What each source had to say for itself.
   *
   * Optional because it arrives over IPC: a main process that has not been
   * taught to forward it sends nothing, and a panel that treated that as "all
   * five read fine" would be inventing the very reassurance this field exists
   * to withdraw.
   */
  sources?: CronSourceReport[]
  error?: string
}

/**
 * The edit channels, or null when this build's main process has none.
 *
 * Checked at runtime rather than assumed, for exactly the reason `sources` is
 * optional below: a main process that has not been taught these answers
 * nothing, and a button that silently does nothing is worse than no button.
 */
function editBridge(): CronEditBridge | null {
  const c = (window.shellpilot as { cron?: Partial<CronEditBridge> } | undefined)?.cron
  return c && typeof c.planEdit === 'function' && typeof c.write === 'function' ? (c as CronEditBridge) : null
}

const cfgFor = (s: Server): CronEditTargetRef['cfg'] => ({
  sessionId: `cron-${s.id}`,
  cols: 80,
  rows: 24,
  serverId: s.id,
  host: s.host,
  port: s.port,
  username: s.username,
  auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
  hops: sshHopsFor(s)
})

const KIND_LABEL: Record<CronEntry['kind'], string> = {
  'user-crontab': 'user crontab',
  'system-crontab': '/etc/crontab',
  'cron.d': 'cron.d',
  'systemd-timer': 'systemd timer',
  'other-user-crontab': 'crontab spool'
}

/**
 * What a host's list of jobs is actually worth.
 *
 * This is the whole point of the change. "Nothing scheduled." under a host name
 * is a claim, and until now it was made just as confidently for a box whose
 * /etc/cron.d we were refused as for one that genuinely has nothing. An
 * operator has no way to tell those apart from the outside, so the panel has to
 * say which it is.
 */
function SourceStatus({ sources }: { sources?: CronSourceReport[] }): React.JSX.Element {
  if (!sources || sources.length === 0) {
    return (
      <div className="faint" style={{ fontSize: 11 }}>
        This host did not report which sources it managed to read, so this list may be incomplete.
      </div>
    )
  }
  const { answered, total, incomplete, usedSudo } = summariseCronSources(sources)
  const complete = incomplete.length === 0
  return (
    <div style={{ fontSize: 11 }}>
      <span className={clsx(complete ? 'faint' : 'warn')}>
        {complete ? `read all ${total} sources` : `read ${answered} of ${total} sources`}
      </span>
      {/* Reading as root is a thing that happened, not an implementation
          detail. It is surfaced for the same reason the Docker panel surfaces
          it: silent escalation is the wrong trade even when it is the only way
          to get an answer. */}
      {usedSudo && (
        <span className="faint" title="Some sources were readable only as root, and were read with sudo -n — which never prompts.">
          {' '}
          · read as root
        </span>
      )}
      {incomplete.map((s) => (
        <div key={s.id} className="state-unknown" style={{ marginTop: 2 }}>
          <ShieldAlert size={11} /> {s.label}: {CRON_STATUS_HELP[s.status]}
          {s.detail ? ` (${s.detail})` : ''}
        </div>
      ))}
    </div>
  )
}

/** One job being written, identified by the line it came from — never by position. */
interface Draft {
  serverId: string
  /** The line as read, when an existing job is being changed. Absent when adding. */
  line?: string
  schedule: string
  command: string
}

/** A planned change, waiting for the operator to answer for it. */
interface Pending {
  target: CronEditTargetRef
  reply: CronEditPlanReply
  runId: string
}

/** The form for one job: a schedule and a command, and nothing clever. */
function JobForm({
  draft,
  onChange,
  onReview,
  onCancel,
  busy
}: {
  draft: Draft
  onChange: (d: Draft) => void
  onReview: () => void
  onCancel: () => void
  busy: boolean
}): React.JSX.Element {
  const scheduleOk = isValidCronSchedule(draft.schedule)
  // The same sentence the list shows, computed by the same function, so what
  // the operator reads before saving is what they will read afterwards. `null`
  // means "a valid schedule this will not describe" — a wrong sentence about
  // when a job runs is worse than none.
  const described = scheduleOk ? describeSchedule(draft.schedule) : null
  return (
    <div className="panel-note" style={{ display: 'grid', gap: 6, marginTop: 6 }}>
      <div className="row" style={{ gap: 6, alignItems: 'center' }}>
        <input
          className="input mono"
          style={{ maxWidth: 170 }}
          placeholder="0 3 * * *"
          value={draft.schedule}
          onChange={(e) => onChange({ ...draft, schedule: e.target.value })}
        />
        <input
          className="input mono grow"
          placeholder="/usr/bin/backup --all"
          value={draft.command}
          onChange={(e) => onChange({ ...draft, command: e.target.value })}
        />
      </div>
      <div className="row" style={{ gap: 8, alignItems: 'center', fontSize: 11 }}>
        <span className={clsx(scheduleOk ? 'faint' : 'warn')}>
          {scheduleOk
            ? (described ?? 'a schedule cron accepts — no plain-English reading of it is offered')
            : 'not a schedule cron accepts: five fields, or @reboot, @daily, @hourly and the rest'}
        </span>
        <span className="grow" />
        <button className="btn" onClick={onCancel}>
          Cancel
        </button>
        <button
          className="btn"
          disabled={busy || !scheduleOk || draft.command.trim() === ''}
          onClick={onReview}
        >
          Review change
        </button>
      </div>
    </div>
  )
}

export function CronPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [rows, setRows] = useState<HostCron[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [filter, setFilter] = useState('')
  const [draft, setDraft] = useState<Draft | null>(null)
  const [pending, setPending] = useState<Pending | null>(null)
  const [phrase, setPhrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<{ serverId: string; ok: boolean; text: string } | null>(null)

  const bridge = editBridge()
  const eligible = useMemo(() => servers.filter((s) => s.status !== 'offline'), [servers])
  const serverById = useMemo(() => new Map(servers.map((s) => [s.id, s])), [servers])

  /**
   * Whether this host's own crontab was read in full.
   *
   * `absent` counts: an account that has never scheduled anything HAS an empty
   * crontab, and the first job anybody adds goes into it. `partial`, `denied`
   * and `unknown` do not — a write replaces the whole file, so the part that
   * could not be read is the part it would delete.
   */
  const ownCrontabReadable = (h: HostCron): boolean => {
    const s = h.sources?.find((x) => x.id === 'user-crontab')
    return s !== undefined && (s.status === 'ok' || s.status === 'absent')
  }

  /** Read the crontab, work out the exact bytes, and hold them for confirmation. */
  const review = async (server: Server, host: HostCron, req: CronEditRequest): Promise<void> => {
    if (!bridge) return
    setBusy(true)
    setNote(null)
    try {
      const target: CronEditTargetRef = {
        serverId: server.id,
        serverName: server.name,
        cfg: cfgFor(server)
      }
      const reply = await bridge.planEdit(target, req, { sources: host.sources })
      if (!reply.ok || !reply.command) {
        setPending(null)
        setNote({ serverId: server.id, ok: false, text: reply.reason ?? 'the change could not be planned.' })
        return
      }
      setPhrase('')
      setPending({ target, reply, runId: `cron-edit-${Date.now().toString(36)}` })
    } finally {
      setBusy(false)
    }
  }

  /**
   * Answer for the change, and make it.
   *
   * The plan is re-derived here rather than carried from `review`, because that
   * is what the record is FOR: main re-derives it a third time and refuses if
   * the two disagree, so a plan computed once and passed around would be one
   * fact where the model wants two that must agree.
   */
  const apply = async (): Promise<void> => {
    const command = pending?.reply.command
    if (!bridge || !pending || command === undefined) return
    const { target, reply, runId } = pending
    const ref = { serverId: target.serverId, serverName: target.serverName }
    const plan = planBroadcast(command, [ref])
    const needed = plan.confirmation.kind === 'type-to-confirm' ? plan.confirmation.phrase : null
    if (needed !== null && phrase.trim() !== needed) return
    setBusy(true)
    try {
      const res = await bridge.write(target, {
        before: reply.before ?? '',
        after: reply.after ?? '',
        token: reply.token ?? '',
        runId,
        approval: approvalFor({
          surface: 'broadcast',
          commands: [command],
          targets: [ref],
          plan,
          phrase: needed,
          confirmedAt: Date.now()
        })
      })
      setNote({
        serverId: target.serverId,
        ok: res.ok,
        text: res.ok
          ? `Changed. The crontab as it was is on the host at ${res.backupPath ?? 'the backup path it reported'}.`
          : res.detail
      })
      setPending(null)
      setDraft(null)
      // Read it again rather than patching the list from what we sent. The
      // host is the only thing that knows what its crontab says now.
      await collect()
    } finally {
      setBusy(false)
    }
  }

  const collect = async (): Promise<void> => {
    setLoading(true)
    try {
      const res = await window.shellpilot?.cron?.collect(
        eligible.map((s) => ({
          serverId: s.id,
          serverName: s.name,
          cfg: cfgFor(s)
        }))
      )
      setRows(res ?? [])
    } finally {
      // The handler catches per host today, so nothing here throws — but one
      // rejected invoke away, a button that never stops spinning is a UI that
      // has silently stopped working.
      setLoading(false)
    }
  }

  /**
   * Edit and remove, or the reason there is neither.
   *
   * The refusal is shown ON THE ROW rather than by leaving the buttons out.
   * "Why can't I edit this one" is a question with a real answer — /etc/cron.d
   * is root-owned and package-managed, a systemd timer is two unit files and a
   * daemon-reload — and a control that is simply absent does not give it.
   */
  // Called, not rendered as <RowControls/>. A component DEFINED inside another
  // component is a new component type on every render, so React unmounts and
  // remounts its whole subtree each time the parent renders — which here meant
  // the confirmation's input lost focus after the first keystroke and the word
  // the operator was asked to type could never be typed. Calling the function
  // inlines the JSX and creates no boundary to remount.
  const rowControls = (host: HostCron, entry: CronEntry): React.JSX.Element => {
    const refusal = cronEditRefusal(entry.kind)
    if (refusal !== null) {
      return (
        <span className="faint" style={{ fontSize: 11 }} title={refusal}>
          not editable
        </span>
      )
    }
    // A job with no line behind it is one we cannot point at. It should not
    // happen for a crontab; if it ever does, saying so beats a button that
    // resolves to whatever line happens to match.
    if (entry.line === undefined || !ownCrontabReadable(host)) {
      return <span className="faint" style={{ fontSize: 11 }} />
    }
    const srv = serverById.get(host.serverId)
    if (!srv) return <span className="faint" style={{ fontSize: 11 }} />
    return (
      <span className="row" style={{ gap: 4 }}>
        <button
          className="btn"
          disabled={busy}
          title="Change this job"
          onClick={() => {
            setPending(null)
            setNote(null)
            setDraft({
              serverId: host.serverId,
              line: entry.line,
              schedule: entry.schedule,
              command: entry.command
            })
          }}
        >
          <Pencil size={12} />
        </button>
        <button
          className="btn"
          disabled={busy}
          title="Remove this job"
          onClick={() => {
            setDraft(null)
            if (entry.line !== undefined) void review(srv, host, { op: 'remove', line: entry.line })
          }}
        >
          <Trash2 size={12} />
        </button>
      </span>
    )
  }

  /**
   * What is about to happen, in the words of the thing that will do it.
   *
   * The summary and the backup are main's, not this panel's — the panel never
   * builds a command and never works out the bytes, so there is nothing here
   * that could describe the change differently from the change.
   */
  const confirmation = (): React.JSX.Element | null => {
    if (!pending?.reply.command) return null
    const ref = { serverId: pending.target.serverId, serverName: pending.target.serverName }
    const plan = planBroadcast(pending.reply.command, [ref])
    const needed = plan.confirmation.kind === 'type-to-confirm' ? plan.confirmation.phrase : null
    return (
      <div className="panel-note" style={{ display: 'grid', gap: 6, marginTop: 6 }}>
        <div className="mono" style={{ fontSize: 12 }}>
          {pending.reply.summary}
        </div>
        <div className="faint" style={{ fontSize: 11 }}>
          The whole crontab is replaced — that is the only way to write one — after a timestamped
          copy of it is kept on {pending.target.serverName}. It is written back only if the file is
          still the one this was planned against, and it is read back afterwards and compared; if it
          does not match, the copy goes straight back.
        </div>
        {pending.reply.addedFinalNewline && (
          <div className="state-watch" style={{ fontSize: 11 }}>
            <ShieldAlert size={11} /> This crontab has no newline at the end of its last line, so one
            is being added. Without it the new job would be glued onto the end of the previous one.
          </div>
        )}
        <div className="row" style={{ gap: 8, alignItems: 'center' }}>
          {needed !== null && (
            <input
              className="input mono"
              style={{ maxWidth: 120 }}
              placeholder={`Type ${needed}`}
              value={phrase}
              onChange={(e) => setPhrase(e.target.value)}
            />
          )}
          <span className="grow" />
          <button className="btn" onClick={() => setPending(null)}>
            Cancel
          </button>
          <button
            className="btn danger"
            disabled={busy || (needed !== null && phrase.trim() !== needed)}
            onClick={() => void apply()}
          >
            Apply to {pending.target.serverName}
          </button>
        </div>
      </div>
    )
  }

  const q = filter.trim().toLowerCase()
  const visible = (rows ?? []).map((h) => ({
    ...h,
    entries: q === '' ? h.entries : h.entries.filter((e) => `${e.command} ${e.origin} ${e.user ?? ''}`.toLowerCase().includes(q))
  }))
  const total = visible.reduce((n, h) => n + h.entries.length, 0)
  const failed = visible.filter((h) => h.error)
  const unparsed = visible.reduce((n, h) => n + h.unparsed, 0)
  const partial = visible.filter(
    (h) => !h.error && (h.sources?.length ?? 0) > 0 && summariseCronSources(h.sources ?? []).incomplete.length > 0
  ).length

  return (
    <div className="bc-panel">
      <div className="panel-head">
        <span className="panel-head-icon">
          <CalendarClock size={14} />
        </span>
        <h2 className="ui-section-title">Scheduled jobs</h2>
        <p className="ui-note panel-head-purpose">
          Every crontab and systemd timer across the estate, and which of them this account was
          actually allowed to read.
        </p>
        <div className="panel-head-actions">
          {rows && (
            <input
              className="input"
              style={{ maxWidth: 220 }}
              placeholder="Filter by command or file…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          )}
          <button
            className="btn primary"
            disabled={loading || eligible.length === 0}
            onClick={() => void collect()}
          >
            <RefreshCw size={13} className={clsx(loading && 'spin')} /> {rows ? 'Refresh' : 'Read schedules'}
          </button>
        </div>
      </div>

      {!rows && !loading && (
        // Before anything has been read this IS the panel, so it is framed as
        // an empty state rather than set at body weight beside the button.
        <div className="panel-empty">
          <p className="panel-empty-title">Nothing has been read yet.</p>
          <p className="panel-empty-body">
            Reads crontabs, /etc/crontab, /etc/cron.d, other accounts’ crontabs and systemd timers
            from every online server, and says which of those it was actually allowed to read.
            Sources that are root-only are retried with <span className="mono">sudo -n</span>, which
            never prompts for a password. Nothing is written or changed — this only looks.
          </p>
          <p className="panel-empty-body">
            Press <b>Read schedules</b> above to start.
          </p>
        </div>
      )}

      {rows && (
        <>
          <div className="panel-stats">
            <span>
              {total} job{total === 1 ? '' : 's'} across {visible.length - failed.length} host
              {visible.length - failed.length === 1 ? '' : 's'}
            </span>
            {/* Lines that looked like jobs but did not parse are counted, not
                hidden. A schedule silently missing from this view is a command
                running on a box that nobody knows about. */}
            {unparsed > 0 && <span className="state-unknown">{unparsed} line{unparsed === 1 ? '' : 's'} not understood</span>}
            {/* Counted across the estate as well as per host: with a dozen
                servers, a single host whose cron.d was refused is easy to
                scroll past, and it is exactly the host you would want to look
                at. */}
            {partial > 0 && (
              <span className="state-unknown">
                {partial} host{partial === 1 ? '' : 's'} only partly readable
              </span>
            )}
          </div>

          {failed.map((h) => (
            <div key={h.serverId} className="panel-note is-alarm">
              {h.serverName}: {h.error}
            </div>
          ))}

          {visible
            .filter((h) => !h.error)
            .map((h) => (
              <div key={h.serverId} style={{ marginTop: 10 }}>
                <div className="row panel-subtitle" style={{ gap: 8, alignItems: 'center' }}>
                  <span className="grow">
                    {h.serverName} <span className="faint">· {h.entries.length}</span>
                  </span>
                  {bridge && serverById.get(h.serverId) && ownCrontabReadable(h) && (
                    <button
                      className="btn"
                      disabled={busy}
                      onClick={() =>
                        setDraft({ serverId: h.serverId, schedule: '0 3 * * *', command: '' })
                      }
                    >
                      <Plus size={12} /> Add job
                    </button>
                  )}
                </div>
                <SourceStatus sources={h.sources} />
                {/* Why the buttons are not there, rather than simply not
                    putting them there. An operator looking at a host whose
                    crontab we only half read deserves the reason. */}
                {bridge && !ownCrontabReadable(h) && (
                  <div className="faint" style={{ fontSize: 11 }}>
                    This account’s crontab was not read in full, so nothing here can be edited.
                  </div>
                )}
                {note?.serverId === h.serverId && (
                  <div className={clsx('panel-note', note.ok ? '' : 'is-alarm')}>{note.text}</div>
                )}
                {draft?.serverId === h.serverId && draft.line === undefined && (
                  <JobForm
                    draft={draft}
                    busy={busy}
                    onChange={setDraft}
                    onCancel={() => {
                      setDraft(null)
                      setPending(null)
                    }}
                    onReview={() => {
                      const srv = serverById.get(h.serverId)
                      if (srv)
                        void review(srv, h, {
                          op: 'add',
                          schedule: draft.schedule.trim(),
                          command: draft.command
                        })
                    }}
                  />
                )}
                {pending?.target.serverId === h.serverId && confirmation()}
                {h.entries.length === 0 && (
                  <div className="faint" style={{ fontSize: 12 }}>
                    {q !== ''
                      ? 'Nothing matching.'
                      : // Only claimed when every source actually answered. On a
                        // host where /etc/cron.d was refused, "Nothing
                        // scheduled" is a sentence about our permissions
                        // wearing a sentence about the host.
                        (h.sources?.length ?? 0) > 0 &&
                          summariseCronSources(h.sources ?? []).incomplete.length === 0
                        ? 'Nothing scheduled.'
                        : 'Nothing found in the sources that could be read.'}
                  </div>
                )}
                {h.entries.map((e, i) => (
                  <div key={`${e.origin}:${i}`}>
                  <div className="cron-row">
                    <span className="chip">{KIND_LABEL[e.kind]}</span>
                    <span className="mono cron-when">
                      {e.kind === 'systemd-timer' ? (e.nextRun ? `next ${e.nextRun}` : 'no next run') : e.schedule}
                    </span>
                    {/* Null means "a valid schedule I decline to describe".
                        A wrong sentence about when a job runs is worse than
                        none. */}
                    <span className="faint cron-desc">{e.description ?? ''}</span>
                    {/* `e.input` is the text after an unescaped `%`, which
                        cron pipes to the command on stdin rather than running.
                        Showing it inside the command would be showing a command
                        that is not the one that runs. */}
                    <span
                      className="mono grow cron-cmd"
                      title={e.input === undefined ? e.command : `${e.command}\n\nstdin:\n${e.input}`}
                    >
                      {e.command}
                      {e.input !== undefined && <span className="faint"> · stdin</span>}
                    </span>
                    {e.user && <span className="faint">{e.user}</span>}
                    {bridge && rowControls(h, e)}
                  </div>
                  {draft?.serverId === h.serverId && draft.line !== undefined && draft.line === e.line && (
                    <JobForm
                      draft={draft}
                      busy={busy}
                      onChange={setDraft}
                      onCancel={() => {
                        setDraft(null)
                        setPending(null)
                      }}
                      onReview={() => {
                        const srv = serverById.get(h.serverId)
                        if (srv && draft.line !== undefined)
                          void review(srv, h, {
                            op: 'update',
                            line: draft.line,
                            schedule: draft.schedule.trim(),
                            command: draft.command,
                            ...(e.input === undefined ? {} : { input: e.input })
                          })
                      }}
                    />
                  )}
                  </div>
                ))}
              </div>
            ))}
        </>
      )}
    </div>
  )
}
