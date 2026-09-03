import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Plus, Trash2, Zap } from 'lucide-react'
import { clsx } from '../../lib/format'
import {
  RULE_ALERT_KINDS,
  RULE_LIMIT_DEFAULT,
  RULE_LIMIT_MAX_FIRINGS,
  RULE_UNATTENDED_PHRASE,
  ruleCreationConfirmation,
  ruleJobPlan,
  type RuleAction,
  type RuleAlertKind,
  type RuleDraftWire,
  type RuleTriggerEvent,
  type RuleView,
  type RulesBridge
} from '../../../../shared/rules'
import { jobApprovalFor } from '../../../../shared/jobs'
import type { JobSpec, JobTargetRef } from '../../../../shared/jobs'
import type { Server } from '../../types'

// Rules — roadmap item 27.
//
// "When this alert fires, run that job, then call that webhook." The whole of
// what a rule is lives in src/shared/rules.ts, including the argument for why a
// job rule is pinned to the spec and the host list it was written with. This
// panel's job is to make that pinning VISIBLE, because a standing authorisation
// nobody can read back is not consent, it is a setting.
//
// So three things are on screen for every rule, always, and none of them is
// behind a disclosure triangle:
//
//  1. WHAT IT RUNS AND WHERE — the step text and the host names, not a job id.
//  2. HOW OFTEN IT MAY ACT — the rate limit as a sentence, and how many
//     matching events it has already declined to act on.
//  3. WHETHER IT STILL CAN — the verdict, re-derived by main on every read. A
//     rule whose approval has drifted reads as refusing HERE, in daylight,
//     rather than being discovered from a webhook at 3am.
//
// And the creation form always demands a typed word for a job rule, which
// `planJob` would not: an ordinary command on two hosts needs one click as a
// job and needs somebody to have noticed as a standing authorisation. See
// `ruleCreationConfirmation`.

function bridge(): Partial<RulesBridge> | undefined {
  return (window.shellpilot as unknown as { rules?: Partial<RulesBridge> } | undefined)?.rules
}

const KIND_LABEL: Record<RuleAlertKind, string> = {
  cpu: 'CPU',
  disk: 'Disk',
  inode: 'Inodes',
  load: 'Load',
  'host-unreachable': 'Host unreachable',
  'job-failed': 'Job failed',
  'tunnel-down': 'Tunnel down',
  'db-alarm': 'Database alarm',
  'db-watch': 'Database watch'
}

const WINDOWS: { ms: number; label: string }[] = [
  { ms: 60_000, label: 'a minute' },
  { ms: 600_000, label: '10 minutes' },
  { ms: 3_600_000, label: 'an hour' },
  { ms: 6 * 3_600_000, label: '6 hours' },
  { ms: 86_400_000, label: 'a day' }
]

function windowLabel(ms: number): string {
  return WINDOWS.find((w) => w.ms === ms)?.label ?? `${Math.round(ms / 60_000)} minutes`
}

/** The rate limit as a sentence. A pair of numbers in a table is not something
 *  anyone reads as "this may restart your database once an hour". */
function limitText(maxFirings: number, windowMs: number): string {
  const times = maxFirings === 1 ? 'once' : `${maxFirings} times`
  return `At most ${times} in ${windowLabel(windowMs)}`
}

function when(rule: RuleView): string {
  const kind = KIND_LABEL[rule.trigger.kind as RuleAlertKind] ?? rule.trigger.kind
  const parts = [`${kind} ${rule.trigger.event}`]
  if (rule.filter.serverId !== undefined) parts.push('on one host')
  if (rule.filter.minValue !== undefined) parts.push(`at or above ${rule.filter.minValue}`)
  return parts.join(', ')
}

function RuleCard({
  rule,
  servers,
  onToggle,
  onRemove
}: {
  rule: RuleView
  servers: Server[]
  onToggle: (enabled: boolean) => void
  onRemove: () => void
}): React.JSX.Element {
  const hostName = (id: string): string => servers.find((s) => s.id === id)?.name ?? id
  const job = rule.action.type === 'job' ? rule.action : null

  return (
    <div className={clsx('card', 'col')} style={{ gap: 8, padding: 12 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline', gap: 8 }}>
        <b>{rule.name || 'Untitled rule'}</b>
        <div className="row" style={{ gap: 8 }}>
          <label className="row" style={{ gap: 4, fontSize: 12 }}>
            <input
              type="checkbox"
              checked={rule.enabled}
              aria-label={`Enable ${rule.name}`}
              onChange={(e) => onToggle(e.target.checked)}
            />
            {rule.enabled ? 'Enabled' : 'Disabled'}
          </label>
          <button className="btn ghost" aria-label={`Delete ${rule.name}`} onClick={onRemove}>
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      <div style={{ fontSize: 12 }}>
        <span className="faint">When </span>
        {when(rule)}
      </div>

      {job === null ? (
        <div style={{ fontSize: 12 }}>
          <span className="faint">Then </span>
          post to the configured webhook
        </div>
      ) : (
        <div className="col" style={{ gap: 4, fontSize: 12 }}>
          <div>
            <span className="faint">Then run </span>
            {job.spec.title}
            <span className="faint"> on </span>
            {job.targets.map((t) => hostName(t.serverId)).join(', ')}
          </div>
          {/* The step text itself, never a job id. What a rule runs is the
              thing a person has to be able to check a year later. */}
          {job.spec.steps.map((s, i) => (
            <code key={i} style={{ fontSize: 11, wordBreak: 'break-all' }}>
              {s.command}
            </code>
          ))}
        </div>
      )}

      <div className="faint" style={{ fontSize: 11 }}>
        {limitText(rule.limit.maxFirings, rule.limit.windowMs)}
        {rule.status.lastFiredAt !== undefined
          ? ` · last acted ${new Date(rule.status.lastFiredAt).toLocaleString()}`
          : ' · has not acted yet'}
        {rule.status.suppressed > 0
          ? ` · ${rule.status.suppressed} matching event(s) declined by the rate limit`
          : ''}
      </div>

      {/* A rule that cannot run says so here rather than at 3am. */}
      {!rule.verdict.ok && (
        <div className="row danger" style={{ gap: 6, fontSize: 12, alignItems: 'flex-start' }}>
          <AlertTriangle size={14} />
          <span>This rule will not run: {rule.verdict.reason}</span>
        </div>
      )}
      {rule.verdict.ok && rule.status.refusal !== undefined && (
        <div className="row warn" style={{ gap: 6, fontSize: 12, alignItems: 'flex-start' }}>
          <AlertTriangle size={14} />
          <span>Last time it fired it was refused: {rule.status.refusal}</span>
        </div>
      )}
    </div>
  )
}

export function RulesPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [rules, setRules] = useState<RuleView[]>([])
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

  const [name, setName] = useState('')
  const [kind, setKind] = useState<RuleAlertKind>('disk')
  const [event, setEvent] = useState<RuleTriggerEvent>('raised')
  const [hostFilter, setHostFilter] = useState('')
  const [minValue, setMinValue] = useState('')
  const [maxFirings, setMaxFirings] = useState(RULE_LIMIT_DEFAULT.maxFirings)
  const [windowMs, setWindowMs] = useState(RULE_LIMIT_DEFAULT.windowMs)
  const [actionType, setActionType] = useState<'notify' | 'job'>('notify')
  const [title, setTitle] = useState('')
  const [commands, setCommands] = useState('')
  const [targetIds, setTargetIds] = useState<string[]>([])
  const [phrase, setPhrase] = useState('')

  const refresh = useCallback(async (): Promise<void> => {
    const list = bridge()?.list
    if (typeof list !== 'function') return
    try {
      setRules(await list())
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const targets = useMemo<JobTargetRef[]>(
    () =>
      targetIds
        .map((id) => servers.find((s) => s.id === id))
        .filter((s): s is Server => s !== undefined)
        .map((s) => ({ serverId: s.id, serverName: s.name })),
    [targetIds, servers]
  )

  const spec = useMemo<JobSpec>(
    () => ({
      kind: 'command',
      title: title.trim() || 'Rule job',
      steps: commands
        .split('\n')
        .map((c) => c.trim())
        .filter((c) => c !== '')
        .map((command) => ({ command }))
    }),
    [title, commands]
  )

  // Risk, confirmation and blast radius, computed from the pinned pair as the
  // form is typed. THE POINT of this panel: the blast radius of a rule has to
  // be knowable when it is written, so it is on screen while it is being
  // written rather than derivable afterwards.
  const plan = useMemo(
    () => (actionType === 'job' ? ruleJobPlan({ spec, targets }) : null),
    [actionType, spec, targets]
  )

  const confirmation = ruleCreationConfirmation(actionType)
  const needsPhrase = confirmation.kind === 'type-to-confirm'
  const phraseOk = !needsPhrase || phrase.trim() === RULE_UNATTENDED_PHRASE
  const jobIncomplete = actionType === 'job' && (spec.steps.length === 0 || targets.length === 0)
  const canCreate = name.trim() !== '' && !jobIncomplete && phraseOk

  const reset = (): void => {
    setOpen(false)
    setName('')
    setHostFilter('')
    setMinValue('')
    setTitle('')
    setCommands('')
    setTargetIds([])
    setPhrase('')
    setActionType('notify')
  }

  const create = async (): Promise<void> => {
    if (!canCreate) return
    const fn = bridge()?.create
    if (typeof fn !== 'function') {
      setError('This build of the app cannot create rules — restart it.')
      return
    }
    const confirmedAt = Date.now()
    const action: RuleAction =
      actionType === 'job'
        ? {
            type: 'job',
            spec,
            targets,
            // Minted HERE, at the moment the dialog is satisfied, over exactly
            // the spec and target list the rule will keep. Main re-derives
            // planJob over the same pair on every firing and refuses if the two
            // disagree — the same door a job goes through, taken for the same
            // reason.
            approval: jobApprovalFor(spec, targets, { phrase: phrase.trim() || null, confirmedAt })
          }
        : { type: 'notify' }

    const draft: RuleDraftWire = {
      name: name.trim(),
      trigger: { kind, event },
      filter: {
        ...(hostFilter !== '' ? { serverId: hostFilter } : {}),
        ...(minValue.trim() !== '' && Number.isFinite(Number(minValue))
          ? { minValue: Number(minValue) }
          : {})
      },
      limit: { maxFirings, windowMs },
      action
    }
    try {
      const created = await fn(draft)
      if (!created) {
        setError('That rule was refused. Check the trigger and the command.')
        return
      }
      setError(null)
      reset()
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const toggle = async (id: string, enabled: boolean): Promise<void> => {
    const fn = bridge()?.setEnabled
    if (typeof fn !== 'function') return
    await fn(id, enabled)
    await refresh()
  }

  const remove = async (id: string): Promise<void> => {
    const fn = bridge()?.remove
    if (typeof fn !== 'function') return
    await fn(id)
    await refresh()
  }

  return (
    <div className="col" style={{ gap: 12 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'baseline' }}>
        <div className="col" style={{ gap: 2 }}>
          <b>Rules</b>
          <span className="faint" style={{ fontSize: 11 }}>
            When an alert fires, run a job or post to the webhook. A rule runs the job it was
            confirmed with, on the hosts it was confirmed for, and refuses if either has changed.
          </span>
        </div>
        <button className="btn" onClick={() => setOpen((v) => !v)}>
          <Plus size={14} /> New rule
        </button>
      </div>

      {error !== null && (
        <div className="row danger" style={{ gap: 6, fontSize: 12 }}>
          <AlertTriangle size={14} />
          {error}
        </div>
      )}

      {open && (
        <div className="card col" style={{ gap: 10, padding: 12 }}>
          <label className="col" style={{ gap: 4, fontSize: 12 }}>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Vacuum the journal" />
          </label>

          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <label className="col" style={{ gap: 4, fontSize: 12 }}>
              When
              <select value={kind} onChange={(e) => setKind(e.target.value as RuleAlertKind)}>
                {RULE_ALERT_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABEL[k]}
                  </option>
                ))}
              </select>
            </label>
            <label className="col" style={{ gap: 4, fontSize: 12 }}>
              is
              <select value={event} onChange={(e) => setEvent(e.target.value as RuleTriggerEvent)}>
                <option value="raised">raised</option>
                <option value="resolved">resolved</option>
              </select>
            </label>
            <label className="col" style={{ gap: 4, fontSize: 12 }}>
              on
              <select value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
                <option value="">any host</option>
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="col" style={{ gap: 4, fontSize: 12 }}>
              at or above
              <input
                value={minValue}
                onChange={(e) => setMinValue(e.target.value)}
                placeholder="any reading"
                inputMode="decimal"
                style={{ width: 100 }}
              />
            </label>
          </div>

          <div className="row" style={{ gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <label className="col" style={{ gap: 4, fontSize: 12 }}>
              At most
              <input
                type="number"
                min={1}
                max={RULE_LIMIT_MAX_FIRINGS}
                value={maxFirings}
                aria-label="Firings allowed in the window"
                onChange={(e) => setMaxFirings(Math.max(1, Number(e.target.value) || 1))}
                style={{ width: 70 }}
              />
            </label>
            <label className="col" style={{ gap: 4, fontSize: 12 }}>
              time(s) in
              <select value={windowMs} onChange={(e) => setWindowMs(Number(e.target.value))}>
                {WINDOWS.map((w) => (
                  <option key={w.ms} value={w.ms}>
                    {w.label}
                  </option>
                ))}
              </select>
            </label>
            <span className="faint" style={{ fontSize: 11, paddingBottom: 6 }}>
              A rule with no ceiling turns a flapping condition into an outage.
            </span>
          </div>

          <div className="row" style={{ gap: 12, fontSize: 12 }}>
            <label className="row" style={{ gap: 4 }}>
              <input
                type="radio"
                name="rule-action"
                checked={actionType === 'notify'}
                onChange={() => setActionType('notify')}
              />
              Post to the webhook
            </label>
            <label className="row" style={{ gap: 4 }}>
              <input
                type="radio"
                name="rule-action"
                checked={actionType === 'job'}
                onChange={() => setActionType('job')}
              />
              Run a job
            </label>
          </div>

          {actionType === 'job' && (
            <div className="col" style={{ gap: 8 }}>
              <label className="col" style={{ gap: 4, fontSize: 12 }}>
                Job title
                <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Clear the journal" />
              </label>
              <label className="col" style={{ gap: 4, fontSize: 12 }}>
                Commands, one per line
                <textarea
                  rows={3}
                  value={commands}
                  onChange={(e) => setCommands(e.target.value)}
                  placeholder="journalctl --vacuum-size=200M"
                />
              </label>
              <div className="col" style={{ gap: 4, fontSize: 12 }}>
                Hosts
                <div className="col" style={{ gap: 2, maxHeight: 160, overflowY: 'auto' }}>
                  {servers.map((s) => (
                    <label key={s.id} className="row" style={{ gap: 6 }}>
                      <input
                        type="checkbox"
                        checked={targetIds.includes(s.id)}
                        onChange={(e) =>
                          setTargetIds((ids) =>
                            e.target.checked ? [...ids, s.id] : ids.filter((i) => i !== s.id)
                          )
                        }
                      />
                      {s.name}
                    </label>
                  ))}
                </div>
              </div>

              {plan !== null && (
                <div className="col" style={{ gap: 2, fontSize: 12 }}>
                  <div>
                    <span className="faint">This runs on </span>
                    {plan.blastRadius} host(s) at once
                    <span className="faint"> and reads as </span>
                    {plan.risk}
                    <span className="faint">, every time it fires.</span>
                  </div>
                  {plan.reasons.map((r) => (
                    <div key={r} className="faint">
                      {r}
                    </div>
                  ))}
                </div>
              )}

              <label className="col" style={{ gap: 4, fontSize: 12 }}>
                {/* Always typed, for a job rule. `planJob` would ask for a click
                    here; a standing authorisation is a different thing being
                    agreed to, and the word says which one. */}
                This rule runs commands on those hosts unattended, whenever it fires. Type{' '}
                <b>{RULE_UNATTENDED_PHRASE}</b> to confirm.
                <input
                  value={phrase}
                  aria-label="Type UNATTENDED to confirm"
                  onChange={(e) => setPhrase(e.target.value)}
                />
              </label>
            </div>
          )}

          <div className="row" style={{ gap: 8 }}>
            <button className="btn primary" disabled={!canCreate} onClick={() => void create()}>
              <Zap size={14} /> Create rule
            </button>
            <button className="btn ghost" onClick={reset}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="faint" style={{ fontSize: 12 }}>
          No rules. Nothing runs on its own.
        </div>
      ) : (
        rules.map((r) => (
          <RuleCard
            key={r.id}
            rule={r}
            servers={servers}
            onToggle={(enabled) => void toggle(r.id, enabled)}
            onRemove={() => void remove(r.id)}
          />
        ))
      )}
    </div>
  )
}
