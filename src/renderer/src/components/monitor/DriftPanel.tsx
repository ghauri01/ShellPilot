import { useCallback, useEffect, useMemo, useState } from 'react'
import { FileDiff, Info, Pin, RefreshCw } from 'lucide-react'
import { bridgeHas } from '../../lib/bridge'
import { clsx } from '../../lib/format'
import type { Server } from '../../types'
import {
  DRIFT_NO_PUSH,
  DRIFT_PREVIEW_CHARS,
  DRIFT_RULE_ORDER,
  DRIFT_STATUS_HELP,
  DRIFT_WATCHES,
  compareDrift,
  driftCoverageSentence,
  driftRule,
  type DriftHostResult,
  type DriftVerdict,
  type HostDrift
} from '../../../../shared/drift'

// Configuration drift — roadmap item 25, the panel.
//
// Everything this panel can get wrong looks fine on screen, so what it renders
// is shaped around three refusals:
//
//  1. A host that could not be read never appears in the same column as a host
//     that matched. It gets its own row, its own word, and its status's own
//     explanation.
//  2. A host whose difference a rule removed is never labelled "identical". It
//     says "differs in ways I was told to ignore" and names the rules.
//  3. The rules are on the screen, not in the source. An operator disagreeing
//     with a verdict can read what each rule removes, with a worked example,
//     and the sentence saying why this file is compared under that set.

const VERDICT_LABEL: Record<DriftVerdict, string> = {
  baseline: 'baseline',
  identical: 'identical',
  'ignored-difference': 'differs in ignored ways',
  differs: 'differs',
  absent: 'not on this host',
  unread: 'could not be read'
}

/** The class that decides the colour. `ignored-difference` is deliberately NOT
 *  the same as `identical`: it matches, and it is not the same answer. */
const VERDICT_CLASS: Record<DriftVerdict, string> = {
  baseline: 'ok',
  identical: 'ok',
  'ignored-difference': 'muted',
  differs: 'warn',
  absent: 'warn',
  unread: 'faint'
}

interface Entry {
  drift?: HostDrift
  at?: number
  error?: string
}

function Rules({ watchId }: { watchId: string }): React.JSX.Element | null {
  const watch = DRIFT_WATCHES.find((x) => x.id === watchId)
  if (!watch) return null
  // Rendered in the pipeline order, which is the order they actually run in —
  // the watch's own list order is not it, and showing a list in an order the
  // code does not use is worse than showing none.
  const rules = DRIFT_RULE_ORDER.filter((id) => watch.rules.includes(id)).map(driftRule)
  return (
    <div className="s-desc" data-testid="drift-rules">
      <b>{watch.path}</b> is compared after these rules are applied, in this order. Two files that
      differ only in what these remove are reported as differing in ignored ways — never as
      identical.
      <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
        {rules.map((r) => (
          <li key={r.id}>
            <b>{r.label}</b> — {r.detail}{' '}
            <span className="faint">
              e.g. <code>{r.example.before}</code> → <code>{r.example.after}</code>
            </span>
          </li>
        ))}
      </ul>
      <div style={{ marginTop: 6 }}>
        <Info size={12} /> {watch.note}
      </div>
    </div>
  )
}

function Row({
  r,
  pinned,
  onPin
}: {
  r: DriftHostResult
  pinned: boolean
  onPin: () => void
}): React.JSX.Element {
  return (
    <tr>
      <td>
        <button
          className={clsx('btn ghost sm', pinned && 'active')}
          title="Compare every other host against this one"
          onClick={onPin}
        >
          <Pin size={11} />
        </button>{' '}
        {r.serverName}
      </td>
      <td className={VERDICT_CLASS[r.verdict]}>{VERDICT_LABEL[r.verdict]}</td>
      <td className="faint">
        {r.verdict === 'ignored-difference' && r.ignoredBy?.length ? (
          // The sentence this whole item turns on. "Candidates" and not "the
          // cause": proving which single rule is load-bearing would need both
          // files' contents, and not keeping those is the storage decision.
          <>
            The bytes differ. After{' '}
            {r.ignoredBy.map((id) => driftRule(id).label.toLowerCase()).join(', ')} they match.
          </>
        ) : r.verdict === 'unread' ? (
          <>{DRIFT_STATUS_HELP[r.status]}{r.detail ? ` (${r.detail})` : ''}</>
        ) : r.verdict === 'absent' ? (
          DRIFT_STATUS_HELP.absent
        ) : r.redacted ? (
          'Secret-shaped text was replaced before comparing, so a difference inside it is invisible here.'
        ) : (
          ''
        )}
      </td>
    </tr>
  )
}

export function DriftPanel({ servers }: { servers: Server[] }): React.JSX.Element {
  const [entries, setEntries] = useState<Record<string, Entry>>({})
  const [watchId, setWatchId] = useState<string>(DRIFT_WATCHES[0].id)
  const [pinned, setPinned] = useState<string | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [showRules, setShowRules] = useState(false)

  const load = useCallback(async (): Promise<void> => {
    const fleet = window.shellpilot?.fleet as Record<string, unknown> | undefined
    if (!bridgeHas(fleet, 'drift')) return
    const next: Record<string, Entry> = {}
    await Promise.all(
      servers.map(async (s) => {
        const r = await window.shellpilot?.fleet?.drift(s.id)
        if (r) next[s.id] = { drift: r.drift, at: r.at, error: r.error }
      })
    )
    setEntries(next)
  }, [servers])

  useEffect(() => {
    void load()
  }, [load])

  const refresh = async (): Promise<void> => {
    setBusy(true)
    try {
      if (bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'sampleNow')) {
        await window.shellpilot?.fleet?.sampleNow()
      }
      await load()
    } finally {
      setBusy(false)
    }
  }

  const watch = DRIFT_WATCHES.find((x) => x.id === watchId) ?? DRIFT_WATCHES[0]

  const comparison = useMemo(
    () =>
      compareDrift({
        watch,
        baselineServerId: pinned,
        hosts: servers.map((s) => ({
          serverId: s.id,
          serverName: s.name,
          drift: entries[s.id]?.drift,
          error: entries[s.id]?.error
        }))
      }),
    [watch, pinned, servers, entries]
  )

  const sentence = driftCoverageSentence(comparison.coverage)
  const collected = servers.filter((s) => entries[s.id]?.drift).length

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <FileDiff size={14} className="faint" />
        <b className="grow">Configuration drift</b>
        <select
          className="input sm"
          aria-label="Watched file"
          value={watchId}
          onChange={(e) => setWatchId(e.target.value)}
        >
          {DRIFT_WATCHES.map((x) => (
            <option key={x.id} value={x.id}>
              {x.label}
            </option>
          ))}
        </select>
        <button
          className="btn"
          disabled={busy || servers.length === 0}
          onClick={() => void refresh()}
          title="Sweeps the estate now and re-reads what has already been collected. Watched files are re-read at most once an hour per host. Nothing is written to any host by this."
        >
          <RefreshCw size={13} className={clsx(busy && 'spin')} /> Check now
        </button>
      </div>

      {/* The refusal, on screen rather than only in the source — the same shape
          docker.ts's refusal to ship `prune` takes. Someone looking at three
          diverging hosts will look for the button that fixes them, and the
          answer has to be here rather than in a code comment. */}
      <div className="s-desc" data-testid="drift-no-push">
        {DRIFT_NO_PUSH}
      </div>

      {collected === 0 ? (
        <div className="s-desc">
          <b>No configuration files have been read yet.</b> ShellPilot reads them about once an
          hour, on the same background sweep as the inventory — so a server added in the last hour,
          or an estate where this has just been switched on, will not have any yet. Press{' '}
          <b>Check now</b> to sweep immediately, and make sure background checking is on in
          Settings.
        </div>
      ) : (
        <>
          <div className="row wrap muted" style={{ fontSize: 11, marginTop: 8, gap: 12 }}>
            {/* Each count is one text node rather than a number beside a word.
                A React fragment splits `{n} match{...}` into three nodes, which
                reads identically and is not the same string — and a headline
                nobody can find is a headline nobody reads. */}
            <span>
              <span>{`${comparison.matching} ${comparison.matching === 1 ? 'match' : 'matches'}`}</span>
              {comparison.diverging > 0 && <span className="warn">{` · ${comparison.diverging} differ`}</span>}
              {comparison.coverage.absent.length > 0 && (
                <span className="warn">
                  {` · ${comparison.coverage.absent.length} do not have the file`}
                </span>
              )}
            </span>
            <button className="btn ghost sm" onClick={() => setShowRules((v) => !v)}>
              {showRules ? 'Hide' : 'Show'} the {watch.rules.length} rules this is compared under
            </button>
          </div>

          {showRules && <Rules watchId={watch.id} />}

          {comparison.baselineServerId === null ? (
            <div className="s-desc warn" data-testid="drift-no-baseline">
              Nothing to compare against. {pinned
                ? 'The host you pinned could not be read, and another has NOT been substituted for it — a column of verdicts against a reference you did not choose would say less than nothing.'
                : 'No host answered with a readable copy of this file.'}
            </div>
          ) : (
            comparison.baselineChosen && (
              <div className="s-desc" data-testid="drift-chosen-baseline">
                Nobody pinned a baseline, so the largest group of matching hosts was used and the
                others are compared against it. That is a statement about the majority, not about
                which side is correct: a host that was fixed first looks exactly like a host that
                drifted. Pin one to compare against it instead.
              </div>
            )
          )}

          {sentence && (
            <div className="s-desc warn" data-testid="drift-coverage">
              {sentence}
            </div>
          )}

          <div className="inv-scroll">
            <table className="table inv-table">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Compared with the baseline</th>
                  <th>Why</th>
                </tr>
              </thead>
              <tbody>
                {comparison.results.map((r) => (
                  <Row
                    key={r.serverId}
                    r={r}
                    pinned={comparison.baselineServerId === r.serverId}
                    onPin={() => setPinned(pinned === r.serverId ? undefined : r.serverId)}
                  />
                ))}
              </tbody>
            </table>
          </div>

          <div className="s-desc faint">
            Comparison is over hashes. ShellPilot keeps two hashes and a status per file per host —
            never the file — so a divergence survives a restart while the configuration itself is
            not copied into its store. The first {DRIFT_PREVIEW_CHARS} characters of each file are
            held in memory for this session only, after every redaction rule has run over the whole
            of it.
          </div>
        </>
      )}
    </div>
  )
}
