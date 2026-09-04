import { TriangleAlert } from 'lucide-react'
import { clsx } from '../../lib/format'
import {
  DOCKER_FAILURE_HELP,
  type DockerReclaimDiff,
  type DockerReclaimItem,
  type DockerReclaimPlan,
  type DockerReclaimResult
} from '../../../../shared/docker'

// The dialog that stands between a list of checkboxes and a `docker rm`.
//
// It has three faces and only ever wears one:
//
//  1. **The plan.** What is about to go, why that is worth a dialog, and the
//     caveats — which are printed in their own block, visually apart from the
//     reasons, because they are not arguments for pressing harder. They are
//     things that would otherwise be discovered afterwards.
//  2. **The refusal.** The list was re-read a moment before this would run, and
//     the host disagreed with what the operator was shown. Nothing runs; the
//     disagreement is printed. This is the face the whole feature is built
//     around, and it is deliberately not dismissible into "do it anyway" — the
//     way out is to look at the fresh list and choose again.
//  3. **The outcome.** Per item, always. "The command exited 1" says nothing
//     about which of five volumes is still there, which is the only question
//     afterwards.
//
// Split out of DockerPanel.tsx rather than added to it, and not only for
// length: `tests/dockerOps.test.ts` scans the `DiskItems` function for anything
// that accumulates per-item bytes, because summing image sizes overstates the
// disk by a multiple. Keeping the dialog out of that file keeps that guard
// reading the thing it was written to guard.

/** Kind, then a readable name. `<none>:<none>` is docker's word, kept. */
function itemRow(i: DockerReclaimItem): React.JSX.Element {
  return (
    <div key={`${i.kind} ${i.id}`} className="cron-row">
      <span className="chip">{i.kind}</span>
      <span className="mono cron-when" title={i.id}>
        {i.label}
      </span>
      <span className="faint cron-desc">{i.kind === 'volume' ? (i.anonymous ? 'anonymous' : 'named') : i.id}</span>
      <span className="grow" />
      <span className="mono">{i.size}</span>
    </div>
  )
}

export function ReclaimDialog({
  plan,
  diff,
  checking,
  running,
  phrase,
  onPhrase,
  onConfirm,
  onCancel
}: {
  plan: DockerReclaimPlan
  /** Set once the fresh read has come back and disagreed. Until then, null. */
  diff: DockerReclaimDiff | null
  checking: boolean
  running: boolean
  phrase: string
  onPhrase: (v: string) => void
  onConfirm: () => void
  onCancel: () => void
}): React.JSX.Element {
  const typedPhrase = plan.confirmation.kind === 'type-to-confirm' ? plan.confirmation.phrase : null
  const canConfirm = typedPhrase === null || phrase.trim() === typedPhrase

  if (diff !== null) {
    return (
      <div className="bc-confirm">
        <div className="s-title">This host is not what the list said it was.</div>
        <div className="s-desc danger">
          <TriangleAlert size={12} /> Nothing was removed. The disk was read again just before running, and
          it disagrees with the list you approved — so the ids that would have been sent no longer describe
          what you were looking at.
        </div>
        {diff.ineligible.length > 0 && (
          <>
            <div className="row muted" style={{ fontSize: 11, marginTop: 8 }}>
              <span className="grow">Still there, no longer removable</span>
            </div>
            {diff.ineligible.map((c) => (
              <div key={`${c.item.kind} ${c.item.id}`} className="cron-row">
                <span className="chip warn">{c.item.kind}</span>
                <span className="mono cron-when">{c.item.label}</span>
                <span className="faint cron-desc">{c.detail}</span>
              </div>
            ))}
          </>
        )}
        {diff.gone.length > 0 && (
          <>
            <div className="row muted" style={{ fontSize: 11, marginTop: 8 }}>
              <span className="grow">Already gone</span>
            </div>
            {diff.gone.map((i) => (
              <div key={`${i.kind} ${i.id}`} className="cron-row">
                <span className="chip">{i.kind}</span>
                <span className="mono cron-when">{i.label}</span>
                <span className="faint cron-desc">something else removed it</span>
              </div>
            ))}
          </>
        )}
        {diff.changed.length > 0 && (
          <>
            <div className="row muted" style={{ fontSize: 11, marginTop: 8 }}>
              <span className="grow">Not the figure you were shown</span>
            </div>
            {diff.changed.map((c) => (
              <div key={`${c.item.kind} ${c.item.id}`} className="cron-row">
                <span className="chip warn">{c.item.kind}</span>
                <span className="mono cron-when">{c.item.label}</span>
                <span className="faint cron-desc">{c.detail}</span>
              </div>
            ))}
          </>
        )}
        <div className="faint" style={{ fontSize: 11, marginTop: 6 }}>
          Close this and itemise again. The selection is not carried over on purpose: it was made against a
          listing that has since been wrong about at least one thing.
        </div>
        <div className="row" style={{ gap: 8, marginTop: 8 }}>
          <button className="btn" onClick={onCancel}>
            Close
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="bc-confirm">
      <div className="s-title">
        Remove {plan.items.length === 1 ? 'this' : `these ${plan.items.length}`}
        {plan.items.length === 1 ? ' object' : ' objects'}?
      </div>
      {plan.items.map(itemRow)}
      {plan.reasons.length > 0 && (
        <div className="s-desc danger" style={{ marginTop: 6 }}>
          <TriangleAlert size={12} /> {plan.reasons.join('; ')}.
        </div>
      )}
      {/* Apart from the reasons, and labelled as something else, because they
          are not arguments for pressing harder — they are the things that get
          discovered afterwards otherwise. */}
      {plan.caveats.length > 0 && (
        <div className="s-desc" style={{ marginTop: 4 }}>
          <div className="faint" style={{ fontSize: 11 }}>
            Worth knowing before, rather than after:
          </div>
          {plan.caveats.map((c) => (
            <div key={c} className="faint" style={{ fontSize: 11 }}>
              · {c}
            </div>
          ))}
        </div>
      )}
      {typedPhrase !== null && (
        <div className="input-group" style={{ marginTop: 6 }}>
          <input
            className="input"
            placeholder={`Type ${typedPhrase} to continue`}
            value={phrase}
            onChange={(e) => onPhrase(e.target.value)}
            autoFocus
          />
        </div>
      )}
      <div className="row" style={{ gap: 8, marginTop: 8, alignItems: 'center' }}>
        <button className="btn primary" disabled={!canConfirm || checking || running} onClick={onConfirm}>
          {checking ? 'Re-reading the disk…' : running ? 'Removing…' : 'Remove'}
        </button>
        <button className="btn ghost" disabled={running} onClick={onCancel}>
          Cancel
        </button>
        <span className="faint" style={{ fontSize: 11 }}>
          The disk is read once more first, and nothing runs if it disagrees with this list.
        </span>
      </div>
    </div>
  )
}

/**
 * What happened, per object.
 *
 * A failed removal is not a failed read: docker refusing to delete a volume
 * that turned out to be in use is this feature working, and it is reported as
 * one row rather than as a broken panel.
 */
export function ReclaimOutcome({ result }: { result: DockerReclaimResult }): React.JSX.Element {
  if (!result.ok) {
    return (
      <div className="s-desc danger">
        <TriangleAlert size={12} /> {DOCKER_FAILURE_HELP[result.reason]}
        <div className="mono" style={{ marginTop: 4, opacity: 0.8 }}>
          {result.detail}
        </div>
        {result.reason === 'permission-denied' && (
          <div className="faint" style={{ marginTop: 6 }}>
            The socket refused this account, and nothing was retried as root on its own. A removal running
            as root is a decision to make deliberately, not one to discover afterwards.
          </div>
        )}
      </div>
    )
  }
  const gone = result.outcomes.filter((o) => o.ok)
  const stayed = result.outcomes.filter((o) => !o.ok)
  return (
    <div className={clsx('s-desc', stayed.length > 0 && 'danger')}>
      <div>
        Removed {gone.length} of {result.outcomes.length}
        {result.usedSudo ? ', as root' : ''}.
      </div>
      {stayed.map((o) => (
        <div key={`${o.item.kind} ${o.item.id}`} className="mono danger" style={{ fontSize: 11 }}>
          {o.item.label}: {o.error}
        </div>
      ))}
      {result.unattributed.map((line, i) => (
        <div key={i} className="mono faint" style={{ fontSize: 11 }}>
          {line}
        </div>
      ))}
      {/* No byte figure here, and its absence is the same decision the itemised
          view makes: per-item sizes do not add up, because image layers are
          shared. The honest number comes from re-reading `docker system df`. */}
      {gone.length > 0 && (
        <div className="faint" style={{ fontSize: 11 }}>
          Read the disk again for the new totals — the freed bytes are not the sum of the rows above,
          because images share layers.
        </div>
      )}
    </div>
  )
}
