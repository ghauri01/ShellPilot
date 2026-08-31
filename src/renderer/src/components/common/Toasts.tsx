import { CheckCircle2, Info, AlertTriangle, X } from 'lucide-react'
import { useToasts } from '../../store/toast'
import { clsx } from '../../lib/format'

export function Toasts(): React.JSX.Element {
  const toasts = useToasts((s) => s.toasts)
  const dismiss = useToasts((s) => s.dismiss)
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={clsx('toast', t.kind)}
          // A sticky toast is not click-to-dismiss: its whole point is the
          // button inside it, and a stray click on the message should not throw
          // away the only route to fixing the problem.
          onClick={t.sticky ? undefined : () => dismiss(t.id)}
          role={t.kind === 'error' ? 'alert' : 'status'}
        >
          {t.kind === 'ok' && <CheckCircle2 size={16} style={{ color: 'var(--ok)' }} />}
          {t.kind === 'error' && <AlertTriangle size={16} style={{ color: 'var(--danger)' }} />}
          {t.kind === 'info' && <Info size={16} style={{ color: 'var(--accent)' }} />}
          <span className="grow">{t.message}</span>
          {t.action && (
            <button
              className="btn sm primary"
              style={{ flexShrink: 0 }}
              onClick={(e) => {
                e.stopPropagation()
                dismiss(t.id)
                t.action?.run()
              }}
            >
              {t.action.label}
            </button>
          )}
          {t.sticky && (
            <button
              className="icon-btn sm"
              title="Dismiss"
              style={{ flexShrink: 0 }}
              onClick={(e) => {
                e.stopPropagation()
                dismiss(t.id)
              }}
            >
              <X size={14} />
            </button>
          )}
        </div>
      ))}
    </div>
  )
}
