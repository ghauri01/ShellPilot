import { CheckCircle2, Info, AlertTriangle } from 'lucide-react'
import { useToasts } from '../../store/toast'
import { clsx } from '../../lib/format'

export function Toasts(): React.JSX.Element {
  const toasts = useToasts((s) => s.toasts)
  const dismiss = useToasts((s) => s.dismiss)
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div key={t.id} className={clsx('toast', t.kind)} onClick={() => dismiss(t.id)}>
          {t.kind === 'ok' && <CheckCircle2 size={16} style={{ color: 'var(--ok)' }} />}
          {t.kind === 'error' && <AlertTriangle size={16} style={{ color: 'var(--danger)' }} />}
          {t.kind === 'info' && <Info size={16} style={{ color: 'var(--accent)' }} />}
          <span>{t.message}</span>
        </div>
      ))}
    </div>
  )
}
