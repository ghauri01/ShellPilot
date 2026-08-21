import { Modal } from '../common/Modal'
import { ClipboardPaste, AlertTriangle } from 'lucide-react'

// A multi-line paste runs line by line as soon as it lands — there is no
// chance to read it first. Confirming shows exactly what is about to execute.
export function PasteConfirm({
  text,
  lines,
  server,
  onConfirm,
  onCancel
}: {
  text: string
  lines: number
  server: string
  onConfirm: () => void
  onCancel: () => void
}): React.JSX.Element {
  const preview = text.split(/\r?\n/).slice(0, 12)
  const hidden = Math.max(0, text.split(/\r?\n/).length - preview.length)

  return (
    <Modal
      title={`Paste ${lines} line${lines === 1 ? '' : 's'} into ${server}?`}
      subtitle="Every line runs as soon as it is pasted"
      onClose={onCancel}
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="row" style={{ gap: 8, color: 'var(--warn)' }}>
          <AlertTriangle size={16} />
          <span style={{ fontSize: 12 }}>
            This is a remote shell. Check the commands before continuing.
          </span>
        </div>
        <pre className="paste-preview selectable">
          {preview.join('\n')}
          {hidden > 0 ? `\n… ${hidden} more line${hidden === 1 ? '' : 's'}` : ''}
        </pre>
        <div className="row" style={{ gap: 8 }}>
          <span className="spacer" />
          <button className="btn sm" onClick={onCancel}>
            Cancel
          </button>
          <button className="btn primary sm" onClick={onConfirm} autoFocus>
            <ClipboardPaste size={14} /> Paste and run
          </button>
        </div>
      </div>
    </Modal>
  )
}
