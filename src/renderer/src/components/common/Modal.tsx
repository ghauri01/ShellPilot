import { ReactNode, useRef } from 'react'
import { X } from 'lucide-react'
import { useClickOutside } from '../../hooks/useClickOutside'
import { clsx } from '../../lib/format'

interface ModalProps {
  title: string
  subtitle?: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  size?: 'md' | 'lg'
}

export function Modal({ title, subtitle, onClose, children, footer, size = 'md' }: ModalProps): React.JSX.Element {
  const ref = useRef<HTMLDivElement>(null)
  useClickOutside(ref, onClose)
  return (
    <div className="scrim">
      <div className={clsx('modal', size === 'lg' && 'lg')} ref={ref} role="dialog" aria-modal>
        <div className="modal-header">
          <div>
            <h2>{title}</h2>
            {subtitle && <div className="sub">{subtitle}</div>}
          </div>
          <button className="icon-btn close" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  )
}
