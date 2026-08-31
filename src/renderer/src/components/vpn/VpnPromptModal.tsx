import { useEffect, useRef, useState } from 'react'
import { KeyRound } from 'lucide-react'
import { Modal } from '../common/Modal'
import type { VpnPrompt } from '../../types'
import { bridgeOn } from '../../lib/bridge'

const FIELD_LABEL: Record<VpnPrompt['kind'], string> = {
  otp: 'Code',
  password: 'Password',
  passphrase: 'Key passphrase',
  username: 'Username'
}

// Answers an engine's mid-connection challenge: an OpenVPN static challenge, a
// key passphrase, or a re-prompt after the server rejected a stored password.
//
// Mounted once at the app root rather than inside the VPN view, because the
// prompt channel is global — a profile started from the Tunnels view can ask
// for an OTP long after the user has switched to a terminal, and a prompt
// nobody can see is a connection that hangs for no visible reason.
export function VpnPromptModal(): React.JSX.Element | null {
  // A queue, not a single slot. Engines do not take turns: two profiles can be
  // starting at once, and `autoStart` makes that the ordinary case rather than
  // the odd one. Holding one request meant the second overwrote the first, the
  // first was never answered, and that connection hung until the engine gave
  // up on it.
  const [queue, setQueue] = useState<VpnPrompt[]>([])
  const [value, setValue] = useState('')
  const field = useRef<HTMLInputElement>(null)

  useEffect(() => {
    return bridgeOn('vpn.onPrompt', window.shellpilot?.vpn?.onPrompt, (p) => {
      // Never prefilled and never carried over: `value` belongs to the request
      // at the head of the queue and is cleared as the queue advances. A
      // one-time code is worthless the moment it is reused, and a remembered
      // one silently turns two factors back into one.
      setQueue((q) => (q.some((x) => x.id === p.id) ? q : [...q, p]))
    })
  }, [])

  const request = queue[0] ?? null
  const requestId = request?.id
  const waiting = queue.length - 1

  // Keyed on the request id, not on mount: answering one prompt reveals the
  // next in the same input element, so an `autoFocus` attribute would only ever
  // fire for the first of them. This is the one field in the app where the user
  // is already waiting and starts typing before looking at the window.
  useEffect(() => {
    if (requestId) field.current?.focus()
  }, [requestId])

  if (!request) return null

  // Advance rather than clear. Whatever else is queued is a different engine
  // still blocked on its own answer, so answering or declining one must never
  // take the rest of them down with it.
  const advance = (): void => {
    setQueue((q) => q.slice(1))
    setValue('')
  }

  const submit = (): void => {
    // Matches the disabled Continue button, so Enter and the button agree.
    if (!value) return
    window.shellpilot?.vpn.replyPrompt(request.id, value)
    advance()
  }

  // null, not an empty string: an empty answer is an answer, and the engine
  // would try it and fail. null means the user declined, and the driver aborts.
  const cancel = (): void => {
    window.shellpilot?.vpn.replyPrompt(request.id, null)
    advance()
  }

  return (
    <Modal
      title={request.kind === 'otp' ? 'One-time code required' : 'Authentication required'}
      subtitle={request.profileName}
      // Escape and a click outside both land here, which is a decline, not a
      // dismissal: replying null lets the driver abort cleanly instead of
      // leaving the engine waiting on a prompt that is no longer on screen.
      onClose={cancel}
      footer={
        <>
          <span className="spacer" />
          <button className="btn" onClick={cancel}>
            Cancel
          </button>
          <button className="btn primary" disabled={!value} onClick={submit}>
            Continue
          </button>
        </>
      }
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="row" style={{ gap: 8 }}>
          <KeyRound size={16} className="faint" />
          {/* The engine's own wording, verbatim: the server chose it, and the
              user has probably seen it in another client already. */}
          <span className="muted" style={{ fontSize: 12 }}>
            {request.label.trim() || 'The VPN server is asking for another credential.'}
          </span>
        </div>

        <label className="field">
          <span className="field-label">{FIELD_LABEL[request.kind]}</span>
          <input
            ref={field}
            className="input"
            // echo:false is the engine saying "do not put this on screen".
            type={request.echo ? 'text' : 'password'}
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') submit()
            }}
          />
        </label>

        {request.kind === 'otp' && (
          <span className="faint" style={{ fontSize: 11 }}>
            One-time codes change every login and are never stored.
          </span>
        )}

        {waiting > 0 && (
          <span className="faint" style={{ fontSize: 11 }}>
            {waiting === 1
              ? 'One more profile is waiting for a credential after this one.'
              : `${waiting} more profiles are waiting for a credential after this one.`}
          </span>
        )}
      </div>
    </Modal>
  )
}
