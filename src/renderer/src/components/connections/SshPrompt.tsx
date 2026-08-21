import { useEffect, useRef, useState } from 'react'
import { KeyRound } from 'lucide-react'
import { Modal } from '../common/Modal'
import { clsx } from '../../lib/format'
import type { SshPromptRequest } from '../../../../preload/index'

// Answers keyboard-interactive challenges: the second factor on servers with
// AuthenticationMethods publickey,keyboard-interactive, or the password on
// servers that only offer keyboard-interactive.
export function SshPrompt(): React.JSX.Element | null {
  const [request, setRequest] = useState<SshPromptRequest | null>(null)
  const [answers, setAnswers] = useState<string[]>([])
  const [remember, setRemember] = useState(false)
  const firstField = useRef<HTMLInputElement>(null)

  useEffect(() => {
    return window.shellpilot?.ssh.onPrompt((req) => {
      setRequest(req)
      setAnswers(req.prompts.map(() => ''))
      setRemember(false)
    })
  }, [])

  useEffect(() => {
    if (request) firstField.current?.focus()
  }, [request])

  if (!request) return null

  // One-time codes rotate, so storing one is useless and weakens the second
  // factor. Offer to remember only what looks like a static secret.
  const looksOneTime = /\b(otp|one[- ]?time|verification code|token|2fa|totp|duo|authenticator)\b/i.test(
    `${request.name} ${request.instructions} ${request.prompts.map((p) => p.prompt).join(' ')}`
  )
  const canRemember = !looksOneTime && request.prompts.length === 1 && !!request.serverId

  const submit = (): void => {
    window.shellpilot?.ssh.replyPrompt(request.id, answers, remember && canRemember, request.serverId)
    setRequest(null)
    setAnswers([])
  }

  const cancel = (): void => {
    // An empty answer set makes the server reject the attempt cleanly.
    window.shellpilot?.ssh.replyPrompt(request.id, [])
    setRequest(null)
    setAnswers([])
  }

  return (
    <Modal
      title={request.name?.trim() || 'Additional authentication required'}
      subtitle={`${request.username}@${request.host}`}
      onClose={cancel}
    >
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="row" style={{ gap: 8 }}>
          <KeyRound size={16} className="faint" />
          <span className="muted" style={{ fontSize: 12 }}>
            {request.instructions?.trim() || 'The server is requesting a second authentication factor.'}
          </span>
        </div>

        {request.prompts.map((p, i) => (
          <label className="field" key={i}>
            <span className="field-label">{p.prompt.replace(/:\s*$/, '')}</span>
            <input
              ref={i === 0 ? firstField : undefined}
              className="input"
              // echo=false means the server wants it hidden (password, OTP).
              type={p.echo ? 'text' : 'password'}
              value={answers[i] ?? ''}
              onChange={(e) =>
                setAnswers((a) => {
                  const next = [...a]
                  next[i] = e.target.value
                  return next
                })
              }
              onKeyDown={(e) => {
                if (e.key === 'Enter' && i === request.prompts.length - 1) submit()
              }}
            />
          </label>
        ))}

        {canRemember && (
          <label className="row" style={{ gap: 8 }}>
            <span className={clsx('switch', remember && 'on')} onClick={() => setRemember((v) => !v)} />
            <span className="muted" style={{ fontSize: 12 }}>
              Remember this answer for {request.host} (stored in OS secure storage)
            </span>
          </label>
        )}
        {looksOneTime && (
          <span className="faint" style={{ fontSize: 11 }}>
            One-time codes change each login and are never stored.
          </span>
        )}

        <div className="row" style={{ gap: 8 }}>
          <span className="spacer" />
          <button className="btn sm" onClick={cancel}>
            Cancel
          </button>
          <button className="btn primary sm" onClick={submit}>
            Continue
          </button>
        </div>
      </div>
    </Modal>
  )
}
