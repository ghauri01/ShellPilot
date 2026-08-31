import { useEffect, useRef, useState } from 'react'
import { Modal } from '../common/Modal'
import type { VpnLogLine } from '../../types'
import { clsx } from '../../lib/format'
import { bridgeHas } from '../../lib/bridge'

// The renderer's own cap. Main already rings its buffer, but a drawer left open
// through a reconnect loop would otherwise grow an unbounded React list in a
// process that also has terminals to render.
const MAX_LINES = 500

// stderr is not automatically an error — most engines log routine progress
// there — so the class comes from the stream, and only stderr gets emphasis.
const STREAM_CLASS: Record<VpnLogLine['stream'], string> = {
  stdout: '',
  stderr: 'warn',
  ctl: 'info',
  app: 'info'
}

function clock(at: number): string {
  return new Date(at).toLocaleTimeString(undefined, { hour12: false })
}

interface VpnLogDrawerProps {
  profileId: string
  profileName: string
  onClose: () => void
}

export function VpnLogDrawer({
  profileId,
  profileName,
  onClose
}: VpnLogDrawerProps): React.JSX.Element {
  const [lines, setLines] = useState<VpnLogLine[]>([])
  const scroller = useRef<HTMLDivElement>(null)
  const pinned = useRef(true)

  // Subscribing here and only here is what keeps `vpn:log:<id>` off the wire the
  // rest of the time: preload sends log-subscribe on attach and log-unsubscribe
  // from the teardown it returns, and main ref-counts those. Mounting this
  // drawer is the subscription, unmounting it is the unsubscribe.
  useEffect(() => {
    let live = true
    const vpn = window.shellpilot?.vpn
    const ns = vpn as Record<string, unknown> | undefined

    // Backfill first: lines that arrived before the drawer opened stopped at
    // main's ring buffer, and they are usually the ones explaining the failure
    // this was opened to read.
    if (bridgeHas(ns, 'logs')) {
      void vpn?.logs(profileId, MAX_LINES).then((history) => {
        if (live && history) setLines(history.slice(-MAX_LINES))
      })
    }

    const off = bridgeHas(ns, 'onLog')
      ? vpn?.onLog(profileId, (l) => {
          setLines((prev) => {
            const next =
              prev.length >= MAX_LINES ? prev.slice(prev.length - MAX_LINES + 1) : prev.slice()
            next.push(l)
            return next
          })
        })
      : undefined

    return () => {
      live = false
      off?.()
    }
  }, [profileId])

  // Follow the tail, but stop following the moment the user scrolls up to read
  // something — nothing is more annoying than a log that yanks itself away.
  useEffect(() => {
    const el = scroller.current
    if (el && pinned.current) el.scrollTop = el.scrollHeight
  }, [lines])

  return (
    <Modal
      title={`${profileName} — log`}
      subtitle="Live output from the tunnel engine, with known secrets redacted"
      size="lg"
      onClose={onClose}
      // In the sticky footer, like every other modal in the app. Inside
      // `children` these buttons sit in the scrolling body, and a long log puts
      // Close below the fold of the very view that scrolls.
      footer={
        <>
          <span className="faint" style={{ fontSize: 11 }}>
            Showing the last {MAX_LINES} lines.
          </span>
          <span className="spacer" />
          <button className="btn" onClick={() => setLines([])}>
            Clear view
          </button>
          <button className="btn primary" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      <div
        ref={scroller}
        className="logview"
        style={{ height: 380, overflowY: 'auto', borderRadius: 'var(--r-md)', padding: '6px 0' }}
        onScroll={(e) => {
          const el = e.currentTarget
          pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24
        }}
      >
        {lines.length === 0 ? (
          <div className="log-line faint">No output yet.</div>
        ) : (
          lines.map((l, i) => (
            <div key={`${l.at}-${i}`} className={clsx('log-line', STREAM_CLASS[l.stream])}>
              <span className="ts">{clock(l.at)}</span>
              <span className="lvl">{l.stream}</span>
              <span>{l.text}</span>
            </div>
          ))
        )}
      </div>
    </Modal>
  )
}
