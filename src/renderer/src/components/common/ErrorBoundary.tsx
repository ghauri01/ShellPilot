import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, Copy, RotateCcw } from 'lucide-react'

interface Props {
  children: ReactNode
}
interface State {
  error: Error | null
  stack: string | null
}

// Without this, a single render error unmounts the whole tree and leaves an
// empty window with no message and no way back — the user sees a white or
// black screen and loses their sessions with no idea why.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, stack: null }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Goes to the terminal in dev and to the crash log in production.
    console.error('[renderer] unhandled error:', error, info.componentStack)
    this.setState({ stack: info.componentStack ?? null })
  }

  private report = (): string =>
    [
      this.state.error?.message ?? 'Unknown error',
      '',
      this.state.error?.stack ?? '',
      '',
      'Component stack:',
      this.state.stack ?? ''
    ].join('\n')

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children

    return (
      <div className="crash">
        <div className="crash-card">
          <div className="crash-icon">
            <AlertTriangle size={24} />
          </div>
          <h2>Something broke in the interface</h2>
          <p className="faint">
            Your servers, credentials and vault are stored on disk and are unaffected. Reloading
            rebuilds the window — any open SSH sessions will be reconnected.
          </p>

          <pre className="crash-detail selectable">{error.message}</pre>

          <div className="row" style={{ gap: 8, justifyContent: 'center' }}>
            <button
              className="btn"
              onClick={() => window.shellpilot?.clipboard.write(this.report())}
            >
              <Copy size={14} /> Copy details
            </button>
            <button className="btn primary" onClick={() => window.location.reload()}>
              <RotateCcw size={14} /> Reload
            </button>
          </div>

          <p className="faint" style={{ fontSize: 11, marginTop: 12 }}>
            Please include the copied details in a bug report — with hostnames and usernames
            redacted.
          </p>
        </div>
      </div>
    )
  }
}
