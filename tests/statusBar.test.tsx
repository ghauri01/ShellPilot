// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { stubBridge } from './setup/renderer'
import { StatusBar } from '../src/renderer/src/components/layout/StatusBar'
import { useAlerts } from '../src/renderer/src/store/alerts'
import { useApp } from '../src/renderer/src/store/app'
import { useFleetStatus } from '../src/renderer/src/store/fleetStatus'

// The status bar, rendered — the third component in this suite and the one that
// is here to show the harness is not shaped around DockerPanel.
//
// It is also where a real defect lived. The alert chip's tooltip used to build
// its label with a ternary over two kinds; when `disk` became a third
// AlertKind, every disk alert arrived in the status bar labelled "Memory". The
// fix was `LABEL[a.kind]` — a Record, so a fourth kind is a type error rather
// than a mislabelled alarm — and the comment in StatusBar.tsx says so. Nothing
// tested it: the tooltip is a string built during render, which is exactly what
// a readFileSync-and-regex test cannot evaluate.

/** One active alert, in the shape store/alerts.ts keys them by. */
function raise(kind: 'cpu' | 'ram' | 'disk', value: number): void {
  useAlerts.setState({
    active: {
      [`s1:${kind}`]: { serverId: 's1', serverName: 'web-1', kind, value, since: Date.now() }
    }
  })
}

const chip = (): HTMLElement => screen.getByRole('button', { name: /alert/ })

describe('StatusBar', () => {
  it('labels a disk alert "Disk", not "Memory"', () => {
    stubBridge({})
    raise('disk', 91)

    render(<StatusBar />)

    expect(chip().getAttribute('title')).toContain('web-1: Disk 91%')
    expect(chip().getAttribute('title')).not.toContain('Memory')
  })

  it('still labels the other two kinds correctly', () => {
    stubBridge({})
    useAlerts.setState({
      active: {
        's1:ram': { serverId: 's1', serverName: 'web-1', kind: 'ram', value: 88, since: Date.now() },
        's2:cpu': { serverId: 's2', serverName: 'db-1', kind: 'cpu', value: 97, since: Date.now() }
      }
    })

    render(<StatusBar />)

    const title = chip().getAttribute('title') ?? ''
    expect(title).toContain('web-1: Memory 88%')
    expect(title).toContain('db-1: CPU 97%')
    expect(chip().textContent).toContain('2 alerts')
  })

  // The negative case matters as much: a bar that always shows a chip cannot
  // tell you anything by showing one. This is also the assertion that proves
  // the previous test's store writes were rolled back rather than inherited.
  it('shows no alert chip when nothing is alerting', () => {
    stubBridge({})

    render(<StatusBar />)

    expect(screen.queryByRole('button', { name: /alert/ })).toBeNull()
    // ...and the pristine store really is pristine.
    expect(useAlerts.getState().list()).toEqual([])
  })

  it('renders the active workspace and the session count', () => {
    stubBridge({})
    useApp.setState({ tabs: [] })

    render(<StatusBar />)

    expect(document.body.textContent).toContain('Personal')
    expect(document.body.textContent).toContain('0 sessions')
  })

  // The sampler warning is the other thing this bar is responsible for saying,
  // and it is the one an operator most needs: an alert count of zero means
  // nothing when the thing that counts them has stopped.
  it('warns when background checking is enabled but not running', () => {
    stubBridge({})
    useApp.getState().setSettings({ fleetSamplingEnabled: true })
    useFleetStatus.getState().setStatus({
      running: false,
      idleReason: 'vault-locked',
      targetCount: 3
    })

    render(<StatusBar />)

    expect(screen.getByRole('button', { name: /Checks paused/ })).toBeTruthy()
  })
})
