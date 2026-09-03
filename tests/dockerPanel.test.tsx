// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { DockerPanel } from '../src/renderer/src/components/docker/DockerPanel'
import type {
  DockerDiskDetailProbe,
  DockerDiskProbe,
  DockerProbe
} from '../src/shared/docker'
import type { Server } from '../src/renderer/src/types'

// The two defects that shipped out of the itemised disk view, rendered rather
// than read.
//
// Both were found by review, not by a test, because there was no way to run a
// component at all — the existing docker panel suites `readFileSync` the .tsx
// and assert regexes against the source, which can see that a generation
// counter is mentioned and cannot see whether it is consulted before the
// setState that matters.
//
//  1. A `diskDetail` read still in flight when the operator changes server
//     landed under the NEW server's heading: one host's image, volume and
//     container names presented as another host's. That is a cross-server data
//     leak, and the itemise button hides itself once a listing exists, so there
//     was no way to notice or correct it on screen.
//
//  2. A FAILED itemise read was a dead end. The button gated on
//     `diskItems === null`, so the most likely failure — an SSH timeout, and
//     the most transient one — removed the only control that could retry it.
//
// Both fixes are in DockerPanel.tsx today. These tests fail if either is
// reverted; see docs/plans/roadmap-execution.md for the proof.

function server(id: string, name: string): Server {
  return {
    id,
    workspaceId: 'ws-default',
    folderId: null,
    name,
    host: `${id}.example.internal`,
    port: 22,
    username: 'ops',
    auth: 'key',
    status: 'online',
    tags: [],
    favorite: false,
    os: 'linux',
    route: [],
    vpnProfileId: null
  }
}

const ALPHA = server('srv-alpha', 'alpha')
const BRAVO = server('srv-bravo', 'bravo')

function listing(prefix: string): DockerProbe {
  return {
    ok: true,
    version: '24.0.7',
    composeLabels: 'read',
    containers: [
      {
        id: `${prefix}0123456789ab`,
        shortId: `${prefix}012345`,
        name: `${prefix}-api`,
        image: `${prefix}/api:latest`,
        state: 'running',
        status: 'Up 3 hours',
        ports: '',
        createdAt: '2026-01-01 00:00:00 +0000 UTC'
      }
    ]
  }
}

const DISK: DockerDiskProbe = {
  ok: true,
  rows: [
    {
      type: 'Images',
      total: 4,
      active: 2,
      size: '2.0GB',
      sizeBytes: 2_000_000_000,
      reclaimable: '1.0GB',
      reclaimableBytes: 1_000_000_000,
      reclaimablePercent: 50
    }
  ]
}

/** An itemised listing whose image name says which host it came from. That
 *  name is the whole assertion: it must never appear under the other host. */
function detail(prefix: string): DockerDiskDetailProbe {
  return {
    ok: true,
    engine: null,
    disk: {
      images: [
        {
          repository: `${prefix}-only/leaked-image`,
          tag: 'v1',
          id: `${prefix}aaa111`,
          created: '3 weeks ago',
          size: '1.2GB',
          sizeBytes: 1_200_000_000,
          sharedSize: '0B',
          sharedSizeBytes: 0,
          uniqueSize: '1.2GB',
          uniqueSizeBytes: 1_200_000_000,
          containers: 0,
          dangling: false
        }
      ],
      containers: [],
      volumes: [],
      buildCache: [],
      sections: { images: true, containers: true, volumes: true, buildCache: true },
      unreadable: 0
    }
  }
}

interface Cfg {
  serverId: string
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

/** Reassigned per phase of a test, so a read can be left in the air. */
let diskDetailImpl: (cfg: Cfg) => Promise<DockerDiskDetailProbe>

beforeEach(() => {
  diskDetailImpl = (cfg) => Promise.resolve(detail(cfg.serverId.replace('srv-', '')))
  stubBridge({
    docker: {
      list: (cfg: Cfg) => Promise.resolve(listing(cfg.serverId.replace('srv-', ''))),
      disk: () => Promise.resolve(DISK),
      diskDetail: (cfg: Cfg) => diskDetailImpl(cfg)
    }
  })
})

const btn = (name: RegExp): HTMLElement => screen.getByRole('button', { name })

/** Read containers, then open the disk card. Every itemise assertion needs
 *  both: the itemise control only exists inside a successful disk card. */
async function openDiskCard(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(btn(/Read containers/))
  await screen.findByText(/Disk usage/)
  await user.click(btn(/Disk usage/))
  await screen.findByText(/reclaimable/)
}

describe('DockerPanel — itemised disk view', () => {
  it('renders the itemised listing for the server that asked for it', async () => {
    const user = userEvent.setup()
    render(<DockerPanel servers={[ALPHA, BRAVO]} />)
    await openDiskCard(user)

    await user.click(btn(/Itemise/))

    await waitFor(() => {
      expect(document.body.textContent).toContain('alpha-only/leaked-image')
    })
  })

  // The leak. This is the test that would have caught it.
  it('drops a diskDetail read that lands after the operator changed server', async () => {
    const user = userEvent.setup()
    render(<DockerPanel servers={[ALPHA, BRAVO]} />)
    await openDiskCard(user)

    // Alpha's itemise goes out and stays out. `docker system df -v` walks every
    // image and volume on the host and is allowed sixty seconds, so this window
    // is not hypothetical.
    const inFlight = deferred<DockerDiskDetailProbe>()
    diskDetailImpl = () => inFlight.promise
    await user.click(btn(/Itemise/))

    // The operator moves on.
    await user.selectOptions(screen.getByRole('combobox'), 'srv-bravo')
    diskDetailImpl = (cfg) => Promise.resolve(detail(cfg.serverId.replace('srv-', '')))
    await openDiskCard(user)
    expect(document.body.textContent).toContain('bravo-api')

    // ...and alpha's answer finally arrives.
    await act(async () => {
      inFlight.resolve(detail('alpha'))
    })

    expect(document.body.textContent).not.toContain('alpha-only/leaked-image')
    // Not merely invisible: no listing was adopted at all, so the control that
    // offers one is still the first-time "Itemise" rather than "Try again".
    expect(btn(/Itemise/)).toBeTruthy()
  })

  // The dead end. A failed read must leave a way out.
  it('offers "Try again" after a failed itemise read, and it works', async () => {
    const user = userEvent.setup()
    render(<DockerPanel servers={[ALPHA, BRAVO]} />)
    await openDiskCard(user)

    diskDetailImpl = () =>
      Promise.resolve({
        ok: false,
        reason: 'unknown',
        detail: 'ssh: connection timed out after 60s'
      })
    await user.click(btn(/Itemise/))
    await screen.findByText(/connection timed out/)

    // The way out exists...
    const retry = btn(/Try again/)
    expect(retry.hasAttribute('disabled')).toBe(false)

    // ...and it is a real retry, not a label.
    diskDetailImpl = (cfg) => Promise.resolve(detail(cfg.serverId.replace('srv-', '')))
    await user.click(retry)

    await waitFor(() => {
      expect(document.body.textContent).toContain('alpha-only/leaked-image')
    })
    expect(document.body.textContent).not.toContain('connection timed out')
  })
})
