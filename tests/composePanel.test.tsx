// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { ComposePanel } from '../src/renderer/src/components/docker/ComposePanel'
import type { ComposeConfigProbe, ComposeListProbe } from '../src/shared/compose'
import type { DockerContainer } from '../src/shared/docker'
import type { Server } from '../src/renderer/src/types'

// Rendered rather than read. The rule this panel has to keep is not visible in
// a source regex: a component can import COMPOSE_ENV_DISCLOSURE and never
// render it, and it can be handed an environment value and put it on screen
// without any single line looking wrong.

const SERVER: Server = {
  id: 'srv-edge',
  workspaceId: 'ws-default',
  folderId: null,
  name: 'edge-01',
  host: 'edge-01.example.internal',
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

const LIST: ComposeListProbe = {
  ok: true,
  composeVersion: '2.29.7',
  projectsFrom: 'compose-ls',
  projects: [
    {
      name: 'edge',
      status: 'running(1)',
      running: 1,
      stopped: 0,
      configFiles: ['/srv/edge/compose.yaml']
    }
  ],
  search: {
    files: [],
    truncated: false,
    bound: {
      roots: ['/srv', '/opt'],
      maxDepth: 4,
      maxResults: 200,
      pruned: ['node_modules'],
      fileNames: ['compose.yaml'],
      crossesFilesystems: false
    }
  }
}

const CONFIG: ComposeConfigProbe = {
  ok: true,
  config: {
    name: 'edge',
    namesOnly: false,
    volumes: [],
    networks: [],
    services: [
      {
        name: 'cache',
        image: 'redis:7.2-alpine',
        build: false,
        containerName: null,
        dependsOn: [],
        ports: [],
        profiles: [],
        environment: [
          { name: 'REDIS_PASSWORD', origin: 'interpolated', variable: 'REDIS_PASSWORD', set: true }
        ],
        envFiles: ['/srv/edge/.env'],
        restart: null
      },
      {
        name: 'worker',
        image: 'busybox:1.36',
        build: false,
        containerName: null,
        dependsOn: [],
        ports: [],
        profiles: [],
        environment: [],
        envFiles: [],
        restart: null
      }
    ]
  }
}

const RUNNING_CACHE: DockerContainer = {
  id: 'a'.repeat(64),
  shortId: 'a'.repeat(12),
  name: 'edge-cache-1',
  image: 'redis:7.2-alpine',
  state: 'running',
  status: 'Up 2 minutes',
  ports: '',
  createdAt: 'now',
  composeProject: 'edge',
  composeService: 'cache'
}

function panelBridge(over: Record<string, unknown> = {}) {
  return {
    compose: {
      list: vi.fn(async () => LIST),
      config: vi.fn(async () => CONFIG),
      envNames: vi.fn(async () => ({
        ok: true as const,
        files: [
          {
            path: '/srv/edge/.env',
            readable: true,
            names: [{ name: 'REDIS_PASSWORD', set: true }]
          }
        ]
      })),
      readFile: vi.fn(async () => ({
        ok: true,
        text: 'services:\n  cache:\n    image: redis:7.2-alpine\n'
      })),
      writeImageTag: vi.fn(async () => ({
        ok: true as const,
        plan: {
          ok: true as const,
          service: 'cache',
          line: 3,
          from: 'redis:7.2-alpine',
          to: 'redis:7.4-alpine',
          before: '    image: redis:7.2-alpine',
          after: '    image: redis:7.4-alpine'
        },
        backup: '/srv/edge/compose.yaml.shellpilot-bak'
      })),
      ...over
    },
    jobs: { run: vi.fn(async () => ({})) }
  }
}

async function openProject(bridgeStub: Record<string, unknown>): Promise<void> {
  stubBridge(bridgeStub)
  render(<ComposePanel server={SERVER} cfg={{}} containers={[RUNNING_CACHE]} sudo={false} />)
  await userEvent.click(screen.getByText('Find compose files'))
  await waitFor(() => screen.getByText(/▸ edge/))
  await userEvent.click(screen.getByText(/▸ edge/))
  // `cache` appears twice once the project opens — once as a service row, once
  // as an environment row — so this waits for at least one rather than exactly
  // one.
  await waitFor(() => expect(screen.getAllByText('cache').length).toBeGreaterThan(0))
}

describe('what the panel shows about environment', () => {
  it('names a variable and marks it set, without its value anywhere on screen', async () => {
    await openProject(panelBridge())
    // Twice: once from the compose model, once from the .env summary. Both are
    // names with a set/empty marker and neither is a value.
    expect(screen.getAllByText(/REDIS_PASSWORD=\(set\)/).length).toBe(2)
    // The value never reached the renderer, so it cannot be here — but the
    // assertion is on the rendered DOM rather than on the bridge, because that
    // is where a future refactor would put it back.
    expect(document.body.textContent).not.toContain('hunter2')
  })

  it('says on screen that the withholding is deliberate', async () => {
    await openProject(panelBridge())
    expect(document.body.textContent).toContain('never their values')
    expect(document.body.textContent).toContain('open the file on the host')
  })

  it('does not claim a .env is empty when it could not be read', async () => {
    await openProject(
      panelBridge({
        envNames: vi.fn(async () => ({
          ok: true as const,
          files: [{ path: '/srv/edge/.env', readable: false, names: [] }]
        }))
      })
    )
    expect(screen.getByText(/could not be read/)).toBeTruthy()
  })
})

describe('declared against running', () => {
  it('says which declared service has no container at all', async () => {
    await openProject(panelBridge())
    // `cache` is running. `worker` is declared and has never been created,
    // which is the fact the container list above cannot state because there is
    // no container to list.
    expect(screen.getByText('never created')).toBeTruthy()
    expect(document.body.textContent).toContain('Declared but never created: worker')
  })

  it('does not present a names-only read as a project with no images', async () => {
    await openProject(
      panelBridge({
        config: vi.fn(async () => ({
          ok: true as const,
          config: {
            name: 'edge',
            namesOnly: true,
            volumes: [],
            networks: [],
            services: [
              {
                name: 'cache',
                image: null,
                build: false,
                containerName: null,
                dependsOn: [],
                ports: [],
                profiles: [],
                environment: [],
                envFiles: [],
                restart: null
              }
            ]
          }
        }))
      })
    )
    expect(document.body.textContent).toContain('unknown here rather than absent')
  })
})

describe('what the panel refuses', () => {
  it('offers exactly two verbs and no third', async () => {
    await openProject(panelBridge())
    // Asserted as the whole set rather than as an absence of the word "down".
    // An absence check passes the moment somebody spells the button
    // differently; this fails the moment a third action button appears at all,
    // whatever it is called.
    const titled = screen
      .getAllByRole('button')
      .map((b) => b.getAttribute('title'))
      .filter((t): t is string => t !== null)
    expect(titled).toEqual([
      'docker compose pull for edge. Fetches images; nothing running changes.',
      'docker compose up -d for edge. Starts what is declared; removes nothing.',
      "Change cache's image tag in the compose file. Nothing is pulled or restarted.",
      "Change worker's image tag in the compose file. Nothing is pulled or restarted."
    ])
  })

  it('prints the reason where the button would have been', async () => {
    await openProject(panelBridge())
    expect(document.body.textContent).toContain('removes every container in the project')
  })
})

describe('the search bounds are on screen', () => {
  it('says where it looked, so an empty answer can be read', async () => {
    await openProject(panelBridge())
    expect(document.body.textContent).toContain('Looked in /srv, /opt')
    expect(document.body.textContent).toContain('4 levels')
    expect(document.body.textContent).toContain('on this filesystem only')
  })

  it('says when the cap cut the list off', async () => {
    await openProject(
      panelBridge({
        list: vi.fn(async () => ({
          ...LIST,
          search: { ...LIST.ok ? LIST.search! : null!, truncated: true }
        }))
      })
    )
    expect(document.body.textContent).toContain('prefix rather than an inventory')
  })
})

describe('pull and up go through the job engine', () => {
  it('runs a job rather than a compose command of its own', async () => {
    const stub = panelBridge()
    await openProject(stub)
    await userEvent.click(screen.getByTitle(/docker compose pull/))
    const run = (stub.jobs as { run: ReturnType<typeof vi.fn> }).run
    await waitFor(() => expect(run).toHaveBeenCalled())
    const req = run.mock.calls[0][0] as {
      spec: { steps: { command: string }[]; title: string }
      approval: unknown
    }
    expect(req.spec.steps[0].command).toBe(
      "docker compose --project-name 'edge' -f '/srv/edge/compose.yaml' pull"
    )
    // The approval record the runner re-checks. A job launched without one is
    // a job started on a confirmation nobody wrote down.
    expect(req.approval).toBeTruthy()
  })
})

describe('the image tag edit', () => {
  it('sends the line the operator was shown, so the host can refuse a stale edit', async () => {
    const stub = panelBridge()
    await openProject(stub)
    await userEvent.click(screen.getByTitle(/Change cache's image tag/))
    const input = screen.getByDisplayValue('redis:7.2-alpine')
    await userEvent.clear(input)
    await userEvent.type(input, 'redis:7.4-alpine')
    await userEvent.click(screen.getByText('Write the file'))
    const write = (stub.compose as { writeImageTag: ReturnType<typeof vi.fn> }).writeImageTag
    await waitFor(() => expect(write).toHaveBeenCalled())
    expect(write.mock.calls[0][1]).toEqual({
      path: '/srv/edge/compose.yaml',
      service: 'cache',
      image: 'redis:7.4-alpine',
      expect: { line: 3, before: '    image: redis:7.2-alpine' }
    })
  })

  it('will not offer to write a reference it cannot prove is one', async () => {
    await openProject(panelBridge())
    await userEvent.click(screen.getByTitle(/Change cache's image tag/))
    const input = screen.getByDisplayValue('redis:7.2-alpine')
    await userEvent.clear(input)
    await userEvent.type(input, '../etc/passwd')
    expect(screen.getByText('Write the file').hasAttribute('disabled')).toBe(true)
  })

  it('says the new image is not running yet', async () => {
    const stub = panelBridge()
    await openProject(stub)
    await userEvent.click(screen.getByTitle(/Change cache's image tag/))
    const input = screen.getByDisplayValue('redis:7.2-alpine')
    await userEvent.clear(input)
    await userEvent.type(input, 'redis:7.4-alpine')
    await userEvent.click(screen.getByText('Write the file'))
    await waitFor(() =>
      expect(document.body.textContent).toContain('Nothing is running the new image')
    )
  })
})
