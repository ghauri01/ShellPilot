import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { useApp } from '../src/renderer/src/store/app'
import type { LocalShell } from '../src/shared/local'
import type { Server } from '../src/renderer/src/types'

// The tab model is a discriminated union: an SSH tab carries a `serverId`, a
// local tab carries a `shellId` and nothing else. The alternative — minting a
// pseudo-`Server` row so every existing consumer keeps working — is what these
// tests exist to make impossible: `servers` is persisted (store/persist.ts:16),
// fed to `data:save` (main/index.ts:704) and mirrored into the MCP data cache,
// so a fake row there is an MCP-addressable target that nobody registered a
// tool for.

const zsh: LocalShell = {
  id: 'darwin-zsh-b663616e',
  label: 'zsh',
  kind: 'posix',
  path: '/bin/zsh',
  args: ['-l'],
  isDefault: true
}

// A second shell that shares the readable prefix but not the path digest —
// shell ids are opaque, and the numbering must key off the whole id rather
// than anything parsed out of it.
const brewZsh: LocalShell = {
  id: 'darwin-zsh-11f4c0a2',
  label: 'zsh (homebrew)',
  kind: 'posix',
  path: '/opt/homebrew/bin/zsh',
  args: ['-l']
}

const server = (id: string, name: string, workspaceId = 'ws-default'): Server => ({
  id,
  workspaceId,
  folderId: null,
  name,
  host: 'example.test',
  port: 22,
  username: 'root',
  auth: 'key',
  status: 'offline',
  tags: [],
  favorite: false,
  os: 'Linux',
  route: [],
  vpnProfileId: null
})

const reset = (): void => {
  useApp.setState({
    tabs: [],
    activeTabId: null,
    tabSession: {},
    tabCwd: {},
    panes: {},
    servers: [],
    localShells: [],
    workspaces: [
      { id: 'ws-default', name: 'Personal', color: 'cyan', hidden: false, locked: false, hasPassword: false }
    ],
    activeWorkspaceId: 'ws-default'
  })
}

describe('local tabs', () => {
  beforeEach(reset)

  it('opens a local tab with no serverId at all', () => {
    useApp.getState().openLocal(zsh)
    const [tab] = useApp.getState().tabs
    expect(tab.kind).toBe('local')
    // Not `toBeUndefined()`: the point is that the key is absent, not that it
    // holds a nullish value. A tab carrying `serverId: undefined` still reads
    // as a server-shaped record to anything doing `'serverId' in t`.
    expect('serverId' in tab).toBe(false)
    expect(tab.title).toBe('zsh')
    expect(useApp.getState().activeTabId).toBe(tab.id)
  })

  it('records the shell id and the requested cwd on the tab', () => {
    useApp.getState().openLocal(zsh, '/Users/me/src')
    const tab = useApp.getState().tabs[0]
    expect(tab).toMatchObject({ kind: 'local', shellId: zsh.id, cwd: '/Users/me/src', view: 'terminal' })
  })

  it('numbers repeat local sessions per shell, not per server', () => {
    const open = useApp.getState().openLocal
    open(zsh)
    open(zsh)
    open(zsh)
    expect(useApp.getState().tabs.map((t) => t.title)).toEqual(['zsh', 'zsh (2)', 'zsh (3)'])
  })

  it('numbers each shell independently', () => {
    const open = useApp.getState().openLocal
    open(zsh)
    open(brewZsh)
    open(zsh)
    open(brewZsh)
    expect(useApp.getState().tabs.map((t) => t.title)).toEqual([
      'zsh',
      'zsh (homebrew)',
      'zsh (2)',
      'zsh (homebrew) (2)'
    ])
  })

  it('always opens a new tab rather than focusing an existing one', () => {
    const open = useApp.getState().openLocal
    open(zsh)
    open(zsh)
    const tabs = useApp.getState().tabs
    expect(tabs).toHaveLength(2)
    expect(tabs[0].id).not.toBe(tabs[1].id)
    expect(useApp.getState().activeTabId).toBe(tabs[1].id)
  })

  it('never writes a synthesized server into the servers list', () => {
    // The whole reason for the discriminated union: `servers` is persisted and
    // fed to the MCP data cache, so anything added here becomes an
    // MCP-addressable server.
    const before = useApp.getState().servers
    useApp.getState().openLocal(zsh)
    expect(useApp.getState().servers).toEqual([])
    // Reference equality too: persist.ts drives its save timer off `servers !==
    // prev.servers`, so even a same-content rebuild would mark the backup stale.
    expect(useApp.getState().servers).toBe(before)
  })

  it('leaves the monitor groups alone as well', () => {
    // syncMonitorLayout files every server in the workspace onto the monitor
    // wall, where a card dials SSH on a timer. Nothing to file means no card.
    const before = useApp.getState().monitorGroups
    useApp.getState().openLocal(zsh)
    expect(useApp.getState().monitorGroups).toBe(before)
  })
})

describe('local tabs alongside servers', () => {
  beforeEach(reset)

  it('keeps local tabs when the server they sit beside is deleted', () => {
    useApp.setState({ servers: [server('s1', 'box')] })
    useApp.getState().openServer('s1')
    useApp.getState().openLocal(zsh)
    useApp.getState().deleteServer('s1')
    expect(useApp.getState().tabs.map((t) => t.kind)).toEqual(['local'])
  })

  it('clears activeTabId only when the deleted server owned the active tab', () => {
    useApp.setState({ servers: [server('s1', 'box')] })
    useApp.getState().openLocal(zsh)
    const localId = useApp.getState().tabs[0].id
    useApp.getState().openServer('s1')
    // The SSH tab is active and is the one going away.
    useApp.getState().deleteServer('s1')
    expect(useApp.getState().activeTabId).toBeNull()

    useApp.setState({ servers: [server('s2', 'other')] })
    useApp.getState().setActiveTab(localId)
    useApp.getState().deleteServer('s2')
    expect(useApp.getState().activeTabId).toBe(localId)
  })

  it('does not renumber ssh sessions because a local tab exists', () => {
    useApp.setState({ servers: [server('s1', 'box')] })
    useApp.getState().openLocal(zsh)
    useApp.getState().newSession('s1')
    useApp.getState().newSession('s1')
    expect(useApp.getState().tabs.map((t) => t.title)).toEqual(['zsh', 'box', 'box (2)'])
  })
})

describe('deleteWorkspace', () => {
  beforeEach(reset)

  it('removes local tabs belonging to the deleted workspace', () => {
    useApp.setState({
      workspaces: [
        { id: 'ws-default', name: 'Personal', color: 'cyan', hidden: false, locked: false, hasPassword: false },
        { id: 'ws-2', name: 'Work', color: 'blue', hidden: false, locked: false, hasPassword: false }
      ]
    })
    useApp.getState().openLocal(zsh)
    const keeper = useApp.getState().tabs[0].id
    useApp.getState().setWorkspace('ws-2')
    useApp.getState().openLocal(zsh)
    expect(useApp.getState().tabs).toHaveLength(2)

    useApp.getState().deleteWorkspace('ws-2')
    expect(useApp.getState().tabs.map((t) => t.id)).toEqual([keeper])
  })

  it('never leaves activeTabId pointing at a tab it just removed', () => {
    useApp.setState({
      workspaces: [
        { id: 'ws-default', name: 'Personal', color: 'cyan', hidden: false, locked: false, hasPassword: false },
        { id: 'ws-2', name: 'Work', color: 'blue', hidden: false, locked: false, hasPassword: false }
      ]
    })
    useApp.getState().setWorkspace('ws-2')
    useApp.getState().openLocal(zsh)
    const doomed = useApp.getState().activeTabId
    expect(doomed).not.toBeNull()

    useApp.getState().deleteWorkspace('ws-2')
    const { tabs, activeTabId } = useApp.getState()
    expect(tabs.some((t) => t.id === doomed)).toBe(false)
    expect(activeTabId === null || tabs.some((t) => t.id === activeTabId)).toBe(true)
  })

  it('removes ssh tabs whose server went with the workspace', () => {
    useApp.setState({
      workspaces: [
        { id: 'ws-default', name: 'Personal', color: 'cyan', hidden: false, locked: false, hasPassword: false },
        { id: 'ws-2', name: 'Work', color: 'blue', hidden: false, locked: false, hasPassword: false }
      ],
      servers: [server('s1', 'box', 'ws-2')]
    })
    useApp.getState().openServer('s1')
    useApp.getState().deleteWorkspace('ws-2')
    expect(useApp.getState().tabs).toEqual([])
    expect(useApp.getState().activeTabId).toBeNull()
  })
})

describe('local tab views', () => {
  beforeEach(reset)

  it('refuses to move a local tab off the terminal view', () => {
    // Monitor and Files are SSH-only. Switching a local tab to 'files' used to
    // be reachable from the open-files shortcut and blanked the pane with no
    // way back.
    useApp.getState().openLocal(zsh)
    const id = useApp.getState().tabs[0].id
    useApp.getState().setTabView(id, 'files')
    expect(useApp.getState().tabs[0].view).toBe('terminal')
  })

  it('still switches views on ssh tabs', () => {
    useApp.setState({ servers: [server('s1', 'box')] })
    useApp.getState().openServer('s1')
    const id = useApp.getState().tabs[0].id
    useApp.getState().setTabView(id, 'files')
    expect(useApp.getState().tabs[0].view).toBe('files')
  })
})

describe('duplicateTab', () => {
  beforeEach(reset)

  it('duplicates a local tab as a local tab on the same shell', () => {
    useApp.getState().openLocal(zsh, '/tmp/work')
    const src = useApp.getState().tabs[0]
    useApp.getState().duplicateTab(src.id)
    const tabs = useApp.getState().tabs
    expect(tabs).toHaveLength(2)
    expect(tabs[1]).toMatchObject({ kind: 'local', shellId: zsh.id, cwd: '/tmp/work', title: 'zsh (2)' })
    expect('serverId' in tabs[1]).toBe(false)
  })

  it('duplicates an ssh tab as an ssh tab', () => {
    useApp.setState({ servers: [server('s1', 'box')] })
    useApp.getState().openServer('s1')
    useApp.getState().duplicateTab(useApp.getState().tabs[0].id)
    const tabs = useApp.getState().tabs
    expect(tabs.map((t) => t.kind)).toEqual(['ssh', 'ssh'])
    expect(tabs[1].title).toBe('box (2)')
  })
})

describe('localShells slice', () => {
  beforeEach(reset)

  it('openLocalById resolves against the cached shell list synchronously', () => {
    useApp.setState({ localShells: [zsh, brewZsh] })
    // Not awaited on purpose: the hotkey RUNNERS entries are (s) => boolean and
    // cannot await anything, so this has to have taken effect on return.
    useApp.getState().openLocalById(brewZsh.id)
    expect(useApp.getState().tabs).toHaveLength(1)
    expect(useApp.getState().tabs[0]).toMatchObject({ kind: 'local', shellId: brewZsh.id })
  })

  it('openLocalById is a no-op for an id that is not in the list', () => {
    useApp.setState({ localShells: [zsh] })
    useApp.getState().openLocalById('darwin-fish-deadbeef')
    expect(useApp.getState().tabs).toEqual([])
  })

  it('openLocalById forwards the cwd', () => {
    useApp.setState({ localShells: [zsh] })
    useApp.getState().openLocalById(zsh.id, '/var/log')
    expect(useApp.getState().tabs[0]).toMatchObject({ cwd: '/var/log' })
  })

  it('refreshLocalShells is a no-op when the preload bridge has no local namespace', async () => {
    // The `local` preload namespace lands in a later phase; until then this
    // must degrade quietly rather than throw inside whatever effect calls it.
    await expect(useApp.getState().refreshLocalShells()).resolves.toBeUndefined()
    expect(useApp.getState().localShells).toEqual([])
  })

  it('refreshLocalShells stores what the bridge returns', async () => {
    const w = globalThis as { window?: unknown }
    const had = 'window' in w
    const prev = w.window
    w.window = { shellpilot: { local: { shells: async () => [zsh, brewZsh] } } }
    try {
      await useApp.getState().refreshLocalShells()
      expect(useApp.getState().localShells).toEqual([zsh, brewZsh])
    } finally {
      if (had) w.window = prev
      else delete w.window
    }
  })
})

describe('persistence', () => {
  // Finding: `Tab` is not in the persisted set, so the union needs no
  // migration. Asserted rather than assumed — a later change that adds tabs to
  // the blob has to come back through here and write the `kind` default.
  const persistSrc = readFileSync(resolve(__dirname, '../src/renderer/src/store/persist.ts'), 'utf8')

  it('does not persist tabs', () => {
    expect(persistSrc).not.toMatch(/\btabs\b/)
  })

  it('does not persist the discovered shell list', () => {
    // localShells is a cache of what is installed on *this* machine. Restoring
    // it from a backup taken on another one would offer shells that are not
    // there.
    expect(persistSrc).not.toMatch(/localShells/)
  })
})
