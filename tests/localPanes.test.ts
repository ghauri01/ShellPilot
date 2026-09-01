import { describe, it, expect, beforeEach } from 'vitest'
import { useApp, MAX_PANES, splitDirectionOf, DEFAULT_SETTINGS } from '../src/renderer/src/store/app'
import type { LocalShell } from '../src/shared/local'
import type { Server } from '../src/renderer/src/types'

// Panes are the highest-risk part of the local-terminal work and the only part
// with no compile-time guard: `tabSession` and `tabCwd` moved from being keyed
// by tab id to being keyed by pane id, which is a change no type notices
// because both are `Record<string, string>`. Everything asserted here is a way
// that re-key can leak, strand or lose state.
//
// The store runs under `environment: 'node'` — it touches `window` only through
// guarded helpers — so these are real store calls, not mocks of one.

const zsh: LocalShell = {
  id: 'darwin-zsh-b663616e',
  label: 'zsh',
  kind: 'posix',
  path: '/bin/zsh',
  args: ['-l'],
  isDefault: true
}

const server = (id: string, name: string): Server => ({
  id,
  workspaceId: 'ws-default',
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
    servers: [server('s1', 'box')],
    localShells: [zsh],
    workspaces: [
      {
        id: 'ws-default',
        name: 'Personal',
        color: 'cyan',
        hidden: false,
        locked: false,
        hasPassword: false
      }
    ],
    activeWorkspaceId: 'ws-default'
  })
}

// The store is the source of pane ids; nothing derives one during render.
const panesOf = (tabId: string): string[] =>
  useApp.getState().panes[tabId].panes.map((p) => p.id)

const activeTabId = (): string => {
  const id = useApp.getState().activeTabId
  if (!id) throw new Error('no active tab')
  return id
}

// Stands in for what a live terminal writes: the session hook is handed a pane
// id and calls setTabSession/setTabCwd with it.
const live = (paneId: string, cwd = '/srv'): void => {
  useApp.getState().setTabSession(paneId, `sess-${paneId}`)
  useApp.getState().setTabCwd(paneId, cwd)
}

describe('every tab is born with exactly one pane', () => {
  beforeEach(reset)

  it('mints the pane in the action that creates the tab, not during render', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    const tp = useApp.getState().panes[tab]
    expect(tp.panes).toHaveLength(1)
    expect(tp.activePaneId).toBe(tp.panes[0].id)
    expect(tp.panes[0].target).toEqual({ kind: 'ssh', serverId: 's1' })
  })

  it('gives a local tab a local pane target carrying its cwd', () => {
    useApp.getState().openLocal(zsh, '/work')
    const tp = useApp.getState().panes[activeTabId()]
    expect(tp.panes[0].target).toEqual({ kind: 'local', shellId: zsh.id, cwd: '/work' })
  })

  it('keeps the pane id stable across unrelated store writes', () => {
    useApp.getState().openLocal(zsh)
    const tab = activeTabId()
    const before = panesOf(tab)
    useApp.getState().setActiveTab(tab)
    useApp.getState().setTabCwd(before[0], '/tmp')
    expect(panesOf(tab)).toEqual(before)
  })

  it('reports no split direction while a tab holds one pane', () => {
    useApp.getState().openServer('s1')
    expect(splitDirectionOf(useApp.getState().panes, activeTabId())).toBeNull()
  })
})

describe('splitPane', () => {
  beforeEach(reset)

  it('clones the active pane target and focuses the new pane', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v')
    const tp = useApp.getState().panes[tab]
    expect(tp.panes).toHaveLength(2)
    expect(tp.panes[1].target).toEqual({ kind: 'ssh', serverId: 's1' })
    expect(tp.activePaneId).toBe(tp.panes[1].id)
    expect(tp.direction).toBe('v')
  })

  it('accepts a different target, so a local pane can sit beside a remote one', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v', { kind: 'local', shellId: zsh.id })
    const targets = useApp.getState().panes[tab].panes.map((p) => p.target.kind)
    expect(targets).toEqual(['ssh', 'local'])
  })

  it('inserts next to the pane it split from rather than appending', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v')
    useApp.getState().splitPane(tab, 'v')
    const [first, second, third] = panesOf(tab)
    // Split the first pane again: the new one lands between it and the rest.
    useApp.getState().setActivePane(tab, first)
    useApp.getState().splitPane(tab, 'v')
    const after = panesOf(tab)
    expect(after[0]).toBe(first)
    expect(after.slice(2)).toEqual([second, third])
  })

  it('stops at MAX_PANES and changes nothing at the cap', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    for (let i = 0; i < MAX_PANES + 3; i++) useApp.getState().splitPane(tab, 'v')
    expect(useApp.getState().panes[tab].panes).toHaveLength(MAX_PANES)

    const before = useApp.getState().panes[tab]
    useApp.getState().splitPane(tab, 'v')
    // Not merely the same length: the same object, so the overflow is a true
    // no-op and not a re-render of every pane in the tab.
    expect(useApp.getState().panes[tab]).toBe(before)
  })

  it('is a no-op for a tab that does not exist', () => {
    const before = useApp.getState().panes
    useApp.getState().splitPane('tab-nope', 'v')
    expect(useApp.getState().panes).toBe(before)
  })
})

describe('closePane', () => {
  beforeEach(reset)

  it('removes the pane and its session and cwd entries', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v')
    const [a, b] = panesOf(tab)
    live(a)
    live(b)

    useApp.getState().closePane(tab, b)

    expect(panesOf(tab)).toEqual([a])
    expect(useApp.getState().tabSession).toEqual({ [a]: `sess-${a}` })
    expect(useApp.getState().tabCwd).toEqual({ [a]: '/srv' })
  })

  it('moves focus to the neighbour when the active pane goes', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v')
    useApp.getState().splitPane(tab, 'v')
    const [a, b, c] = panesOf(tab)
    useApp.getState().setActivePane(tab, b)
    useApp.getState().closePane(tab, b)
    expect(useApp.getState().panes[tab].activePaneId).toBe(c)

    useApp.getState().setActivePane(tab, c)
    useApp.getState().closePane(tab, c)
    expect(useApp.getState().panes[tab].activePaneId).toBe(a)
  })

  it('leaves the last pane alone — closing a tab is the tab close, not a pane close', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    const [only] = panesOf(tab)
    live(only)

    useApp.getState().closePane(tab, only)

    expect(useApp.getState().tabs).toHaveLength(1)
    expect(panesOf(tab)).toEqual([only])
    expect(useApp.getState().tabSession[only]).toBe(`sess-${only}`)
  })
})

describe('dropTabs removes every pane entry a closed tab owned', () => {
  beforeEach(reset)

  it('leaves no stranded session or cwd behind a closed split tab', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v')
    useApp.getState().splitPane(tab, 'h')
    for (const p of panesOf(tab)) live(p)
    expect(Object.keys(useApp.getState().tabSession)).toHaveLength(3)

    useApp.getState().closeTab(tab)

    expect(useApp.getState().tabSession).toEqual({})
    expect(useApp.getState().tabCwd).toEqual({})
    expect(useApp.getState().panes[tab]).toBeUndefined()
  })

  it('spares the panes of tabs that survive a bulk close', () => {
    useApp.getState().openServer('s1')
    const keep = activeTabId()
    live(panesOf(keep)[0])
    useApp.getState().openLocal(zsh)
    const doomed = activeTabId()
    useApp.getState().splitPane(doomed, 'v')
    for (const p of panesOf(doomed)) live(p)

    useApp.getState().closeOtherTabs(keep)

    expect(Object.keys(useApp.getState().panes)).toEqual([keep])
    expect(Object.keys(useApp.getState().tabSession)).toEqual(panesOf(keep))
  })

  it('drops pane state for every tab closed at once', () => {
    useApp.getState().openServer('s1')
    useApp.getState().openLocal(zsh)
    for (const t of useApp.getState().tabs) {
      useApp.getState().splitPane(t.id, 'v')
      for (const p of panesOf(t.id)) live(p)
    }

    useApp.getState().closeAllTabs()

    expect(useApp.getState().panes).toEqual({})
    expect(useApp.getState().tabSession).toEqual({})
    expect(useApp.getState().tabCwd).toEqual({})
  })
})

describe('the other two ways a tab is removed prune their panes too', () => {
  beforeEach(reset)

  it('deleteServer takes the pane state of the tabs it closes', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v')
    for (const p of panesOf(tab)) live(p)
    useApp.getState().openLocal(zsh)
    const localTab = activeTabId()
    live(panesOf(localTab)[0])

    useApp.getState().deleteServer('s1')

    // The local tab has no server to cascade from and keeps running.
    expect(Object.keys(useApp.getState().panes)).toEqual([localTab])
    expect(Object.keys(useApp.getState().tabSession)).toEqual(panesOf(localTab))
    expect(Object.keys(useApp.getState().tabCwd)).toEqual(panesOf(localTab))
  })

  it('deleteWorkspace takes the pane state of every tab that goes with it', () => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    useApp.getState().splitPane(tab, 'v')
    useApp.getState().openLocal(zsh)
    for (const t of useApp.getState().tabs) for (const p of panesOf(t.id)) live(p)
    useApp.setState({
      workspaces: [
        ...useApp.getState().workspaces,
        { id: 'ws-2', name: 'Other', color: 'cyan', hidden: false, locked: false, hasPassword: false }
      ]
    })

    useApp.getState().deleteWorkspace('ws-default')

    expect(useApp.getState().tabs).toEqual([])
    expect(useApp.getState().panes).toEqual({})
    expect(useApp.getState().tabSession).toEqual({})
    expect(useApp.getState().tabCwd).toEqual({})
  })
})

describe('duplicateTab copies the layout without sharing a session', () => {
  beforeEach(reset)

  it('copies every pane under fresh ids, keeping direction and focus', () => {
    useApp.getState().openServer('s1')
    const src = activeTabId()
    useApp.getState().splitPane(src, 'h')
    const srcPanes = panesOf(src)
    useApp.getState().setActivePane(src, srcPanes[0])

    useApp.getState().duplicateTab(src)
    const copy = activeTabId()
    const copyPanes = panesOf(copy)

    expect(copy).not.toBe(src)
    expect(copyPanes).toHaveLength(2)
    expect(copyPanes.some((id) => srcPanes.includes(id))).toBe(false)
    expect(useApp.getState().panes[copy].direction).toBe('h')
    // The active pane of the copy is the copy of the source's active pane.
    expect(useApp.getState().panes[copy].activePaneId).toBe(copyPanes[0])
    expect(useApp.getState().panes[src].panes.map((p) => p.id)).toEqual(srcPanes)
  })

  it('inherits the working directory per pane', () => {
    useApp.getState().openServer('s1')
    const src = activeTabId()
    useApp.getState().splitPane(src, 'v')
    const [a, b] = panesOf(src)
    useApp.getState().setTabCwd(a, '/var/log')
    useApp.getState().setTabCwd(b, '/etc')

    useApp.getState().duplicateTab(src)
    const [ca, cb] = panesOf(activeTabId())

    expect(useApp.getState().tabCwd[ca]).toBe('/var/log')
    expect(useApp.getState().tabCwd[cb]).toBe('/etc')
  })

  it('does not copy the session id — the duplicate dials its own', () => {
    useApp.getState().openLocal(zsh)
    const src = activeTabId()
    live(panesOf(src)[0])

    useApp.getState().duplicateTab(src)
    const [copyPane] = panesOf(activeTabId())

    expect(useApp.getState().tabSession[copyPane]).toBeUndefined()
  })

  it('gives a duplicated tab panes even when the source somehow had none', () => {
    // Reachable only by writing tabs into the store directly, which is what a
    // future restore path would do. The duplicate must still be usable.
    useApp.getState().openLocal(zsh)
    const src = activeTabId()
    useApp.setState({ panes: {} })

    useApp.getState().duplicateTab(src)

    expect(useApp.getState().panes[activeTabId()].panes).toHaveLength(1)
  })
})

describe('toggleSplit truth table', () => {
  beforeEach(reset)

  const openSplit = (n: number, dir: 'h' | 'v' = 'v'): string => {
    useApp.getState().openServer('s1')
    const tab = activeTabId()
    for (let i = 1; i < n; i++) useApp.getState().splitPane(tab, dir)
    return tab
  }

  it('1 pane, either direction: splits to two', () => {
    const tab = openSplit(1)
    useApp.getState().toggleSplit(tab, 'h')
    expect(useApp.getState().panes[tab].panes).toHaveLength(2)
    expect(useApp.getState().panes[tab].direction).toBe('h')
    expect(splitDirectionOf(useApp.getState().panes, tab)).toBe('h')
  })

  it('2 panes, same direction: collapses to the pane that had focus', () => {
    const tab = openSplit(2, 'v')
    const [a, b] = panesOf(tab)
    live(a)
    live(b)
    useApp.getState().setActivePane(tab, b)

    useApp.getState().toggleSplit(tab, 'v')

    expect(panesOf(tab)).toEqual([b])
    expect(useApp.getState().panes[tab].activePaneId).toBe(b)
    // The discarded pane takes its session and cwd with it.
    expect(useApp.getState().tabSession).toEqual({ [b]: `sess-${b}` })
    expect(useApp.getState().tabCwd).toEqual({ [b]: '/srv' })
  })

  it('2 panes, other direction: re-orients and keeps both', () => {
    const tab = openSplit(2, 'v')
    const before = panesOf(tab)
    useApp.getState().toggleSplit(tab, 'h')
    expect(panesOf(tab)).toEqual(before)
    expect(useApp.getState().panes[tab].direction).toBe('h')
  })

  it('3+ panes, same direction: does nothing rather than killing two shells', () => {
    const tab = openSplit(3, 'v')
    const before = panesOf(tab)
    for (const p of before) live(p)

    useApp.getState().toggleSplit(tab, 'v')

    expect(panesOf(tab)).toEqual(before)
    expect(Object.keys(useApp.getState().tabSession)).toHaveLength(3)
  })

  it('3+ panes, other direction: re-orients and keeps all of them', () => {
    const tab = openSplit(3, 'v')
    const before = panesOf(tab)
    useApp.getState().toggleSplit(tab, 'h')
    expect(panesOf(tab)).toEqual(before)
    expect(useApp.getState().panes[tab].direction).toBe('h')
  })

  it('at the cap, the other direction re-orients and the same one is inert', () => {
    const tab = openSplit(MAX_PANES, 'v')
    const before = panesOf(tab)
    useApp.getState().toggleSplit(tab, 'h')
    expect(panesOf(tab)).toEqual(before)
    expect(useApp.getState().panes[tab].direction).toBe('h')

    useApp.getState().toggleSplit(tab, 'h')
    expect(panesOf(tab)).toEqual(before)
  })

  it('is a no-op for a tab that does not exist', () => {
    const before = useApp.getState().panes
    useApp.getState().toggleSplit('tab-nope', 'v')
    expect(useApp.getState().panes).toBe(before)
  })
})

describe('the local terminal flag', () => {
  it('defaults to enabled, and must stay that way', () => {
    // Main keeps its own copy (main/services/localGate.ts) and reads *absence*
    // as enabled. Settings persist wholesale and merge saved-over-default, so a
    // `false` shipped as the default is written to disk and permanently
    // outranks any later change — which is why the two halves have to agree.
    expect(DEFAULT_SETTINGS.localTerminalEnabled).toBe(true)
  })
})
