// The renderer test harness.
//
// Loaded by tests/setup/global.ts, and only when the test file has asked for a
// DOM with `// @vitest-environment jsdom`. It exists to remove the two reasons
// a React component in this app could not previously be rendered in a test:
//
//  1. `window.shellpilot`. The preload bridge (src/preload/index.ts) is the
//     renderer's entire outside world, and store/alerts.ts reads it at MODULE
//     scope to stamp the app version into outbound payloads. Before this file,
//     the only way to test anything that imported it was the manoeuvre at the
//     top of tests/diskAlerts.test.ts: assign `globalThis.window` by hand, then
//     `await import()` the module afterwards so the assignment happened first.
//     That worked, but it made every renderer test carry the ordering rule in
//     its head, and it could not be used with a static import at all. Here the
//     bridge is installed before the test module is imported, so a plain
//     `import { Thing } from '...'` is safe, and `stubBridge()` replaces it per
//     test.
//
//  2. Store bleed. Every zustand store in src/renderer/src/store is a module
//     singleton. A test that adds a server or raises an alert leaves it there
//     for whatever runs next, and the suite quietly becomes order-dependent —
//     the failure mode where a file passes alone and fails in CI. Every store
//     is snapshotted here at its pristine value and restored after each test.
//
// The glob is deliberate: a store added next month is reset without anyone
// remembering to come back here.

import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

/** Whatever slice of the preload bridge a test needs. Deliberately loose:
 *  ShellPilotApi is several hundred methods and a test that had to satisfy it
 *  would stub the whole app to assert on one button. */
export type BridgeStub = Record<string, unknown>

function install(stub: BridgeStub): void {
  ;(window as unknown as { shellpilot: BridgeStub }).shellpilot = stub
}

/**
 * Replace `window.shellpilot` for this test.
 *
 * Whole-object replacement rather than a merge: a stub that silently inherits
 * a namespace from a previous test is the same order-dependence the store
 * snapshots exist to prevent. Call it in `beforeEach` or at the top of a test;
 * it is undone automatically.
 */
export function stubBridge(stub: BridgeStub = {}): void {
  install(stub)
}

// Installed before anything below imports a store, so module-scope reads of the
// bridge see an object rather than `undefined`. It is EMPTY on purpose: every
// call site in the renderer is written to survive a missing method (see
// src/renderer/src/lib/bridge.ts), and a harness that handed out plausible
// defaults would let a component pass a test by talking to the harness.
install({})

// ---------------------------------------------------------------------------
// Store snapshots
// ---------------------------------------------------------------------------

interface ZustandStore {
  getState: () => Record<string, unknown>
  setState: (state: Record<string, unknown>, replace: true) => void
}

function isStore(value: unknown): value is ZustandStore {
  return (
    typeof value === 'function' &&
    typeof (value as Partial<ZustandStore>).getState === 'function' &&
    typeof (value as Partial<ZustandStore>).setState === 'function'
  )
}

const snapshots: { store: ZustandStore; state: Record<string, unknown> }[] = []
/** `resetXForTests()` helpers, e.g. store/alerts.ts's. Those own module-level
 *  maps a store snapshot cannot reach — a repeat window or a notification
 *  memory — and the store state alone is not the whole of what leaks. */
const resetters: (() => void)[] = []

const storeModules = import.meta.glob<Record<string, unknown>>('../../src/renderer/src/store/*.ts')
for (const load of Object.values(storeModules)) {
  const mod = await load()
  for (const [name, exported] of Object.entries(mod)) {
    if (isStore(exported)) snapshots.push({ store: exported, state: exported.getState() })
    else if (typeof exported === 'function' && /^reset[A-Za-z]*ForTests$/.test(name)) {
      resetters.push(exported as () => void)
    }
  }
}

afterEach(() => {
  // Unmount first. A component still mounted while the stores below are
  // restored re-renders against state it did not ask for, and any effect it
  // owns fires during teardown instead of during the test.
  cleanup()
  for (const reset of resetters) reset()
  for (const { store, state } of snapshots) store.setState({ ...state }, true)
  install({})
  try {
    localStorage.clear()
  } catch {
    /* jsdom always has one; a future environment might not, and a lost
       dismissal is not worth failing a teardown over. */
  }
})
