// Optional first-party modules — plugin system, part (a).
//
// Features that ship with the app but are off until enabled, and whose weight
// is not paid until they are. This is what "we don't want to ship bloatware"
// actually asks for, and it introduces no new trust boundary: the code is still
// ours, still reviewed, still in this repo.
//
// It is emphatically NOT part (b), a third-party extension API. The two share a
// registry and almost nothing else, and letting (a) drift into (b) by accident
// is the failure this file is written to prevent. ShellPilot's whole thesis is
// that credentials never leave it; code we did not write, running in-process
// with access to `credentialResolver`, is a vault with no lock. (b) needs a real
// sandbox and a capability-scoped API. It is a product, not a refactor.
//
// The shape is borrowed from AI_CAPABILITIES on purpose, including the part
// that matters most: absent reads as OFF. A module added in a later version
// does not silently switch itself on for an existing install — see
// `backfillModules`, which mirrors `backfillCapabilities`.

export type ModuleId = 'docker' | 'cron' | 'logTail' | 'broadcast' | 'fleetSearch'

export interface ModuleDef {
  id: ModuleId
  label: string
  /** What enabling it actually gives you. Shown in Settings. */
  detail: string
  /**
   * On for a brand new install. Existing installs are never switched on by an
   * upgrade regardless — see backfillModules.
   */
  defaultEnabled: boolean
  /**
   * Heavy modules must fetch their dependency on enable rather than bundling
   * it for everyone. Nothing here does yet; the flag exists so the first one
   * that does cannot be added without someone deciding how it is verified.
   * See resources/bin/manifest.json and resolveBundled() — extend that, do not
   * invent something beside it.
   */
  fetchesOnEnable?: boolean
}

export const MODULES: ModuleDef[] = [
  {
    id: 'fleetSearch',
    label: 'Fleet-wide search',
    detail:
      'Search systemd units, listening ports and hosts across the workspace, from data the monitor already collects.',
    defaultEnabled: true
  },
  {
    id: 'broadcast',
    label: 'Run a command on many servers',
    detail:
      'Run one command across selected servers, with confirmation that scales to how many hosts and how dangerous the command is.',
    defaultEnabled: false
  },
  {
    id: 'logTail',
    label: 'Live log tailing',
    detail: 'Follow a systemd unit or a log file on several hosts at once, interleaved by host.',
    defaultEnabled: true
  },
  {
    id: 'cron',
    label: 'Scheduled jobs',
    detail: 'Read crontabs, /etc/cron.d and systemd timers across the estate. Read-only.',
    defaultEnabled: true
  },
  {
    id: 'docker',
    label: 'Docker',
    detail:
      'List containers on a server, read their logs and open a shell inside one. Uses the docker binary already on the host.',
    defaultEnabled: false
  }
]

export type ModuleState = Partial<Record<ModuleId, boolean>>

/**
 * Whether a module is on.
 *
 * Absent is OFF, never on. The alternative — treating an unset module as
 * enabled — means every upgrade silently turns on whatever was added, which is
 * the opposite of what an optional-module system is for.
 */
export function moduleEnabled(state: ModuleState | undefined, id: ModuleId): boolean {
  return state?.[id] === true
}

/**
 * Fill in modules a stored state has never seen.
 *
 * Mirrors `backfillCapabilities`: a value already present is never overwritten,
 * and a module the user has explicitly turned off stays off across upgrades.
 *
 * `isFreshInstall` is the whole subtlety. A brand new install gets the
 * defaults, so the app is useful out of the box. An EXISTING install gets new
 * modules off, because the user has already decided what their app looks like
 * and an upgrade is not consent.
 */
export function backfillModules(stored: ModuleState | undefined, isFreshInstall: boolean): ModuleState {
  const next: ModuleState = { ...(stored ?? {}) }
  for (const m of MODULES) {
    if (next[m.id] === undefined) next[m.id] = isFreshInstall ? m.defaultEnabled : false
  }
  return next
}

/** The modules a fresh install starts with. */
export function defaultModuleState(): ModuleState {
  return backfillModules(undefined, true)
}

// ---------------------------------------------------------------------------
// The rule that must hold whatever else gets built.
//
// A module may not read the vault, resolve credentials, register an MCP tool
// without a policy entry, or reach the local terminal. Those four are what the
// security model is made of. This list is the vocabulary half of the guard;
// tests/moduleBoundaries.test.ts walks the real import closure, the same way
// tests/localTerminalNotExposed.test.ts does, because a convention nobody
// enforces is not a boundary.
// ---------------------------------------------------------------------------

export const MODULE_FORBIDDEN_IMPORTS = [
  'services/vault',
  'services/credentialResolver',
  'services/localPty',
  'services/secrets'
] as const

/**
 * The same four things, named the way the RENDERER reaches them.
 *
 * Every path above lives under src/main. Three of the five modules are renderer
 * components, and a renderer file does not import the vault — it calls
 * `window.shellpilot.vault.list()`, which returns every entry with its password
 * in it, from a file whose import closure is spotless. An import-closure guard
 * cannot see a global, so the closure walk alone was checking the modules least
 * able to violate it and saying nothing about the ones most able to.
 *
 * These are `window.shellpilot` namespaces (src/preload/index.ts): `vault` is
 * the vault, `secrets` is the OS keychain, `local` is a shell on the user's own
 * machine. A module needing any of them is not a module — it is part (b), and
 * needs the sandbox and the capability-scoped API that part (b) means.
 */
export const MODULE_FORBIDDEN_BRIDGE = ['vault', 'secrets', 'local'] as const
