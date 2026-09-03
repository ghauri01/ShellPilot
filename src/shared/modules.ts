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

export type ModuleId =
  | 'docker'
  | 'kubernetes'
  | 'cron'
  | 'logTail'
  | 'broadcast'
  | 'fleetSearch'
  | 'inventory'
  | 'patch'
  | 'access'

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
    id: 'inventory',
    label: 'Inventory',
    detail:
      'What every host is — distribution, architecture, CPU, virtualisation — and what it needs: pending updates, security updates where the distribution publishes them, and whether a reboot is owed. Read-only, and nothing is refreshed: package caches are read, never updated, and their age is reported alongside the counts.',
    // OFF for a fresh install too, not merely for upgrades.
    //
    // Enabling it means running the host's package manager on every host once
    // an hour — `apt-get -s upgrade`, `dnf -C check-update`, `zypper
    // list-updates`. Each is cheap, none mutates and none touches the network,
    // but "we now run your package manager on all of your servers" is a thing a
    // person should switch on rather than discover. `backfillModules` already
    // guarantees an upgrade never switches it on for an existing install;
    // `defaultEnabled: false` extends the same courtesy to a new one.
    defaultEnabled: false
  },
  {
    id: 'patch',
    label: 'Patch and update management',
    detail:
      'What every host needs — pending updates, security updates where the distribution publishes them, and whether a reboot is owed — and applying them in waves, with a health check between waves and a hard refusal to restart a host other servers connect through. It never patches on a schedule and never decides for you.',
    // OFF by default, and not merely for upgrades.
    //
    // This is the only module that can INSTALL SOFTWARE ON YOUR SERVERS. The
    // inventory beside it is read-only and still ships off, on the argument
    // that "we now run your package manager on all of your hosts" is a thing to
    // switch on rather than discover; that argument is strictly stronger here,
    // where the verb is `upgrade` rather than `-s upgrade` and one of the steps
    // can restart the machine.
    defaultEnabled: false
  },
  {
    id: 'access',
    label: 'Fleet keys and access',
    detail:
      'Which key opens which host and whose it is: every authorized_keys file across the estate, fingerprinted, with locked and expired accounts and administrative group membership alongside. A host whose files could not be read is shown as unreadable and excluded from every count — never as a host with no keys. Read-only.',
    // OFF by default, and this one's toggle gates the COLLECTION rather than
    // just the panel — see FleetSamplerDeps.accessEnabled.
    //
    // Every other module here hides a UI while its main-process handlers stay
    // registered, which is fine for something a person has to press. This is a
    // background probe that walks /etc/passwd on every host once an hour,
    // stats every home directory in it, and where passwordless sudo exists uses
    // `sudo -n cat` to read other accounts' authorized_keys — one line in that
    // host's sudo log per account per hour.
    //
    // Every one of those reads is a read a person could do by hand, none of
    // them mutates anything, and no private key is touched anywhere. It is
    // still not something to discover after the fact.
    defaultEnabled: false
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
      'List containers on a server, read their logs, and open a shell inside a running one. Uses the docker binary already on the host — a container shell is arbitrary code execution there.',
    defaultEnabled: false
  },
  {
    id: 'kubernetes',
    label: 'Kubernetes',
    detail:
      'List contexts, namespaces and pods and read pod logs, using the kubectl already on the host. Reading only: it never switches your context, never execs into a pod, and never applies or deletes anything.',
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
  'services/secrets',
  // The renderer's own copy, which is a different file with the same secrets in
  // it. `store/vault` is not matched by `services/vault`, and a renderer module
  // importing it can read `VaultEntry.password` straight out of renderer memory
  // without ever touching main. Verified against every module's import closure
  // before adding: none reaches it today, so this costs nothing now and closes
  // the path before something does.
  'store/vault'
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
