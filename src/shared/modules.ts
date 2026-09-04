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
  | 'posture'
  | 'capacity'
  | 'rules'
  | 'changeLog'
  | 'drift'
  | 'processes'

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
      'Search systemd units, listening ports and servers across the workspace, from data the monitor already collects.',
    defaultEnabled: true
  },
  {
    id: 'inventory',
    label: 'Inventory',
    detail:
      'What every server is — distribution, architecture, CPU, virtualisation — and what it needs: pending updates, security updates where the distribution publishes them, and whether a reboot is owed. Read-only, and nothing is refreshed: package caches are read, never updated, and their age is reported alongside the counts.',
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
      'What every server needs — pending updates, security updates where the distribution publishes them, and whether a reboot is owed — and applying them in waves, with a health check between waves and a hard refusal to restart a server other servers connect through. It never patches on a schedule and never decides for you.',
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
      'Which key opens which server and whose it is: every authorized_keys file across the estate, fingerprinted, with locked and expired accounts and administrative group membership alongside. A server whose files could not be read is shown as unreadable and excluded from every count — never as a server with no keys. Read-only.',
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
    id: 'capacity',
    label: 'Capacity trends',
    detail:
      'How full a server is getting and when it runs out — "this disk fills in eleven days" — drawn from the samples the monitor already writes. It stores nothing of its own, schedules nothing and evaluates nothing in the background: every line is derived on demand from history that exists whether or not this is on. A forecast is never stated without the window it was drawn from, and a gap where a server was unreachable is left as a hole in the line rather than drawn across.',
    // OFF for a fresh install too, and this one is the cheapest module in the
    // list — it reads the local history store and opens no connection at all.
    //
    // Off anyway, for the reason `backfillModules` exists: an upgrade is not
    // consent, and a fresh install that arrived with nine tabs already open
    // would be the bloat this registry was built to avoid. Nothing here argues
    // that a module has to be dangerous to be optional.
    defaultEnabled: false
  },
  {
    id: 'changeLog',
    label: 'Change log',
    detail:
      '"What did I change on Tuesday" — one timeline over four records that already exist: shells run on this machine, what you confirmed before a job or a broadcast ran, what an agent did through the MCP bridge, and the alerts, jobs and store events the durable history keeps. Metadata only: commands and targets, never output. It reads; it stores nothing of its own and writes nothing.',
    // OFF by default, and this one's toggle gates the READ rather than the tab
    // — see the `changelog:read` handler in main/index.ts, which returns a page
    // saying "switched off" without opening a file.
    //
    // Gated because recording a person's work is a different consent question
    // from recording an agent's, which is the roadmap's own words for item 14.
    // The four records are written whether or not this is on, each for its own
    // reasons and each relied on by something else; what a person consents to
    // here is having them ASSEMBLED into one account of their week. That
    // assembled thing is more useful than any of its parts, which is exactly
    // why it is also the part to ask about.
    defaultEnabled: false
  },
  {
    id: 'rules',
    label: 'Rules',
    detail:
      'When an alert fires, run a job or post to the webhook \u2014 with a ceiling on how often it may act. A rule runs the job it was confirmed with, on the servers it was confirmed for, and refuses if either has changed. It is not a workflow language: one trigger, one filter, one action, one rate limit.',
    // OFF by default, and this is the module the default matters most for.
    //
    // Every other module here is something a person presses. This one acts on
    // its own, on hosts, while nobody is watching. `backfillModules` already
    // guarantees an upgrade never switches a module on for an existing install;
    // `defaultEnabled: false` extends that to a new one, so no install has ever
    // had an unattended execution path appear without somebody choosing it.
    //
    // What the toggle gates is the PANEL and the sweep, not the rules
    // themselves \u2014 a rule that exists stays on disk with its approval record
    // intact, so switching the module off and on again does not silently
    // re-arm anything. Disarming is per rule, on the rule.
    defaultEnabled: false
  },
  {
    id: 'drift',
    label: 'Configuration drift',
    detail:
      'Compare a watched configuration file across the estate and say where it diverges \u2014 "all twelve web servers have this nginx.conf, three do not". Every file is compared under normalisation rules that are named on screen, so two files that differ and are called the same say which rule ate the difference. A server that could not be read is never reported as a server that matches. Read-only: it never writes a file back to bring a server into line.',
    // OFF by default, and this one's toggle gates the COLLECTION rather than
    // just the panel \u2014 see FleetSamplerDeps.driftEnabled.
    //
    // Not for what the probe DOES on the host: it reads seven world-readable
    // files with no sudo anywhere, which is less than the inventory probe does
    // and far less than the access one. It is gated for what it PRODUCES, which
    // is the posture module's argument rather than the access module's.
    //
    // A table of which hosts differ from a known-good configuration is a table
    // of which hosts are behind. "These three still have PasswordAuthentication
    // where the other twelve do not" is a target list, kept fresh, across the
    // whole estate. That is worth having \u2014 it is why the item exists \u2014 and it
    // is not worth having without somebody deciding to have it.
    defaultEnabled: false
  },
  {
    id: 'posture',
    label: 'Security posture',
    detail:
      'What every server already knows about its own exposure: which firewall is active and the shape of its rules, whether SELinux or AppArmor is enforcing, how sshd compares with a hardening baseline, and how many logins have failed. Read-only, and emphatically not a vulnerability scanner — the pending security update count comes from the Inventory probe, which asks the server\'s own package manager, rather than from a CVE feed. A check that could not run is shown as unread, never as passed.',
    // OFF by default, and this one's toggle gates the COLLECTION rather than
    // just the panel — see FleetSamplerDeps.postureEnabled.
    //
    // The access module beside it is gated for what its probe DOES on the host.
    // This one is gated for what it PRODUCES. Every individual read here is one
    // an operator could do by hand and none of them changes anything; the
    // assembled result is a fleet-wide table of which host has no firewall,
    // which still takes passwords over ssh, and which has SELinux switched off
    // — a map of how to attack the estate, kept fresh in one process's memory
    // and written into the durable store.
    //
    // That is worth having, which is why it exists. It is not worth having
    // without somebody deciding to have it.
    defaultEnabled: false
  },
  {
    id: 'broadcast',
    label: 'Run a command on many servers',
    detail:
      'Run one command across selected servers, with confirmation that scales to how many servers and how dangerous the command is.',
    defaultEnabled: false
  },
  {
    id: 'logTail',
    label: 'Live log tailing',
    detail: 'Follow a systemd unit or a log file on several servers at once, interleaved by server.',
    defaultEnabled: true
  },
  {
    id: 'cron',
    label: 'Scheduled jobs',
    detail: 'Read crontabs, /etc/cron.d and systemd timers across the estate. Read-only.',
    defaultEnabled: true
  },
  {
    id: 'processes',
    label: 'Local processes',
    detail:
      'Run, watch, restart and read the logs of a long-lived process on THIS machine \u2014 a dev server, a worker, a script that should outlive its terminal. Restart policies, exponential backoff, crash-loop detection and a bounded log ring, from the supervisor that already keeps VPN engines alive. Nothing runs on a remote server, nothing starts by itself, and a value that looks like a secret has to come from the vault rather than the process list.',
    // OFF by default, and this is the module whose default matters most in the
    // whole registry.
    //
    // Every other module here acts on a REMOTE system through a credential
    // that a person could rotate afterwards, or reads something. This one runs
    // a program ON THE MACHINE THE VAULT IS ON, from a command line held in a
    // file, and keeps it running.
    //
    // What the toggle gates is the panel, not the definitions: a stored
    // process stays on disk with the module off, and nothing about it executes
    // by existing \u2014 there is no auto-start and there is not going to be one
    // (see the refusal at the top of src/shared/processes.ts). So turning this
    // off does not silently disarm something the user thinks is running, and
    // turning it back on does not silently arm anything either. The only thing
    // that starts a process is a person pressing Start.
    defaultEnabled: false
  },
  {
    id: 'docker',
    label: 'Docker',
    detail:
      'List containers on a server, read their logs, and open a shell inside a running one. Uses the docker binary already on the server — a container shell is arbitrary code execution there.',
    defaultEnabled: false
  },
  {
    id: 'kubernetes',
    label: 'Kubernetes',
    detail:
      'List contexts, namespaces and pods and read pod logs, using the kubectl already on the server. Reading only: it never switches your context, never execs into a pod, and never applies or deletes anything.',
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
