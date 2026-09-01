import { create } from 'zustand'
import { bridgeHas, bridgeOn } from '../lib/bridge'
import {
  channelOfVersion,
  DEFAULT_UPDATE_PREFS,
  isUpdatePending,
  type UpdatePrefs,
  type UpdaterCapabilities,
  type UpdaterStatus
} from '../../../shared/updater'

// One subscription to the updater, shared by everyone who shows update state.
//
// The Settings panel used to subscribe to `onStatus` itself. Adding the
// always-visible status-bar indicator would have made two independent
// subscribers of the same event, each holding its own copy of the status — and
// two copies drift as soon as one of them mounts late, misses an event, or
// re-mounts and re-reads a status that has since moved on. The status bar would
// then say an update is waiting while Settings says the app is up to date, with
// no way for the user to tell which one is lying. Everything reads from here
// instead, so there is only ever one answer.

// Survives restarts on purpose: a user who has decided to skip a version has
// decided it for good, not just until the next launch.
const DISMISSED_KEY = 'shellpilot.updater.dismissedVersion'

function readDismissed(): string | null {
  try {
    return localStorage.getItem(DISMISSED_KEY)
  } catch {
    /* private mode or a wiped profile: worst case the chip comes back once */
    return null
  }
}

function writeDismissed(version: string | null): void {
  try {
    if (version === null) localStorage.removeItem(DISMISSED_KEY)
    else localStorage.setItem(DISMISSED_KEY, version)
  } catch {
    /* see above — a lost dismissal is a visible chip, not a broken app */
  }
}

/** The version a pending status is about, or null when nothing is pending.
 *  A download can be in flight before the version is known, and there is
 *  nothing to dismiss until it is. */
export function pendingVersion(status: UpdaterStatus): string | null {
  if (status.state === 'available' || status.state === 'downloaded' || status.state === 'manual') {
    return status.version
  }
  if (status.state === 'downloading') return status.version ?? null
  return null
}

interface UpdaterState {
  status: UpdaterStatus
  prefs: UpdatePrefs
  // Null until the first load, and stays null when the preload bridge does not
  // offer it. Callers show nothing rather than guessing a version or a
  // platform rule they do not have.
  capabilities: UpdaterCapabilities | null
  dismissedVersion: string | null

  init: () => void
  check: () => void
  download: () => void
  install: () => void
  setPrefs: (patch: Partial<UpdatePrefs>) => void
  /** Silence the indicator for the version now on offer, without turning
   *  updates off. Any other version supersedes it. */
  dismiss: () => void
  /** Undo a dismissal, so Settings can hand the version back. */
  undismiss: () => void
  /** Whether the indicator should be drawing attention to itself. */
  shouldNotify: () => boolean
}

const noop = (): void => {}

// Module-level, not store state: `init` runs from a mount effect, and React
// mounts effects twice in StrictMode.
let started = false

export const useUpdater = create<UpdaterState>((set, get) => {
  // A dismissal is about one version, not about updates in general. The feed
  // only ever offers a version it considers better than the running one, so an
  // offer that is not the dismissed one is a fresh decision for the user to
  // make — including after a channel switch, where the offer can be lower.
  const applyStatus = (status: UpdaterStatus): void => {
    const dismissed = get().dismissedVersion
    const version = pendingVersion(status)
    if (dismissed !== null && version !== null && version !== dismissed) {
      writeDismissed(null)
      set({ status, dismissedVersion: null })
      return
    }
    set({ status })
  }

  // Enough of a UpdaterCapabilities to keep the version on screen when main
  // could not answer. `canAutoInstall` is false rather than guessed: every
  // install affordance in the UI is gated on it, and offering a restart that
  // silently cannot replace the app is the one failure worth ruling out here.
  // `platform` is null rather than a guess: it only feeds explanatory copy, and
  // the panel already has generic wording for the unknown case. Naming a
  // plausible-looking platform would put the wrong install instructions in
  // front of someone at the exact moment they need the right ones.
  const degradedCapabilities = async (): Promise<void> => {
    try {
      const version = await window.shellpilot?.getVersion()
      if (!version) return
      set({
        capabilities: {
          canAutoInstall: false,
          isPortable: false,
          platform: null,
          currentVersion: version,
          runningChannel: channelOfVersion(version)
        }
      })
    } catch {
      /* Nothing left to fall back to. The indicator renders nothing rather
         than an empty "v", which is the one case it is allowed to be absent. */
    }
  }

  return {
    status: { state: 'idle' },
    prefs: DEFAULT_UPDATE_PREFS,
    capabilities: null,
    dismissedVersion: readDismissed(),

    init: () => {
      if (started) return
      started = true

      const u = window.shellpilot?.updater
      if (bridgeHas(u, 'status')) void u?.status().then(applyStatus).catch(noop)
      if (bridgeHas(u, 'getPrefs')) void u?.getPrefs().then((prefs) => set({ prefs })).catch(noop)

      // The version is supposed to be on screen at all times, and every caller
      // reads it from `capabilities` — so a rejected capabilities() call is not
      // a missing platform rule, it is an empty status bar. Falling back to
      // app:version keeps the promise the indicator makes, and the fallback is
      // deliberately pessimistic about what this build can do: an update the
      // user is told about but cannot install is a worse outcome than an
      // install button that appears a moment late.
      if (bridgeHas(u, 'capabilities')) {
        void u
          ?.capabilities()
          .then((c) => set({ capabilities: c }))
          .catch(degradedCapabilities)
      } else {
        void degradedCapabilities()
      }

      // Never unsubscribed: the only caller is the status bar, which stays
      // mounted for the life of the window.
      bridgeOn('updater.onStatus', u?.onStatus, applyStatus)
    },

    check: () => {
      if (bridgeHas(window.shellpilot?.updater, 'check')) void window.shellpilot?.updater.check()
    },

    download: () => {
      if (bridgeHas(window.shellpilot?.updater, 'download')) void window.shellpilot?.updater.download()
    },

    install: () => {
      if (bridgeHas(window.shellpilot?.updater, 'install')) void window.shellpilot?.updater.install()
    },

    setPrefs: (patch) => {
      // Applied locally first so a switch moves under the finger, then replaced
      // by what main actually stored — main is the authority, and it may refuse
      // a preference this platform cannot honour.
      set({ prefs: { ...get().prefs, ...patch } })
      if (bridgeHas(window.shellpilot?.updater, 'setPrefs')) {
        void window.shellpilot?.updater.setPrefs(patch).then((prefs) => set({ prefs }))
      }
    },

    dismiss: () => {
      const version = pendingVersion(get().status)
      if (!version) return
      writeDismissed(version)
      set({ dismissedVersion: version })
    },

    undismiss: () => {
      writeDismissed(null)
      set({ dismissedVersion: null })
    },

    shouldNotify: () => {
      const { status, dismissedVersion } = get()
      if (!isUpdatePending(status)) return false
      const version = pendingVersion(status)
      // An update whose version is not known yet cannot be the dismissed one,
      // and staying quiet on the strength of two unknowns would hide a
      // download that is already running.
      return version === null || version !== dismissedVersion
    }
  }
})
