// Which tunnel engines ShellPilot actually ships, and where.
//
// This is one fact that two processes have to agree on, and they cannot import
// each other's code to get it. The main process asks it to decide whether to
// look for a bundled binary at all (`binaries.ts`); the renderer asks it to
// decide whether offering "Install OpenVPN" makes any sense. Answering it
// separately in each — which is what a bare `platform === 'win32'` check in
// both places amounts to — means the next change to the list desyncs the UI
// from the resolver, silently, with the UI telling someone to install software
// that is already on their disk.
//
// It lives in `shared/` rather than in `binaries.ts` for a mechanical reason:
// `binaries.ts` imports `electron`, so the renderer cannot load it. Nothing
// here imports anything, deliberately — that is the property that makes it
// usable from both sides.

/**
 * Engines shipped on some platforms but not all, keyed by binary base name.
 * Anything absent from this map is shipped everywhere, which is true of
 * `shellpilot-netd` and `frpc`.
 */
const BUNDLED_PLATFORMS: Record<string, readonly NodeJS.Platform[]> = {
  // OpenVPN needs a tun adapter driver on Windows and cannot produce one
  // itself: `openvpn.exe` opens an adapter that already exists
  // (`at_least_one_tap_win` in upstream's tun.c) and never calls
  // `WintunCreateAdapter`, so bundling the DLL does not help it. A bundled
  // `openvpn.exe` would abort on a clean machine, so Windows drives a system
  // install, whose installer brings both the driver and the Interactive
  // Service. The obstacle is a driver, not the GPL — see
  // THIRD-PARTY-NOTICES.md, which explains why the licence permits bundling.
  openvpn: ['darwin', 'linux']
}

/** Whether ShellPilot ships `name` on `platform`. */
export function isEngineBundledOn(name: string, platform: NodeJS.Platform): boolean {
  const base = name.endsWith('.exe') ? name.slice(0, -4) : name
  const platforms = BUNDLED_PLATFORMS[base]
  return !platforms || platforms.includes(platform)
}

/**
 * Whether finding this engine is the user's job rather than ours — the
 * question the UI is really asking before it offers a download link.
 *
 * `null` means the platform is not known yet, because the renderer learns it
 * over an IPC round trip. The answer then is "not the user's", and that
 * asymmetry is deliberate: withholding a button for one frame is recoverable,
 * while telling someone to go and install software they already have is not.
 */
export function userSuppliesEngine(name: string, platform: NodeJS.Platform | null): boolean {
  return platform !== null && !isEngineBundledOn(name, platform)
}
