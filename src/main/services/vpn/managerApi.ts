import type { VpnDependent, VpnResult, VpnStartResult, VpnStatus } from '../../../shared/vpn'

// The narrow slice of the VPN manager that the MCP bridge needs, and nothing
// else.
//
// `manager.ts` owns profiles, drivers, the supervisor, the vault and the
// renderer's IPC surface. `mcpServer.ts` needs four things out of all that:
// whether a profile is up, what would break if it went down, and the two verbs
// that change it. Importing the manager directly would drag the whole engine
// graph — and its Electron/child-process dependencies — into every test that
// merely lists MCP tools, and it would couple two files that are being written
// at the same time.
//
// So the dependency is inverted: this file declares the contract, the bridge
// imports only this, and the manager registers an implementation at startup.
//
// FOR THE MANAGER AUTHOR
// ----------------------
// Call `registerVpnManager({ ... })` once, from `manager.ts`'s own
// initialisation (the same place `reapOrphans()` runs), before the MCP server
// starts. Until you do, every accessor below throws: a bridge that silently
// reported "no VPNs are running" because the manager had not booted yet would
// be lying about the state of the user's network, and the read-only tool checks
// `isVpnManagerReady()` rather than guess.
//
// Contract notes the implementation must honour:
//
//   * `statusOf` is SYNCHRONOUS and must not throw. It returns the live status
//     the manager already holds, or null for a profile that has not run in this
//     app run — which the bridge reads as `stopped`.
//   * `dependentsOf` is SYNCHRONOUS and must not throw. It returns the same
//     list `vpn:dependents` returns. The bridge only looks at `live`, because
//     that is what makes a stop destructive rather than merely inconvenient.
//   * `startVpn`/`stopVpn` take a profile id, not a spec: the bridge never sees
//     a VpnSpec, so it cannot change where a profile points even by accident.
//     They must resolve errors into `{ ok: false, error }` rather than reject —
//     the bridge surfaces `error` to the agent verbatim, so it has to be a
//     sentence a user would recognise, and it must never contain key material.
//   * `startVpn` must still enforce every engine-side gate of its own
//     (`acknowledgedExposure`, elevation, vault unlock). Nothing here replaces
//     them; the policy check in the bridge sits on top of them, not instead.
export interface VpnManagerApi {
  statusOf(profileId: string): VpnStatus | null
  dependentsOf(profileId: string): VpnDependent[]
  startVpn(profileId: string): Promise<VpnStartResult>
  stopVpn(profileId: string): Promise<VpnResult>
}

const NOT_INITIALISED = 'VPN manager not initialised'

// Deliberately throws rather than returning an empty/false answer. "Nothing is
// running" and "nobody has told me what is running" are different facts, and
// only one of them is safe to act on.
const stub: VpnManagerApi = {
  statusOf() {
    throw new Error(NOT_INITIALISED)
  },
  dependentsOf() {
    throw new Error(NOT_INITIALISED)
  },
  startVpn() {
    throw new Error(NOT_INITIALISED)
  },
  stopVpn() {
    throw new Error(NOT_INITIALISED)
  }
}

let impl: VpnManagerApi = stub

export function registerVpnManager(manager: VpnManagerApi): void {
  impl = manager
}

// Lets a caller distinguish "no VPN is up" from "the manager has not booted",
// so a read-only tool can say the second one instead of asserting the first.
export function isVpnManagerReady(): boolean {
  return impl !== stub
}

export function vpnStatusOf(profileId: string): VpnStatus | null {
  return impl.statusOf(profileId)
}

export function vpnDependentsOf(profileId: string): VpnDependent[] {
  return impl.dependentsOf(profileId)
}

export function startVpn(profileId: string): Promise<VpnStartResult> {
  return impl.startVpn(profileId)
}

export function stopVpn(profileId: string): Promise<VpnResult> {
  return impl.stopVpn(profileId)
}

// Test-only: drop back to the throwing stub so one test's fake manager cannot
// leak into the next.
export function resetVpnManagerForTests(): void {
  impl = stub
}
