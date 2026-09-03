import type { HostStatus, ServerRef } from '../../../../shared/hostHealth'
import type { Server } from '../../types'

// This module moved to src/shared/hostHealth.ts.
//
// Not because the renderer stopped needing it, but because the job engine's
// health gate (roadmap B4) has to answer "is this host healthy" in MAIN, before
// a stage is allowed to roll on to the next cohort — and shared/ is the only
// place both processes can read. A second implementation in main is exactly the
// disagreement `isDiskCritical` exists to prevent.
//
// Everything below is a re-export. FleetHealth.tsx, ServerMonitorCard.tsx, the
// alert store and tests/hostHealth.test.ts import from here unchanged.
export * from '../../../../shared/hostHealth'

/**
 * The drift guard for the one thing the move could silently break.
 *
 * shared/ may not import from the renderer, so `ServerRef.status` is a
 * hand-written mirror of `ServerStatus` rather than a `Pick<Server, …>`. A
 * mirror nobody checks is a copy that drifts: add a fifth status to the
 * renderer's union and the shared one still compiles, still accepts every
 * caller, and quietly means something narrower than the type it is standing in
 * for.
 *
 * So assert both directions. If the unions stop being identical — either way
 * round — this alias resolves to `never` and the constant below fails to
 * compile, on the line that says why, rather than at whatever call site
 * happens to notice first.
 */
export type ServerRefMatchesServer = [Server['status']] extends [HostStatus]
  ? [HostStatus] extends [Server['status']]
    ? [Pick<Server, 'id' | 'name' | 'status'>] extends [ServerRef]
      ? [ServerRef] extends [Pick<Server, 'id' | 'name' | 'status'>]
        ? true
        : never
      : never
    : never
  : never

/** See ServerRefMatchesServer. Its only job is to be type-checked. */
export const SERVER_REF_MATCHES_SERVER: ServerRefMatchesServer = true
