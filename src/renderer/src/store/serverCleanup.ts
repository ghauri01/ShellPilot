// Per-server state that lives outside the server list, and has to go when the
// server does.
//
// A registry rather than direct calls, because the obvious version is a cycle:
// `alerts.ts` imports `app.ts` for settings, so `app.ts` importing `alerts.ts`
// back would make module initialisation order load-bearing. Here the owner of
// each piece of state registers its own cleanup and `deleteServer` calls one
// function that knows about none of them.
//
// This exists because three cleanup functions were written — `clearServer`,
// `clearUnitAlerts`, `useFleet.forget` — each with a docstring describing
// exactly what it prevented, and none of them was ever called. A deleted server
// kept counting in the status bar under a name that no longer existed, kept its
// last metrics in the fleet totals, and kept its failed-unit set, so deleting
// and re-adding a server suppressed the next genuine failure as "not fresh".

type Cleanup = (serverId: string) => void

const registered: Cleanup[] = []

export function onServerForgotten(fn: Cleanup): void {
  registered.push(fn)
}

export function forgetServer(serverId: string): void {
  for (const fn of registered) {
    try {
      fn(serverId)
    } catch {
      // One handler failing must not strand the others, or deleting a server
      // half-cleans and leaves exactly the stale state this exists to avoid.
    }
  }
}
