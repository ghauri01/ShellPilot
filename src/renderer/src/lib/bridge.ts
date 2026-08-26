// Guarded access to the preload bridge.
//
// `window.shellpilot?.x.onY(...)` guards a missing bridge but not a missing
// METHOD. The two halves normally ship together, so in a packaged build they
// cannot disagree — but under `electron-vite dev` the renderer hot-reloads
// while the running process still holds the preload bundle it booted with, so
// any newly added method is undefined for the rest of that session. Calling it
// throws inside a useEffect, the error boundary catches it, and one optional
// subscription takes down the entire window.
//
// Subscribing to an event is never load-bearing enough to justify that, so a
// method that is not there yet degrades to a no-op with one console warning.

let warned = false

function warnOnce(name: string): void {
  if (warned) return
  warned = true
  console.warn(
    `[shellpilot] preload bridge is missing "${name}". The renderer is newer than the preload ` +
      'script — restart the dev server (or the app) to rebuild it. Live updates for this feature ' +
      'are disabled until then.'
  )
}

/**
 * Attaches `cb` via a preload event-subscription function, if that function
 * exists. Returns the unsubscribe callback, or a no-op when it does not.
 */
export function bridgeOn<A extends unknown[]>(
  name: string,
  register: ((cb: (...args: A) => void) => () => void) | undefined,
  cb: (...args: A) => void
): () => void {
  if (typeof register !== 'function') {
    warnOnce(name)
    return () => {}
  }
  return register(cb)
}

/** True when the preload bridge actually exposes `method` on `namespace`. */
export function bridgeHas(namespace: Record<string, unknown> | undefined, method: string): boolean {
  return typeof namespace?.[method] === 'function'
}
