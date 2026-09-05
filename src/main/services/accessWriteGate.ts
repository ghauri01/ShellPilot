// The main-side gate on the access WRITE half — adding and revoking keys.
//
// Modelled on localGate.ts, and the default is INVERTED. Read that difference
// before copying either file.
//
// `localTerminalEnabled` treats an ABSENT key as ON, because settings persist
// wholesale and a `false` that ever shipped as a default would be written into
// every install and permanently outrank a later change. That reasoning is about
// a convenience feature whose safe state is "available".
//
// This one is a safety gate. Its safe state is OFF, and absence must read as
// OFF: a settings file that predates this key, a half-written blob, a renderer
// that never sent one — every path where we do not positively know the operator
// turned this on has to end with the write refused. The cost of the localGate
// trap in the other direction (a `false` sticking) is a toggle somebody has to
// flip again. The cost here would be a key revocation running on a build where
// nobody consented to it.
//
// WHY IT LIVES IN MAIN. The renderer has a toggle, but a renderer-side flag
// constrains only the honest UI. The threat is a compromised renderer calling
// the access IPC directly, which never goes near the toggle, so the flag is
// mirrored here and both `access:plan` and `access:run` consult this copy.

let enabled = false

/**
 * Read the flag out of the renderer's data blob, which main already receives on
 * every `data:save`.
 *
 * `=== true` rather than `!== false`: only the exact boolean turns this on.
 * Absent, null, a string, a truthy number — all of them mean off, because none
 * of them is somebody having made the decision.
 */
export function syncAccessWriteEnabled(data: unknown): void {
  const settings = (data as { settings?: { accessWriteEnabled?: unknown } } | null)?.settings
  enabled = settings?.accessWriteEnabled === true
}

export function isAccessWriteEnabled(): boolean {
  return enabled
}

/** Test seam. Not exported to the renderer and not reachable over IPC. */
export function setAccessWriteEnabledForTests(value: boolean): void {
  enabled = value
}
