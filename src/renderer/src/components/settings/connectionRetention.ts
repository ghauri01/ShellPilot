// Why "Keep authenticated connection" stops meaning anything while background
// checking is on.
//
// The pool arms a connection's idle timer only when its reference count reaches
// zero (see release() in main/services/ssh.ts). The metrics layer acquires one
// connection per server and holds it until that server stops being watched, so
// a server being sampled never reaches zero and its idle timer is never armed.
// Every interval offered for background checking is shorter than every non-zero
// retention choice anyway, so even releasing after each pass would not change
// it: the next pass re-acquires before the timer could fire.
//
// That is defensible as behaviour — reconnecting to fifteen hosts through a
// bastion every couple of minutes is worse — and indefensible as a silence.
// The retention setting's stated purpose is how often a two-factor code is
// requested, so turning background checking on quietly extends an authenticated
// session to the lifetime of the app. A user who chose "Immediately" chose it
// for a reason.
//
// This is a pure function so the condition can be tested without a DOM.

/** Human form of a background-checking interval. */
export function intervalLabel(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)} seconds`
  const mins = Math.round(ms / 60_000)
  return mins === 1 ? 'minute' : `${mins} minutes`
}

/**
 * The sentence to show under the retention choices, or null when the setting
 * means what it says.
 *
 * Null rather than an empty string: an empty description still renders a row of
 * blank space, and "nothing to say" should look like nothing.
 */
export function retentionOverrideNotice(
  fleetSamplingEnabled: boolean,
  intervalMs: number
): string | null {
  if (!fleetSamplingEnabled) return null
  const every = intervalLabel(intervalMs)
  const cadence = every.startsWith('minute') ? 'every minute' : `every ${every}`
  return (
    `Background checking is on, so every server in this workspace is contacted ${cadence}. ` +
    'Their connection never sits idle long enough for this to expire, so it does not apply to ' +
    'them at any setting — including Immediately. On a server with two-factor authentication, no ' +
    'new code is requested while ShellPilot is running.'
  )
}
