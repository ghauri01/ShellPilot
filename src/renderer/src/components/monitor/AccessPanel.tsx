import { useCallback, useEffect, useMemo, useState } from 'react'
import { KeyRound, RefreshCw, ShieldAlert } from 'lucide-react'
import { bridgeHas } from '../../lib/bridge'
import { clsx } from '../../lib/format'
import {
  ACCESS_STATUS_HELP,
  KEY_PROBLEM_HELP,
  accessSource,
  summariseAccess,
  type AccessAccount,
  type AccessChangePreview,
  type AccessCommitOutcome,
  type AccessRunResult,
  type AccessStatus,
  type HostAccess
} from '../../../../shared/access'
import type { Server } from '../../types'

// Fleet keys and access — roadmap item 23, renderer half.
//
// The question this exists to answer is "which of my hosts still trusts the
// laptop I sold", and the whole design follows from the fact that the answer
// has THREE parts, not two: the hosts that trust it, the hosts that do not, and
// the hosts nobody could check. The third list is the one every other tool
// leaves out, and leaving it out is what turns a security review into a
// reassuring fiction.
//
// So there is no cell in this panel that renders an unread host as a zero, an
// empty list or a dash, and the by-key view carries its "could not check" count
// in the same row as its "found on" count rather than in a footnote.
//
// It reads through the preload bridge directly rather than through the fleet
// store, and pulls rather than subscribes: `fleet.access()` is a read of what
// the background sweep already holds and never triggers a probe. There is
// exactly one thing deciding how often every home directory on every host gets
// stat'ed, and it is the sampler.

/** What one server's collection looks like from here, including the two states
 *  that are not a collection: never run, and failed. */
interface Entry {
  access?: HostAccess
  at?: number
  error?: string
  errorAt?: number
}

/**
 * One fingerprint, and everywhere it is — plus everywhere that could not be
 * checked, which is the same size of fact.
 */
interface KeyRow {
  fingerprint: string
  /** The comments the estate attaches to this key, which is how a person
   *  recognises it. More than one means different hosts label it differently. */
  labels: string[]
  type: string
  bits: number | null
  /** serverName → the accounts on that host that trust it. */
  on: { server: string; users: string[] }[]
  /** True when every appearance of this key carries a restricting option. A key
   *  that is `command=`-restricted on four hosts and unrestricted on a fifth is
   *  a different situation from one restricted everywhere. */
  restrictedEverywhere: boolean
}

function statusChip(status: AccessStatus): React.JSX.Element | null {
  if (status === 'ok') return null
  return (
    <span
      className={clsx('inv-na', (status === 'denied' || status === 'unknown') && 'loud')}
      title={ACCESS_STATUS_HELP[status]}
    >
      {status === 'denied'
        ? 'not permitted'
        : status === 'absent'
          ? 'not on this host'
          : status === 'no-tool'
            ? 'no tool for it'
            : status === 'unsupported'
              ? 'cannot be answered'
              : status === 'partial'
                ? 'partly read'
                : 'unknown'}
    </span>
  )
}

/** One account's key count, or the reason there is not one. Never a zero for an
 *  account whose file was not read — that substitution is the whole failure
 *  this feature exists to avoid. */
function KeyCount({ account }: { account: AccessAccount }): React.JSX.Element {
  if (account.keys === null) return statusChip(account.keysStatus) ?? <span>unknown</span>
  const usable = account.keys.filter((k) => k.problem === null).length
  const unreadable = account.keys.length - usable
  return (
    <span>
      <span className="mono">{usable}</span>
      {unreadable > 0 && (
        <span
          className="chip warn"
          title={`${unreadable} line${unreadable === 1 ? '' : 's'} in this file could not be fingerprinted, so ${unreadable === 1 ? 'it is' : 'they are'} not in the count beside it and cannot be matched against other hosts.`}
        >
          +{unreadable} unreadable
        </span>
      )}
      {account.keysUsedSudo && (
        <span className="chip" title="Read as root after the unprivileged attempt was refused.">
          root
        </span>
      )}
    </span>
  )
}

/**
 * What one host's key change came to.
 *
 * THREE OUTCOMES AND NOT TWO, and the styling says so as loudly as the words.
 * "Reverted because a second session could not get in" is the host rejecting
 * the change and there is something to look at; "reverted because nothing
 * confirmed it in time" is the dead-man's switch doing exactly what it promised
 * and there is nothing wrong at all. Rendering both as one red row would teach
 * an operator that the safety net is a fault, and an operator who believes that
 * is an operator who will want it switched off.
 */
const OUTCOME_LABEL: Record<AccessCommitOutcome, string> = {
  committed: 'Committed',
  'reverted-verification-failed': 'Reverted — the host would not let a new session in',
  'reverted-unconfirmed': 'Reverted — nothing confirmed it in time'
}

function outcomeClass(outcome: AccessCommitOutcome): string {
  return outcome === 'committed' ? 'ok' : outcome === 'reverted-verification-failed' ? 'loud' : 'warn'
}

export function AccessPanel({
  servers,
  onOpen
}: {
  servers: Server[]
  onOpen?: (serverId: string) => void
}): React.JSX.Element {
  const [entries, setEntries] = useState<Record<string, Entry>>({})
  const [busy, setBusy] = useState(false)
  const [view, setView] = useState<'keys' | 'hosts'>('keys')
  // The revoke flow, and it is three states rather than one boolean: nothing
  // asked, a plan main has derived and the operator has not agreed to, and what
  // happened. A single "revoking" flag would have had to invent one of them.
  const [pending, setPending] = useState<{ fingerprint: string; preview: AccessChangePreview } | null>(null)
  const [result, setResult] = useState<AccessRunResult | null>(null)
  const [running, setRunning] = useState(false)
  const [problem, setProblem] = useState<string | null>(null)

  const load = useCallback(async (): Promise<void> => {
    if (!bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'access')) return
    const next: Record<string, Entry> = {}
    await Promise.all(
      servers.map(async (s) => {
        const r = await window.shellpilot?.fleet?.access(s.id)
        if (r) next[s.id] = { access: r.access, at: r.at, error: r.error, errorAt: r.errorAt }
      })
    )
    setEntries(next)
  }, [servers])

  useEffect(() => {
    void load()
  }, [load])

  const refresh = async (): Promise<void> => {
    setBusy(true)
    try {
      // A sweep first, so a server added since the last one is collected rather
      // than reported as never checked, then a read of what main now holds.
      if (bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'sampleNow')) {
        await window.shellpilot?.fleet?.sampleNow()
      }
      await load()
    } finally {
      setBusy(false)
    }
  }

  /** The accounts this key is on, as targets main can look up for itself. The
   *  renderer names the key and the servers; it does not decide anything. */
  const targetsFor = useCallback(
    (fingerprint: string): { serverId: string; serverName: string; user: string; cfg: unknown }[] => {
      const out: { serverId: string; serverName: string; user: string; cfg: unknown }[] = []
      for (const s of servers) {
        const access = entries[s.id]?.access
        if (!access) continue
        for (const a of access.accounts) {
          if ((a.keys ?? []).some((k) => k.fingerprint === fingerprint)) {
            out.push({ serverId: s.id, serverName: s.name, user: a.user, cfg: s })
          }
        }
      }
      return out
    },
    [servers, entries]
  )

  const planRevoke = async (fingerprint: string): Promise<void> => {
    setProblem(null)
    setResult(null)
    setRunning(true)
    try {
      const preview = await window.shellpilot?.fleet?.accessPlan({
        kind: 'revoke',
        fingerprint,
        targets: targetsFor(fingerprint)
      })
      if (preview) setPending({ fingerprint, preview })
    } catch (e) {
      setProblem(e instanceof Error ? e.message : String(e))
    } finally {
      setRunning(false)
    }
  }

  const runRevoke = async (): Promise<void> => {
    if (!pending) return
    setRunning(true)
    setProblem(null)
    try {
      const r = await window.shellpilot?.fleet?.accessRun({
        kind: 'revoke',
        fingerprint: pending.fingerprint,
        token: pending.preview.token,
        // The command text as it was SHOWN. Main re-derives and refuses if the
        // two differ, so what was agreed to is what runs or nothing runs.
        confirmedCommand: pending.preview.command,
        targets: targetsFor(pending.fingerprint)
      })
      setPending(null)
      if (r) setResult(r)
      // The estate has changed, whichever way each host went.
      await load()
    } catch (e) {
      setProblem(e instanceof Error ? e.message : String(e))
    } finally {
      setRunning(false)
    }
  }

  // Every host, sorted into the three buckets that matter. `incomplete` is not
  // a subset of `failed`: a host can answer perfectly and still have two home
  // directories this account cannot traverse, and that host's counts are a
  // lower bound exactly as a failed host's are.
  const hosts = useMemo(
    () =>
      servers.map((s) => {
        const e = entries[s.id]
        const summary = e?.access ? summariseAccess(e.access) : null
        return { server: s, entry: e, summary }
      }),
    [servers, entries]
  )

  const collected = hosts.filter((h) => h.entry?.access)
  const failed = hosts.filter((h) => !h.entry?.access && h.entry?.error)
  const never = hosts.filter((h) => !h.entry?.access && !h.entry?.error)
  const incomplete = collected.filter((h) => h.summary && !h.summary.certain)

  /**
   * The by-key view. One row per distinct fingerprint across everything that
   * WAS read — and the header above it says how many hosts were not, because a
   * key absent from this table has not been shown to be absent from the estate.
   */
  const keyRows = useMemo((): KeyRow[] => {
    const by = new Map<string, KeyRow>()
    for (const h of collected) {
      for (const a of h.entry!.access!.accounts) {
        for (const k of a.keys ?? []) {
          if (k.fingerprint === null) continue
          const row = by.get(k.fingerprint) ?? {
            fingerprint: k.fingerprint,
            labels: [],
            type: k.type ?? 'unknown',
            bits: k.bits,
            on: [],
            restrictedEverywhere: true
          }
          if (k.comment && !row.labels.includes(k.comment)) row.labels.push(k.comment)
          if (!k.restricted) row.restrictedEverywhere = false
          const existing = row.on.find((o) => o.server === h.server.name)
          if (existing) {
            if (!existing.users.includes(a.user)) existing.users.push(a.user)
          } else row.on.push({ server: h.server.name, users: [a.user] })
          by.set(k.fingerprint, row)
        }
      }
    }
    // Most widespread first: a key on eleven hosts is the one worth looking at.
    return [...by.values()].sort(
      (a, b) => b.on.length - a.on.length || a.fingerprint.localeCompare(b.fingerprint)
    )
  }, [collected])

  const unchecked = failed.length + never.length
  // The write half is gated by the module switch in main, which also decides
  // whether the bridge has these methods at all. A build or an install where it
  // is off shows no button rather than a button that fails.
  const canWrite = bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'accessPlan')

  return (
    <div className="bc-panel">
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <KeyRound size={14} className="faint" />
        <b className="grow">Keys and access</b>
        {collected.length > 0 && (
          <button className="btn ghost sm" onClick={() => setView(view === 'keys' ? 'hosts' : 'keys')}>
            {view === 'keys' ? 'By host' : 'By key'}
          </button>
        )}
        <button
          className="btn"
          disabled={busy || servers.length === 0}
          onClick={() => void refresh()}
          title="Sweeps the estate now and re-reads what has already been collected. Keys are re-read at most once an hour per host."
        >
          <RefreshCw size={13} className={clsx(busy && 'spin')} /> Check now
        </button>
      </div>

      {collected.length === 0 ? (
        <div className="s-desc">
          <b>No authorized_keys have been collected yet.</b> ShellPilot reads them about once an
          hour, on the same background sweep as host facts — so a server added in the last hour, or
          an estate where this module has just been switched on, will not have any yet. Press{' '}
          <b>Check now</b> to sweep immediately, and make sure background checking is on in
          Settings. Nothing is written to any host by this: the files are read, never edited, and no
          private key is touched.
          {failed.length > 0 && (
            <>
              {' '}
              <b>{failed.length}</b> host{failed.length === 1 ? '' : 's'} refused the probe — see
              below.
            </>
          )}
        </div>
      ) : (
        <>
          {/* The headline, and the reason the second half of the sentence is
              never optional. "37 keys across 12 hosts" on an estate where 3
              hosts could not be read is a count over 9 hosts wearing the label
              of a count over 12. */}
          <div className="row wrap muted" style={{ fontSize: 11, marginTop: 8, gap: 12 }}>
            <span>
              {keyRows.length} distinct key{keyRows.length === 1 ? '' : 's'} across{' '}
              {collected.length} host{collected.length === 1 ? '' : 's'}
            </span>
            {unchecked > 0 && (
              <span className="warn" data-testid="unchecked-hosts">
                {unchecked} host{unchecked === 1 ? '' : 's'} could not be checked and{' '}
                {unchecked === 1 ? 'is' : 'are'} not in that count
              </span>
            )}
            {incomplete.length > 0 && (
              <span className="warn" data-testid="incomplete-hosts">
                {incomplete.length} host{incomplete.length === 1 ? '' : 's'} answered only partly
              </span>
            )}
          </div>

          {/* The sentence that must exist before anyone concludes anything.
              Rendered whenever any host is unchecked or incomplete, and it says
              explicitly what may NOT be concluded — not merely that some data
              is missing. */}
          {(unchecked > 0 || incomplete.length > 0) && (
            <div className="s-desc warn" data-testid="not-an-answer">
              <ShieldAlert size={12} /> This is not a complete picture of the estate, so “this key
              is not on my fleet” cannot be concluded from it.{' '}
              {unchecked > 0 && (
                <>
                  {unchecked} host{unchecked === 1 ? ' was' : 's were'} not read at all
                  {incomplete.length > 0 ? ', and ' : '. '}
                </>
              )}
              {incomplete.length > 0 && (
                <>
                  {incomplete.length} host{incomplete.length === 1 ? '' : 's'} answered for some
                  accounts and not others.{' '}
                </>
              )}
              Every count above is a lower bound.
            </div>
          )}

          {problem !== null && (
            <div className="s-desc warn" data-testid="access-problem">
              <b>Nothing was changed.</b> {problem}
            </div>
          )}

          {pending !== null && (
            <div className="s-desc" data-testid="revoke-confirm">
              <b>
                Revoke {pending.fingerprint} from {pending.preview.hosts.length} account
                {pending.preview.hosts.length === 1 ? '' : 's'}?
              </b>{' '}
              This is staged, not applied. Each host takes a timestamped backup, replaces the file,
              and arms its OWN rollback before ShellPilot lets go — so if this app dies in the next
              instant, the host puts the previous file back by itself after{' '}
              {pending.preview.rollbackSeconds} seconds. Nothing becomes permanent until a second
              connection has authenticated against the changed file.
              {pending.preview.hosts.length > 0 && (
                <div className="mono" style={{ fontSize: 10, marginTop: 6 }}>
                  {pending.preview.hosts.map((h) => (
                    <div key={h.serverId}>
                      {h.serverName} · {h.user}
                    </div>
                  ))}
                </div>
              )}
              {(pending.preview.blocks.length > 0 || pending.preview.refusals.length > 0) && (
                <div style={{ marginTop: 8 }} data-testid="revoke-blocked">
                  <b>
                    {pending.preview.blocks.length + pending.preview.refusals.length} left out, and
                    not by choice:
                  </b>
                  <ul style={{ margin: '4px 0 0 16px' }}>
                    {pending.preview.blocks.map((b, i) => (
                      <li key={`b${i}`}>
                        <b>
                          {b.serverName} · {b.user}
                        </b>{' '}
                        — {b.reason}
                      </li>
                    ))}
                    {pending.preview.refusals.map((r, i) => (
                      <li key={`r${i}`}>
                        <b>
                          {r.serverName} · {r.user}
                        </b>{' '}
                        — {r.reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <div style={{ marginTop: 6 }}>
                <details>
                  <summary className="muted" style={{ fontSize: 11 }}>
                    What will run on each host
                  </summary>
                  {/* Shown, and sent back with the run: main derives it again
                      and refuses to touch a host if the two differ. */}
                  <pre className="mono" style={{ fontSize: 10, whiteSpace: 'pre-wrap' }}>
                    {pending.preview.command || 'nothing — every host was left out'}
                  </pre>
                </details>
              </div>
              <div className="row" style={{ gap: 8, marginTop: 8 }}>
                <button
                  className="btn danger"
                  data-testid="revoke-go"
                  disabled={running || pending.preview.hosts.length === 0}
                  onClick={() => void runRevoke()}
                >
                  Stage the revocation
                </button>
                <button className="btn ghost" disabled={running} onClick={() => setPending(null)}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {result !== null && (
            <div className="s-desc" data-testid="revoke-result">
              {result.reports.map((r) => (
                <div
                  key={`${r.serverId}:${r.token}`}
                  data-testid={`outcome-${r.serverId}`}
                  data-outcome={r.outcome}
                  style={{ marginBottom: 6 }}
                >
                  <span className={clsx('chip', outcomeClass(r.outcome))}>
                    {OUTCOME_LABEL[r.outcome]}
                  </span>{' '}
                  {r.detail}
                </div>
              ))}
              {result.notStaged.map((n) => (
                <div key={n.serverId} data-testid={`not-staged-${n.serverId}`} style={{ marginBottom: 6 }}>
                  <span className="chip loud">Not staged</span> Nothing was changed on {n.serverName}:{' '}
                  {n.detail}
                </div>
              ))}
              {result.reports.length === 0 && result.notStaged.length === 0 && (
                <span>Nothing ran: every host was left out.</span>
              )}
            </div>
          )}

          {view === 'keys' ? (
            <div className="inv-scroll">
              <table className="table inv-table">
                <thead>
                  <tr>
                    <th>Fingerprint</th>
                    <th>Labelled</th>
                    <th>Type</th>
                    <th className="num">Hosts</th>
                    <th>Where</th>
                    {canWrite && <th />}
                  </tr>
                </thead>
                <tbody>
                  {keyRows.map((k) => (
                    <tr key={k.fingerprint} data-fingerprint={k.fingerprint}>
                      <td className="mono" style={{ fontSize: 10 }}>
                        {k.fingerprint}
                      </td>
                      <td>
                        {k.labels.length === 0 ? (
                          <span
                            className="inv-na"
                            title="No comment on any line carrying this key. A key with no label is not an unused key — it is a key nobody wrote down the owner of."
                          >
                            no label
                          </span>
                        ) : (
                          // The most attacker-controlled string in this whole
                          // feature: it is free text in a file on a host that
                          // may already be compromised. It arrives stripped of
                          // control characters and bidi overrides and capped
                          // (see shared/access.ts), and it is rendered as text
                          // in a cell — never as a title, a link or markup.
                          k.labels.join(' · ')
                        )}
                      </td>
                      <td className="mono" style={{ fontSize: 10 }}>
                        {k.type}
                        {k.bits !== null && ` ${k.bits}`}
                        {k.restrictedEverywhere && (
                          <span
                            className="chip"
                            title="Every line carrying this key restricts it — a command=, from= or restrict option. It is not a general-purpose login on any host where it was found."
                          >
                            restricted
                          </span>
                        )}
                      </td>
                      <td className="num mono">{k.on.length}</td>
                      <td>
                        {k.on.map((o) => (
                          <span key={o.server} style={{ marginRight: 8 }}>
                            {onOpen ? (
                              <button
                                className="inv-host"
                                onClick={() => {
                                  const s = servers.find((x) => x.name === o.server)
                                  if (s) onOpen(s.id)
                                }}
                              >
                                {o.server}
                              </button>
                            ) : (
                              <span>{o.server}</span>
                            )}
                            <span className="faint mono" style={{ fontSize: 10 }}>
                              {' '}
                              {o.users.join(', ')}
                            </span>
                          </span>
                        ))}
                      </td>
                      {canWrite && (
                        <td>
                          <button
                            className="btn ghost sm"
                            data-testid={`revoke-${k.fingerprint}`}
                            disabled={running || pending !== null}
                            onClick={() => void planRevoke(k.fingerprint)}
                            title="Shows exactly what would run on which hosts. Nothing is written until you confirm it, and nothing becomes permanent until a second, independent session has proved the host still lets ShellPilot in."
                          >
                            Revoke…
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="inv-scroll">
              <table className="table inv-table">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Account</th>
                    <th className="num">Keys</th>
                    <th>Password</th>
                    <th>Admin groups</th>
                    <th>Last login</th>
                  </tr>
                </thead>
                <tbody>
                  {collected.flatMap((h) =>
                    h.entry!.access!.accounts.map((a) => (
                      <tr key={`${h.server.id}:${a.user}`} data-host={h.server.name} data-user={a.user}>
                        <td>{h.server.name}</td>
                        <td className="mono" style={{ fontSize: 11 }}>
                          {a.user}
                          {a.hasLegacyKeyFile && (
                            <span
                              className="chip warn"
                              title="This account has a .ssh/authorized_keys2 file. sshd still reads it and ShellPilot does not, so this account may trust keys that are not listed here."
                            >
                              authorized_keys2
                            </span>
                          )}
                        </td>
                        <td className="num">
                          <KeyCount account={a} />
                        </td>
                        <td>
                          {a.passwordLocked === null ? (
                            statusChip(a.accountStatus)
                          ) : a.passwordLocked ? (
                            // The trap this column exists to defuse. `passwd -l`
                            // defeats password authentication and has NO effect
                            // on public-key authentication, so "locked" next to
                            // a live key is not a safe combination — it is the
                            // exact combination an access review is looking for.
                            <span
                              className={clsx('chip', (a.keys?.length ?? 0) > 0 && 'warn')}
                              title={
                                (a.keys?.length ?? 0) > 0
                                  ? 'The password is locked and this account still trusts SSH keys. Locking a password does not affect key authentication — whoever holds one of these keys can still log in.'
                                  : 'The password is locked. This does not by itself prevent key authentication.'
                              }
                            >
                              locked
                            </span>
                          ) : (
                            <span className="faint">usable</span>
                          )}
                          {a.expired === true && (
                            <span className="chip warn" title={a.expiresText ?? undefined}>
                              expired
                            </span>
                          )}
                        </td>
                        <td>
                          {a.adminGroups === null ? (
                            statusChip('unknown')
                          ) : a.adminGroups.length === 0 ? (
                            <span className="faint">none</span>
                          ) : (
                            <span
                              className="mono"
                              style={{ fontSize: 10 }}
                              title="Membership of an administrative group, which is a proxy for sudo rights rather than a reading of sudoers."
                            >
                              {a.adminGroups.join(', ')}
                            </span>
                          )}
                        </td>
                        <td className="faint" style={{ fontSize: 10 }}>
                          {a.neverLoggedIn ? (
                            'never'
                          ) : a.lastLoginAt !== null ? (
                            new Date(a.lastLoginAt).toLocaleString()
                          ) : a.lastLoginText !== null ? (
                            // Kept as the host's own phrase when it could not be
                            // turned into an instant. "We cannot make a date out
                            // of this" is not "we do not know when they logged
                            // in", and showing the phrase is the better of the
                            // two answers.
                            <span title="The host reported this and ShellPilot could not read a date out of it.">
                              {a.lastLoginText}
                            </span>
                          ) : (
                            statusChip(accessSource(h.entry!.access!, 'last-login').status)
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* Why each partly-read host is partly read, in its own words. Kept
              below the tables rather than in a tooltip: it is the list of
              machines somebody has to go and check by hand. */}
          {incomplete.map((h) => (
            <div key={h.server.id} className="s-desc warn" data-testid={`incomplete-${h.server.name}`}>
              <b>{h.server.name}</b>: {h.summary!.uncertainty.join('; ')}.
            </div>
          ))}
        </>
      )}

      {failed.map((h) => (
        <div key={h.server.id} className="s-desc danger" data-testid={`failed-${h.server.name}`}>
          {h.server.name}: the access probe failed — {h.entry!.error}. This host is excluded from
          every count above; it is not a host with no keys.
        </div>
      ))}
      {collected.length > 0 && never.length > 0 && (
        <div className="s-desc" data-testid="never-collected">
          {never.length} host{never.length === 1 ? '' : 's'} ({never.map((h) => h.server.name).join(', ')}
          ) {never.length === 1 ? 'has' : 'have'} not been read yet. They are excluded from every
          count above.
        </div>
      )}

      {/* The vocabulary, stated once. Every problem word above links back to
          here rather than to a shrug. */}
      {collected.some((h) =>
        h.entry!.access!.accounts.some((a) => a.keys?.some((k) => k.problem !== null))
      ) && (
        <div className="s-desc" data-testid="problem-help">
          Some lines in files that WERE read could not be fingerprinted.{' '}
          {KEY_PROBLEM_HELP['unknown-type']}
        </div>
      )}
    </div>
  )
}
