// Turns an access group's raw capability map into a sentence a person can read
// and check against what they meant to configure.
//
// This is deliberately derived from the live `capabilities` object rather than
// written per built-in group: a user who edits "Read Only" until it can write
// must get a summary that says so. A hard-coded blurb would keep claiming the
// group is read-only, which is worse than showing no summary at all.

import { AI_CAPABILITIES } from '../../../../shared/mcp'
import type { AccessGroup, AiCapability, FilePathRule, PermissionValue } from '../../../../shared/mcp'

interface Phrasing {
  /** Bare infinitive — "Can run commands", "Cannot run commands". */
  verb: string
  /** Gerund — "Asks before running commands". */
  gerund: string
}

// Short verb phrases, not the grid's noun labels: "Execute terminal commands,
// Read files" is a column header, "run commands and read files" is a sentence.
const PHRASING: Record<AiCapability, Phrasing> = {
  viewServer: { verb: 'see server details', gerund: 'showing server details' },
  terminal: { verb: 'run commands', gerund: 'running commands' },
  readFiles: { verb: 'read files', gerund: 'reading files' },
  writeFiles: { verb: 'write files', gerund: 'writing files' },
  sftpDownload: { verb: 'download files', gerund: 'downloading files' },
  sftpUpload: { verb: 'upload files', gerund: 'uploading files' },
  sshTunnel: { verb: 'open SSH tunnels', gerund: 'opening SSH tunnels' },
  databaseAccess: { verb: 'query databases', gerund: 'querying databases' },
  sudo: { verb: 'use sudo', gerund: 'using sudo' },
  serverMetrics: { verb: 'read server metrics', gerund: 'reading server metrics' },
  manageServers: { verb: 'add servers to the workspace', gerund: 'adding servers to the workspace' },
  vpnControl: { verb: 'control VPNs and reverse proxies', gerund: 'controlling VPNs and reverse proxies' }
}

// The three that do not merely act on a server the user already trusts: sudo is
// root, manageServers writes a new credential into ShellPilot itself, and
// vpnControl decides which network every later session travels over. They are
// listed first inside whichever clause they land in, so a summary can never
// bury "can use sudo" behind six mundane capabilities.
export const ELEVATED_CAPABILITIES: AiCapability[] = ['sudo', 'manageServers', 'vpnControl']

const DECLARATION_ORDER = AI_CAPABILITIES.map((c) => c.id)

export interface CapabilityDecision {
  id: AiCapability
  label: string
  value: PermissionValue
}

/**
 * Every capability with the value the policy engine would actually use.
 *
 * `evaluateCapability` reads `capabilities[id] ?? 'deny'` so that a group saved
 * before a capability existed is not silently granted it on upgrade. The
 * summary has to make the same substitution or it will describe an upgraded
 * install as permitting something the engine refuses.
 */
export function capabilityDecisions(group: AccessGroup): CapabilityDecision[] {
  return AI_CAPABILITIES.map(({ id, label }) => ({
    id,
    label,
    value: group.capabilities?.[id] ?? 'deny'
  }))
}

function sortForSentence(ids: AiCapability[]): AiCapability[] {
  const rank = (id: AiCapability): number =>
    (ELEVATED_CAPABILITIES.includes(id) ? 0 : 100) + DECLARATION_ORDER.indexOf(id)
  return [...ids].sort((a, b) => rank(a) - rank(b))
}

/** "a", "a and b", "a, b, and c" — Oxford comma, matching the app's copy. */
function join(items: string[], conjunction: 'and' | 'or'): string {
  if (items.length === 0) return ''
  if (items.length === 1) return items[0]
  if (items.length === 2) return `${items[0]} ${conjunction} ${items[1]}`
  return `${items.slice(0, -1).join(', ')}, ${conjunction} ${items[items.length - 1]}`
}

export interface AccessGroupSummary {
  /** The whole thing, ready to render or assert on. */
  sentence: string
  /** The same text split by decision, so the UI can style each clause. */
  clauses: string[]
  /** Elevated capabilities granted with no prompt — worth a visible warning. */
  elevated: AiCapability[]
  counts: Record<PermissionValue, number>
}

/**
 * A plain-English description of what an access group permits.
 *
 * Deliberately complete rather than abbreviated: there are only twelve
 * capabilities, and "and 3 more" in a security summary invites exactly the
 * distrust this screen is trying to remove.
 */
export function summariseAccessGroup(group: AccessGroup): AccessGroupSummary {
  const decisions = capabilityDecisions(group)
  const idsBy = (v: PermissionValue): AiCapability[] =>
    sortForSentence(decisions.filter((d) => d.value === v).map((d) => d.id))

  const allowed = idsBy('allow')
  const asked = idsBy('ask')
  const denied = idsBy('deny')
  const elevated = allowed.filter((id) => ELEVATED_CAPABILITIES.includes(id))
  const counts = { allow: allowed.length, ask: asked.length, deny: denied.length }

  const clauses: string[] = []

  if (denied.length === decisions.length) {
    // The state a brand-new install is in until a group is assigned, and the
    // one that makes an agent look broken rather than restricted.
    clauses.push('Allows nothing — every AI request against the server is refused.')
  } else if (allowed.length === decisions.length) {
    // Listing all twelve here reads as a wall of text at the exact moment the
    // reader most needs to notice one fact, so name the dangerous three.
    clauses.push(
      `Can do everything without asking — including ${join(
        ELEVATED_CAPABILITIES.map((id) => PHRASING[id].gerund),
        'and'
      )}.`
    )
  } else {
    if (allowed.length > 0) {
      clauses.push(`Can ${join(allowed.map((id) => PHRASING[id].verb), 'and')} without asking.`)
    }
    if (asked.length > 0) {
      clauses.push(`Asks you first before ${join(asked.map((id) => PHRASING[id].gerund), 'and')}.`)
    }
    if (denied.length > 0) {
      clauses.push(`Cannot ${join(denied.map((id) => PHRASING[id].verb), 'or')}.`)
    }
  }

  return { sentence: clauses.join(' '), clauses, elevated, counts }
}

export interface FilePolicySummary {
  sentence: string
  total: number
  denying: number
  asking: number
}

/**
 * The path-rule list one line shorter than reading it.
 *
 * A rule counts as denying if either its read or its write is 'deny' — the two
 * are separate settings and a rule that blocks writes to /etc while still
 * allowing reads is a deny rule from the reader's point of view.
 */
export function summariseFilePolicies(rules: FilePathRule[]): FilePolicySummary {
  const has = (r: FilePathRule, v: PermissionValue): boolean => r.read === v || r.write === v
  const denying = rules.filter((r) => has(r, 'deny')).length
  const asking = rules.filter((r) => !has(r, 'deny') && has(r, 'ask')).length

  if (rules.length === 0) {
    return {
      sentence: 'No path rules — every file follows the read and write settings above.',
      total: 0,
      denying: 0,
      asking: 0
    }
  }

  const parts: string[] = []
  if (denying > 0) parts.push(`${denying} blocking access`)
  if (asking > 0) parts.push(`${asking} asking first`)
  const detail = parts.length > 0 ? ` — ${join(parts, 'and')}` : ''
  return {
    sentence: `${rules.length} path ${rules.length === 1 ? 'rule' : 'rules'}${detail}.`,
    total: rules.length,
    denying,
    asking
  }
}
