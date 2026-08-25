import type { CachedServer, CachedWorkspace } from './mcpDataCache'
import { getServerMeta } from './policyStore'

export interface ServerMatch {
  workspace: CachedWorkspace
  server: CachedServer
}

export type ResolveResult =
  | { type: 'found'; match: ServerMatch }
  | { type: 'ambiguous'; matches: ServerMatch[] }
  | { type: 'not-found' }

function normalize(s: string): string {
  return s.trim().toLowerCase()
}

function candidateNames(server: CachedServer): string[] {
  const meta = getServerMeta(server.id)
  return [server.name, ...meta.aliases].map(normalize)
}

// Never guesses: an exact name match wins outright even if a looser alias
// match exists elsewhere, but two equally-good matches are surfaced to the
// caller as an ambiguity rather than silently picking one.
export function resolveServerByName(
  query: string,
  servers: CachedServer[],
  workspaces: CachedWorkspace[]
): ResolveResult {
  const q = normalize(query)
  if (!q) return { type: 'not-found' }

  const byWorkspace = new Map(workspaces.map((w) => [w.id, w]))
  const toMatch = (s: CachedServer): ServerMatch | null => {
    const workspace = byWorkspace.get(s.workspaceId)
    return workspace ? { workspace, server: s } : null
  }

  const exact = servers
    .filter((s) => candidateNames(s).includes(q))
    .map(toMatch)
    .filter((m): m is ServerMatch => m !== null)

  if (exact.length === 1) return { type: 'found', match: exact[0] }
  if (exact.length > 1) return { type: 'ambiguous', matches: exact }

  const partial = servers
    .filter((s) => candidateNames(s).some((name) => name.includes(q)))
    .map(toMatch)
    .filter((m): m is ServerMatch => m !== null)

  if (partial.length === 1) return { type: 'found', match: partial[0] }
  if (partial.length > 1) return { type: 'ambiguous', matches: partial }

  return { type: 'not-found' }
}

export function formatAmbiguity(matches: ServerMatch[]): string {
  const lines = matches.map((m, i) => `${i + 1}. ${m.workspace.name} / ${m.server.name}`)
  return `Multiple servers match. Ask the user to pick one:\n${lines.join('\n')}`
}
