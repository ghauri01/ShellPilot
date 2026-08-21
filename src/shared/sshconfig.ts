// Parser for OpenSSH client config files (~/.ssh/config).
//
// Only the directives that map onto a ShellPilot server are read. Pattern
// entries (Host *, Host web-*) are treated as defaults and merged into the
// concrete hosts they match rather than being imported as servers.

export interface SshConfigHost {
  // The alias as written after `Host`.
  alias: string
  hostName: string
  user: string
  port: number
  identityFile?: string
  proxyJump?: string
  // Directives kept for display but not imported.
  extras: Record<string, string>
}

interface RawBlock {
  patterns: string[]
  values: Record<string, string>
}

// Translate an OpenSSH host pattern into a matcher (* and ? are the wildcards).
function patternMatches(pattern: string, alias: string): boolean {
  if (pattern === alias) return true
  if (!/[*?]/.test(pattern)) return false
  const rx = new RegExp(
    '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
  )
  return rx.test(alias)
}

const isPattern = (p: string): boolean => /[*?!]/.test(p)

export function parseSshConfig(text: string): SshConfigHost[] {
  const blocks: RawBlock[] = []
  let current: RawBlock | null = null

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue

    // `Key value`, `Key=value`, and quoted values are all legal.
    const m = /^(\w+)\s*(?:=|\s)\s*(.*)$/.exec(line)
    if (!m) continue
    const key = m[1].toLowerCase()
    const value = m[2].trim().replace(/^"(.*)"$/, '$1')

    if (key === 'host') {
      current = { patterns: value.split(/\s+/).filter(Boolean), values: {} }
      blocks.push(current)
      continue
    }
    // Directives before the first Host block, and Match blocks, are ignored.
    if (!current) continue
    if (key === 'match') {
      current = null
      continue
    }
    if (current.values[key] === undefined) current.values[key] = value
  }

  const concrete = blocks.filter((b) => b.patterns.some((p) => !isPattern(p)))

  const out: SshConfigHost[] = []
  for (const block of concrete) {
    for (const alias of block.patterns.filter((p) => !isPattern(p))) {
      // Later-matching wildcard blocks supply defaults; first value wins, which
      // is what OpenSSH does.
      const merged: Record<string, string> = { ...block.values }
      for (const b of blocks) {
        if (b === block) continue
        if (!b.patterns.some((p) => isPattern(p) && patternMatches(p, alias))) continue
        for (const [k, v] of Object.entries(b.values)) if (merged[k] === undefined) merged[k] = v
      }

      const { hostname, user, port, identityfile, proxyjump, ...extras } = merged
      out.push({
        alias,
        hostName: hostname || alias,
        user: user || '',
        port: Number(port) || 22,
        identityFile: identityfile,
        proxyJump: proxyjump,
        extras: extras as Record<string, string>
      })
    }
  }
  return out
}
