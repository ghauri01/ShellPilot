// Output scrubbing: command/file output returned to an AI agent (and
// anything written to the audit log) is passed through this before it
// leaves the security boundary. Two layers:
//  1. Known secret values actually held for the servers involved in this
//     operation (resolved passwords/passphrases/DB credentials) are blanked
//     out verbatim, so a command that happens to print one back can't leak it.
//  2. Common secret-shaped patterns (KEY=value assignments, private key
//     blocks, bearer/API tokens) are redacted even when the value itself
//     isn't one ShellPilot already knows about.
const PLACEHOLDER = '[REDACTED]'

const PATTERN_RULES: { regex: RegExp; replace: (m: string[]) => string }[] = [
  // FOO_PASSWORD=bar / FOO_TOKEN=bar / FOO_SECRET=bar style env assignments.
  {
    regex: /\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)[A-Za-z0-9_]*)\s*[:=]\s*("[^"\n]*"|'[^'\n]*'|\S+)/gi,
    replace: (m) => `${m[1]}=${PLACEHOLDER}`
  },
  // Full PEM private key blocks.
  {
    regex: /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g,
    replace: () => `-----BEGIN PRIVATE KEY-----\n${PLACEHOLDER}\n-----END PRIVATE KEY-----`
  },
  // Bearer/API tokens in headers or CLI flags.
  {
    regex: /\b(Bearer|Authorization:\s*Bearer)\s+[A-Za-z0-9._-]{10,}/gi,
    replace: (m) => `${m[1]} ${PLACEHOLDER}`
  },
  // AWS access key ids.
  { regex: /\bAKIA[0-9A-Z]{16}\b/g, replace: () => PLACEHOLDER },
  // Postgres/MySQL/Mongo style connection URIs with an embedded password.
  {
    regex: /\b([a-z][a-z0-9+.-]*:\/\/[^:/\s]+:)([^@/\s]+)(@)/gi,
    replace: (m) => `${m[1]}${PLACEHOLDER}${m[3]}`
  }
]

export function redactKnownSecrets(text: string, knownSecrets: string[]): string {
  let out = text
  for (const secret of knownSecrets) {
    if (!secret || secret.length < 3) continue
    out = out.split(secret).join(PLACEHOLDER)
  }
  return out
}

export function redactPatterns(text: string): string {
  let out = text
  for (const rule of PATTERN_RULES) {
    out = out.replace(rule.regex, (...args: unknown[]) => {
      // args is [fullMatch, group1, group2, ..., offset, string] — groups
      // line up at the same indices the rule callbacks index by (m[1], m[2]).
      const groups = args.slice(0, -2).map((a) => (typeof a === 'string' ? a : ''))
      return rule.replace(groups)
    })
  }
  return out
}

export function redactOutput(text: string, knownSecrets: string[] = []): string {
  return redactPatterns(redactKnownSecrets(text, knownSecrets))
}
