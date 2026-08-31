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
  },
  // --- VPN engine output -------------------------------------------------
  //
  // A WireGuard key is 32 bytes, so base64 of one is 44 chars with a fixed
  // final alphabet. Private, public and preshared keys are indistinguishable
  // by shape, so the public key is redacted too. That is the right trade: a
  // redacted public key costs a support ticket, a leaked private key costs the
  // tunnel. The UI must therefore show a public key from the profile model,
  // never scraped back out of a log.
  //
  // The trailing \B is what keeps this off ordinary base64: a longer blob's
  // only '=' is its own terminator, and the char before the 44-char window is
  // then a word char, so neither boundary holds.
  // WireGuard keys: 44 base64 characters, the 43rd constrained.
  //
  // Two things here are easy to get wrong and both leak a private key.
  //
  // The trailing `048`: the 43rd character encodes only the low nibble of the
  // last byte shifted left by two, so it is one of `AEIMQUYcgkosw048`. The
  // first thirteen are letters and the last three digits, so the digits get
  // dropped — which lets 19% of real keys through.
  //
  // The boundaries: `\b` does not work here. A base64 key can begin with `+`
  // or `/`, which are not word characters, so after a space there is no word
  // boundary and the match fails — silently, for 2 keys in 64. Anchoring on
  // "not preceded/followed by another base64 character" is what actually
  // expresses the intent, and it still declines to bite a 44-character window
  // inside a longer blob.
  {
    regex: /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=(?![A-Za-z0-9+/=])/g,
    replace: () => PLACEHOLDER
  },
  // The same keys in the hex form wireguard-go's UAPI speaks on its socket.
  {
    regex: /\b((?:private|preshared)_key)=[0-9a-f]{64}\b/gi,
    replace: (m) => `${m[1]}=${PLACEHOLDER}`
  },
  // OpenVPN static-challenge response: base64(password) and base64(otp) in one
  // token. It carries the password itself, not just the one-time code.
  { regex: /SCRV1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/g, replace: () => PLACEHOLDER },
  // frp / generic TOML+INI secret assignment. Line-anchored and greedy to the
  // end of the line because a TOML value may be quoted, bare, or a Go template
  // expression, and the whole of it is the secret.
  {
    regex: /^(\s*(?:auth\.)?(?:token|secretKey|password)\s*=\s*).+$/gim,
    replace: (m) => `${m[1]}${PLACEHOLDER}`
  },
  // OpenVPN management-channel command echo. `--management-query-passwords`
  // makes us write `password "Auth" "<secret>"` on the socket, and the daemon
  // echoes what it received back at us when logging is verbose.
  {
    regex: /\b(password\s+"[^"\n]*"\s+)"[^"\n]*"/gi,
    replace: (m) => `${m[1]}"${PLACEHOLDER}"`
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
