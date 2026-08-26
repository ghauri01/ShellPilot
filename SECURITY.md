# Security Policy

ShellPilot handles SSH keys, passwords and database credentials. Security
reports are taken seriously and are welcome.

For the AI & MCP bridge's threat model specifically — what an AI agent can and cannot reach, and
where that design's limits are — see [docs/AI-SECURITY.md](docs/AI-SECURITY.md).

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's [private vulnerability reporting](../../security/advisories/new),
or email the maintainer at <aliwaqarofficial@gmail.com>. Include:

- what the issue is and roughly how severe you think it is
- steps to reproduce, or a proof of concept
- affected version and platform

You can expect an acknowledgement within a few days. We will keep you updated
while a fix is prepared, and credit you in the release notes unless you would
rather stay anonymous.

## Supported versions

Fixes land on the latest release. There is no long-term support branch yet.

## How secrets are handled

Knowing the design may help you assess a finding.

| Data | Storage | Protection |
|---|---|---|
| SSH passwords, key paths, key passphrases | `shellpilot-secrets.json` | Electron `safeStorage` — DPAPI / Keychain / libsecret. Machine and user bound. |
| Vault entries | `shellpilot-vault.json` | AES-256-GCM, key from the master password via scrypt (N=32768). Password never stored. Decrypted entries are sent to the renderer while the vault is open, so they live in the renderer's memory too — not only in the main process. |
| Biometric unlock key (opt-in, off by default) | main-process memory, or `shellpilot-vault-bio.json` | The vault's **derived key**, wrapped with Electron `safeStorage`. By default this is held in memory only and dies with the process, so nothing is written to disk. The file exists only if you explicitly choose to keep biometric unlock across restarts. |
| Workspace passwords | `shellpilot-wslocks.json` | scrypt verifier with a random salt, compared with `timingSafeEqual`. Not reversible. |
| Trusted SSH host keys | `shellpilot-known-hosts.json` | SHA-256 fingerprints, plaintext (not secret). |
| Backups | user-chosen `.spbackup` file | AES-256-GCM under a passphrase you supply. Credentials are unsealed from the keychain and re-encrypted so the file is portable. |
| Servers, folders, workspaces | `shellpilot-data.json` | Plaintext. Contains no credentials. |
| AI/MCP agent sessions | `shellpilot-mcp-sessions.json` | Only a SHA-256 hash and a 4-character preview of the bearer token is stored — never the raw token. |
| AI/MCP audit log | `shellpilot-ai-audit.jsonl` | Plaintext, append-only. Free-text fields are passed through the same secret-redaction as command output before being written, so it should never contain a credential. |
| AI/MCP access-group policy | `shellpilot-ai-policy.json` | Plaintext. Contains no credentials — capability rules and file-path patterns only. |

### SSH host keys

ShellPilot does trust-on-first-use host key checking against its own
`shellpilot-known-hosts.json`. Without it, ssh2 accepts any key presented, so
anything on the path to a server could capture the session and the credentials
sent over it.

It also **reads** `~/.ssh/known_hosts` (and `known_hosts2`), but never inherits
trust from it. Adopting that file wholesale would silently take on every trust
decision it has accumulated, including whatever `StrictHostKeyChecking=accept-new`
waved through unattended. So an entry there only changes what the prompt says:
a host whose exact key OpenSSH already has is presented as recognised, and the
dialog defaults to Trust instead of Cancel. A human still confirms it once.

Two cases there are not merely informational:

- **`@revoked`** matching the presented key refuses the connection outright. It
  is a negative signal, so acting on it without asking only ever restricts.
- **A host present under a different key** is called out explicitly in the
  prompt, since that is either a rebuilt server or an interception.

`@cert-authority` lines are ignored. They authorise certificates rather than
naming a host key, and ShellPilot cannot validate a certificate chain — so they
are treated as no evidence rather than as trust.

Once a host is trusted, a *changed* key is always refused outright and never
re-prompted: the user has to forget the saved key in Settings → Security first.

### Process hardening

macOS builds run with the **hardened runtime**, which blocks
`DYLD_INSERT_LIBRARIES` injection and debugger attach. This matters more than
any of the vault's own protections: without it, a process running as the same
user can inject into ShellPilot and read an unlocked vault key out of memory,
and no amount of encryption at rest or biometric gating prevents that.

The hardened runtime does not require an Apple Developer certificate — it works
with the ad-hoc signature these builds already carry.

Library validation is disabled by entitlement, because `asarUnpack` keeps the
ssh2 and cpu-features native binaries outside the archive deliberately. That
gives back one of the three protections the hardened runtime provides and keeps
the two that defend an unlocked vault.

### Workspaces and the vault

Workspaces isolate **servers, databases and tunnels** — each record carries a
workspace id and is filtered by it. A password-protected workspace keeps those
out of sight until it is unlocked.

**The vault is filtered by workspace, not separated by it.** A vault entry can
belong to a workspace — new entries belong to the one they were created in —
and the entry list then shows that workspace's entries plus any marked shared.
Entries written before this existed have no workspace recorded, so they stay
shared and can be moved deliberately.

What that is worth, stated precisely: it stops another client's credentials
being in front of you, and it stops you saving a credential into the wrong
place by accident. It is **not** a cryptographic boundary. The vault remains
one encrypted file under one master password, so anything that can read the
unlocked vault can read every entry in it regardless of workspace. Locking a
workspace does not lock the vault.

Per-workspace cryptographic separation would mean a master password per
workspace, which is a different product; this is a view over one vault.

### What biometric unlock actually protects

Worth stating plainly, because it is easy to assume more.

Electron's `promptTouchID` authenticates the person at the keyboard. It does not
return a key. So enabling Touch ID unlock stores the vault's derived key on disk
under `safeStorage`, with a biometric prompt in front of reading it — a **gate**,
not a cryptographic binding. Software running under your macOS account can read
that key without ever triggering the prompt.

The stronger designs — a Keychain item with a biometry ACL, or a Secure Enclave
key wrapping the vault key — both require the macOS data-protection keychain,
which requires entitlements authorised by a provisioning profile, which requires
a paid Apple Developer account. ShellPilot is ad-hoc signed and has none, so
neither is available to it. (Apple's TN3137 documents this; it is the design, not
a gap we have failed to close.)

This is why biometric unlock is **session-scoped by default**: the wrapped key
is held in main-process memory and dies with the app, so an attacker who can
read your files finds nothing to read. You type the master password once per
launch and Touch ID reopens the vault after that. It is the same design
KeePassXC uses, and it is what makes the feature defensible without the
entitlements above.

Keeping it across restarts is a separate, explicit choice, and it is the one
that writes the key to disk.

Two consequences worth being concrete about:

- With biometric unlock **off**, the master password exists nowhere on the
  machine, and the vault is the only ShellPilot data an attacker with your files
  and your logged-in session cannot read. Turning it on gives that up.
- Your SSH credentials in `shellpilot-secrets.json` have always been protected
  by `safeStorage` alone. So enabling this moves the vault down to the protection
  the rest of the app already has, rather than opening a new category of risk.

It remains a real barrier against someone who picks up an unlocked laptop, and it
is why the feature exists. It is not a barrier against code running as you.

## Known limitations

These are design decisions, not bugs. Please do not report them as
vulnerabilities — but do open a discussion if you disagree with the tradeoff.

- **Workspace passwords gate the UI only.** They do not encrypt that
  workspace's servers on disk.
- **A backup passphrase cannot be recovered.** There is no escrow and no
  backdoor.
- **`safeStorage` is machine bound.** Copying the config folder to another
  machine will not carry credentials — use an encrypted backup instead.
- **Releases are not code-signed.** Verify checksums if you need assurance
  about a download.
