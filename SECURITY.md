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
| Biometric unlock key (opt-in, off by default) | `shellpilot-vault-bio.json` | The vault's **derived key**, wrapped with Electron `safeStorage`. Present only if you enable Touch ID unlock. The master password is not stored, but see below — this is the weakest protection any vault data gets. |
| Workspace passwords | `shellpilot-wslocks.json` | scrypt verifier with a random salt, compared with `timingSafeEqual`. Not reversible. |
| Trusted SSH host keys | `shellpilot-known-hosts.json` | SHA-256 fingerprints, plaintext (not secret). |
| Backups | user-chosen `.spbackup` file | AES-256-GCM under a passphrase you supply. Credentials are unsealed from the keychain and re-encrypted so the file is portable. |
| Servers, folders, workspaces | `shellpilot-data.json` | Plaintext. Contains no credentials. |
| AI/MCP agent sessions | `shellpilot-mcp-sessions.json` | Only a SHA-256 hash and a 4-character preview of the bearer token is stored — never the raw token. |
| AI/MCP audit log | `shellpilot-ai-audit.jsonl` | Plaintext, append-only. Free-text fields are passed through the same secret-redaction as command output before being written, so it should never contain a credential. |
| AI/MCP access-group policy | `shellpilot-ai-policy.json` | Plaintext. Contains no credentials — capability rules and file-path patterns only. |

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
