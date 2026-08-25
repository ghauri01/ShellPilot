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
| Vault entries | `shellpilot-vault.json` | AES-256-GCM, key from the master password via scrypt (N=32768). Password never stored. |
| Workspace passwords | `shellpilot-wslocks.json` | scrypt verifier with a random salt, compared with `timingSafeEqual`. Not reversible. |
| Trusted SSH host keys | `shellpilot-known-hosts.json` | SHA-256 fingerprints, plaintext (not secret). |
| Backups | user-chosen `.spbackup` file | AES-256-GCM under a passphrase you supply. Credentials are unsealed from the keychain and re-encrypted so the file is portable. |
| Servers, folders, workspaces | `shellpilot-data.json` | Plaintext. Contains no credentials. |
| AI/MCP agent sessions | `shellpilot-mcp-sessions.json` | Only a SHA-256 hash and a 4-character preview of the bearer token is stored — never the raw token. |
| AI/MCP audit log | `shellpilot-ai-audit.jsonl` | Plaintext, append-only. Free-text fields are passed through the same secret-redaction as command output before being written, so it should never contain a credential. |
| AI/MCP access-group policy | `shellpilot-ai-policy.json` | Plaintext. Contains no credentials — capability rules and file-path patterns only. |

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
