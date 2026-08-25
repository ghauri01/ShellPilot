# AI & MCP — threat model and security boundaries

This document describes what ShellPilot's MCP bridge is designed to protect against, exactly
where the trust boundary sits, and — just as importantly — what it does **not** claim. For how
the bridge is built and how to use it, see [AI-MCP.md](AI-MCP.md). For ShellPilot's general
security posture and how to report a vulnerability, see [SECURITY.md](../SECURITY.md).

## The trust boundary

```
AI Agent  --(MCP: stdio or HTTP + Bearer token)-->  ShellPilot main process
```

Everything to the right of that arrow — policy evaluation, approval, credential lookup, the SSH/
SFTP/database connection itself — runs inside ShellPilot's own main process, on your machine. The
AI agent is a client on the *left* of that boundary: it sends a tool call and a friendly server
name, and receives back either an error, a text result, or a redacted command output. Nothing
else ever crosses back.

The bridge's HTTP listener binds to `127.0.0.1` only (`startMcpServer`, `mcpServer.ts`). There is
no configuration option that exposes it to a network interface — the boundary is not "trust
whoever can reach this port," it's "nothing beyond this machine can reach this port at all."

## What an AI agent never receives

Regardless of which access group a session holds:

- **SSH passwords, private keys or passphrases.** Resolved server-side by
  `credentialResolver.ts` at the moment a connection is opened; no MCP tool response ever
  contains one.
- **Database passwords or connection-string credentials.** Same resolver, same rule — and any
  password embedded in a connection-string URL that shows up in command output is redacted before
  the agent sees it (`secretRedaction.ts`).
- **Vault secrets.** There is no MCP tool that reads the Vault. This isn't a policy that could be
  misconfigured to `allow` — the code path doesn't exist.
- **Sudo / root credentials.** ShellPilot does not separately store a "sudo password" for any
  server — sudo capability is a policy decision about whether a `sudo`/`doas` command is allowed
  to run over the SSH connection that's already authenticated, not a credential handed to
  anything. Unrestricted root shells (`sudo -i`, `sudo su`, `sudo bash`, bare `su`) are refused
  unconditionally, before the access group is even consulted.
- **A server's real host, IP, port or username.** Every tool that names a server takes and
  returns a friendly name (e.g. "Production API"); `get_server_details` returns OS, access group
  and effective permissions, never connection details.

## Threat model

| Risk | What closes it | Where |
|---|---|---|
| Credential exposure to a model's context (and whatever a provider retains of it) | Credentials are resolved inside the main process at connect time and never placed in a tool response | `credentialResolver.ts` |
| Network/topology exposure — leaking internal IPs, hosts, usernames just by listing servers | Tool responses carry only names, OS and permissions | `mcpServer.ts` (`list_servers`, `get_server_details`) |
| Prompt-injection or a confused agent running something destructive | Any capability set to ASK blocks until a human approves; the agent has no path to approve its own request | `approvals.ts`, `mcpServer.ts` |
| Sudo / privilege escalation, including via disguised unrestricted shells | Hard-denied by pattern match, independent of access-group configuration | `policyEngine.ts` (`classifyCommand`, `evaluateCommand`) |
| Secrets leaking through command output (`env`, a misconfigured app, a `cat` of a file with a key in it) | Known credential values blanked verbatim; pattern rules catch `PASSWORD=`/`TOKEN=`-style assignments, PEM key blocks, bearer tokens, AWS access key IDs, connection-string passwords | `secretRedaction.ts` |
| A leaked or stolen token granting standing access | Only a SHA-256 hash + 4-character preview is ever stored; every session has its own expiry and is individually revocable, or all revocable at once | `mcpAuth.ts` |
| Lateral movement — a session scoped to one workspace reaching another | A server outside the session's workspace is never in the candidate list a tool call resolves against — invisible, not merely denied | `mcpDataCache.ts`, `serverResolver.ts` |
| No record of what an agent actually did | Every decision — allowed, asked, approved, denied, failed — is written to an append-only, redacted audit log | `auditLog.ts` |
| A compromised local process trying to complete CLI pairing on its own | The pairing code is shown only inside the ShellPilot window, never returned over HTTP to whatever process asked for it | `cliPairing.ts` |

## What this does not claim

This design **reduces** the ways an AI integration can go wrong; it does not make the integration
risk-free, and none of the following should be inferred from anything in this document or the
README:

- **Not "unhackable," "zero risk," or "fully secure."** Access groups and approvals reduce the
  blast radius of a mistake or a malicious prompt; they do not make one impossible. A group you
  configure as `Full Access` genuinely grants full access.
- **Approval quality depends on the human approving.** If you reflexively click Approve without
  reading what an ASK request is actually asking to do, the approval gate provides no protection.
  It only helps if the decision is actually considered.
- **This does not protect against a compromised local machine.** If an attacker has your OS user
  account, they have the same keychain access ShellPilot itself uses to resolve credentials — the
  MCP policy layer is not a substitute for endpoint security.
- **Redaction is pattern-based, not exhaustive.** `secretRedaction.ts` catches known secret values
  and common secret-*shaped* text (env-style assignments, PEM blocks, bearer tokens, AWS key IDs,
  connection-string passwords). A credential in a format none of those patterns match, and that
  ShellPilot doesn't already hold as a known value for that server, will not be caught.
- **A denied or ASK-gated capability is a policy decision, not a sandbox.** ShellPilot does not
  run commands inside a container or restricted shell on the target server; `execute_command` runs
  exactly what it's given, over the same SSH session an interactive terminal would use, once
  policy allows it.
- **This document describes the MCP bridge specifically.** It does not extend to ShellPilot's
  general attack surface (the desktop app itself, its update mechanism, its dependencies) — see
  [SECURITY.md](../SECURITY.md) for that, and to report a vulnerability.
