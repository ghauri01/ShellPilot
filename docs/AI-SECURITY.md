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

**The local terminal is on the human side of that boundary, permanently.** ShellPilot can open a
shell on the machine it is itself running on — your own zsh, PowerShell, WSL, with your own
privileges — and no part of that surface is reachable from the left of the arrow. It is not a tool,
not a capability and not an ASK prompt, because an agent that can run local commands can read the
vault file, the policy store and the audit log that are supposed to constrain it: every constraint
described in this document is a file on the same disk as that shell. See
["No local terminal" is a narrower claim than "no local process"](#no-local-terminal-is-a-narrower-claim-than-no-local-process)
below for what that does and does not rule out, and the *Local terminal* section of
[SECURITY.md](../SECURITY.md) for what such a shell reaches.

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
- **A shell on your own machine.** ShellPilot's local terminal — the tab that runs your zsh, bash,
  PowerShell or WSL with your own privileges — has no MCP tool, no capability and no ASK prompt,
  and that is deliberate rather than a gap waiting to be filled. There is no setting of either that
  would make it safe: an agent that can run local commands can read the vault file, the policy store
  and the audit log that are supposed to constrain it. So the answer is not "gated", it is "not
  reachable", and `tests/localTerminalNotExposed.test.ts` fails the build if that stops being true —
  it walks the transitive import closure of `mcpServer.ts` and `src/cli/`, so the module cannot even
  be *imported* by anything an agent talks to, let alone called.
- **Third-party API keys, and the proxy that uses them.** The API credential proxy
  (`credProxy.ts`) lets a script call a third-party API without holding its key: the credential is
  resolved through the same `credentialResolver.ts` and injected at the boundary. An agent gets
  neither half of it. It cannot *define a rule*, because a rule is a durable statement of where one
  of your credentials may go — a row in a JSON file that outlives the session that wrote it, with
  nothing pending for `denyAllPending()` to revoke, which is the same objection this document's
  companion makes about the job engine, one turn further. And it cannot *call the proxy*, because
  a caller that does not hold the key is still spending your API budget on somebody else's meter,
  under a credential no audit here can attribute to it. There is no tool, no capability and no ASK
  prompt; `tests/jobsNotExposed.test.ts` walks the same import closure the local terminal relies on
  and fails the build if the module becomes reachable.
- **A VPN's endpoint, keys or listener addresses.** `list_vpns` reports which profiles exist,
  which engine carries each one and whether it is up. The cached record it reads from
  (`CachedVpn`, `mcpDataCache.ts`) does not hold an endpoint, a key ref or a bind address at all,
  so this is a shape that cannot leak one rather than a field somebody remembered not to print.

## "No local terminal" is a narrower claim than "no local process"

Worth drawing out, because the broad version of the claim is false and stating the narrow one is
the only way to keep the guard honest.

ShellPilot does run programs on this machine while serving an agent. Ten modules inside the very
import closure that `tests/localTerminalNotExposed.test.ts` walks spawn child processes:
`vpn/supervisor.ts`, `vpn/binaries.ts`, `vpn/drivers/wireguard.ts`, `vpn/netstate.ts`, the three
`vpn/elevation/*.ts`, `vpn/driver.ts`, and two modules under `src/cli/`. Bringing up a WireGuard
tunnel means executing a binary locally; there is no version of that feature that does not.

Those are fine, and the reasons they are fine are exactly the properties a shell lacks:

- **The argv is ShellPilot's, not the agent's.** An agent supplies a profile name. It never supplies
  a command, an argument or a path. `vpn/binaries.ts` runs either an engine ShellPilot ships,
  checked against a manifest of its exact bytes before the first exec, or a system-installed one
  from a fixed allowlist of directories — never a `PATH` search, because on Windows the search *is*
  the vulnerability.
- **They are behind `vpnControl` and an approval.** No built-in group grants it outright, and
  starting a VPN is ASK on every group including one raised to ALLOW — see the section below.
- **The two `src/cli` spawns are not agent-driven at all.** They are what `shellpilot claude`,
  `shellpilot codex` and `shellpilot run -- …` do when a human types them in their own terminal:
  launch that agent's CLI as a child of the CLI process, before any MCP session exists. No tool call
  reaches them.

An interactive shell has none of that. Its entire purpose is that the argv is whatever gets typed.
So the claim this document makes — and the one the test enforces — is that **no agent-facing surface
reaches an interactive shell on this machine**, not that no local process ever runs at an agent's
request.

## Threat model

| Risk | What closes it | Where |
|---|---|---|
| Credential exposure to a model's context (and whatever a provider retains of it) | Credentials are resolved inside the main process at connect time and never placed in a tool response | `credentialResolver.ts` |
| Network/topology exposure — leaking internal IPs, hosts, usernames just by listing servers | Tool responses carry only names, OS and permissions | `mcpServer.ts` (`list_servers`, `get_server_details`) |
| Prompt-injection or a confused agent running something destructive | Any capability set to ASK blocks until a human approves; the agent has no path to approve its own request | `approvals.ts`, `mcpServer.ts` |
| Sudo / privilege escalation, including via disguised unrestricted shells | Hard-denied by pattern match, independent of access-group configuration | `policyEngine.ts` (`classifyCommand`, `evaluateCommand`) |
| An agent silently changing which network the user's traffic crosses | Starting a VPN is always ASK, on every group, including one set to ALLOW; stopping one is ASK whenever live sessions depend on it | `policyEngine.ts` (`evaluateVpnControl`) |
| An agent publishing a local port to the internet through a reverse proxy | `set_vpn` refuses `frp` profiles before the access group is consulted, in either direction; no capability value reaches past it, and there is no tool that can create one | `policyEngine.ts` (`isVpnKindRefusedForAi`), `mcpServer.ts` (`set_vpn`) |
| Secrets leaking through command output (`env`, a misconfigured app, a `cat` of a file with a key in it) | Known credential values blanked verbatim; pattern rules catch `PASSWORD=`/`TOKEN=`-style assignments, PEM key blocks, bearer tokens, AWS access key IDs, connection-string passwords | `secretRedaction.ts` |
| A leaked or stolen token granting standing access | Only a SHA-256 hash + 4-character preview is ever stored; every session has its own expiry and is individually revocable, or all revocable at once | `mcpAuth.ts` |
| Lateral movement — a session reaching a workspace it wasn't granted | A server outside the session's granted workspace(s) is never in the candidate list a tool call resolves against — invisible, not merely denied. Workspaces are chosen explicitly per session, never "all, including future ones" | `mcpDataCache.ts`, `serverResolver.ts` |
| No record of what an agent actually did | Every decision the bridge makes — allowed, asked, approved, denied, failed — is written to an append-only, redacted audit log. It records the *bridge*, not the whole application — see the note under this table | `auditLog.ts` |
| A compromised local process trying to complete CLI pairing on its own | The pairing code is shown only inside the ShellPilot window, never returned over HTTP to whatever process asked for it | `cliPairing.ts` |

**What the audit log does and does not cover.** `recordAudit` is called from `mcpServer.ts` and
nowhere else, so `shellpilot-ai-audit.jsonl` is a record of **the MCP bridge**, not of everything
that happens in ShellPilot. Nothing an agent does is missing from it, so the row above holds for the
threat it names — but do not read the broader claim out of that row.

The local terminal is logged **separately**, to `shellpilot-local-sessions.jsonl`
(`localSessionLog.ts`, append-only, `0600`, same discipline). One entry when a shell starts and one
when it exits: shell label, resolved path, pid, working directory, exit status. **Never keystrokes,
never output** — a shell session's contents are yours, and a log of them would be a more attractive
target than the thing it was meant to protect. There is a test asserting no field capable of holding
terminal input or output has been added.

Jobs and broadcasts are logged **separately again**, to `shellpilot-job-approvals.jsonl`
(`approvalLog.ts`, append-only, `0600`, same discipline — a separate module as well as a separate file, because `auditLog.ts` is inside the agent-reachable import closure and `tests/jobsNotExposed.test.ts` refuses to let anything in it import the job vocabulary). One entry per approval
decision — granted, refused, resumed, or sealed — carrying the risk, the confirmation kind, the
phrase the user typed where one was required, the host names and the step commands, all redacted
through the same `redactOutput` rules. **Never output**: a job's output is in the history store
under its own retention, not here.

Three files rather than one is deliberate, and it is the same argument twice. The AI audit log
answers *"what did an agent do"*; its entries are agent-shaped (`agentName`, `capability`,
`approval`) and it is displayed in the AI section. Local terminal rows there would mean an
AI-labelled log full of things no AI did, which is how a log stops being trusted. A job is
human-only by construction — it is not reachable from the bridge and will not be, because
durability defeats revocation: `denyAllPending()` resolves requests that are *pending*, and a job
already detached on fifteen hosts has nothing pending to deny. So its rows would be AI-labelled rows
no AI produced, for exactly the local terminal's reason.

**One reader now spans all three, and it does not merge them.** The change log
(`changelog.ts`) reads all three files to answer *"who changed what on this estate, and who
approved it"* — a question none of them answers alone. It reads them; it does not combine them into
a fourth file, and each row keeps the source it came from, so the argument above still holds: an
entry from the local terminal is still labelled as the local terminal, not as an agent. The
separation is in what each file *means*, and that survives being read together. The change log is
also read-only over them — nothing it does writes back, and it is not reachable from the bridge.

**None of the three is pruned, and that is a real gap rather than a decision.** The history store
has a retention horizon per event kind; these three files have none, so they grow for as long as the
app is used. In practice that is slow — one line per approval or per agent call, not per output line
— but "slow" is not "bounded", and an operator who wants a bound has to remove the file themselves
today. Deleting one loses history and breaks nothing: each is opened append-only and recreated on
next write.

## Granting `vpnControl` is a bigger decision than it looks

Read this before setting `vpnControl` to anything other than `deny`.

Every other capability in the model is scoped to one server, one file or one statement.
`vpnControl` is not. **A VPN decides which network the user's later SSH and database sessions
travel over** — including sessions the agent never touches and connections the user opens by hand
afterwards. An agent that can start a VPN is an agent that can change the meaning of "connect to
Production API" without going anywhere near that server's configuration.

Combined with `manageServers`, the two compose into something neither grants alone: an agent could
add a server *and* bring up a VPN that server's traffic is routed through, and both actions would
look ordinary in isolation. That composition is the reason for the three rules below, and none of
them is a preference:

- **Starting a VPN is always ASK**, on every group, including one a user has explicitly raised to
  ALLOW (`evaluateVpnControl`, `policyEngine.ts`). There is no configuration in which a VPN comes
  up silently at an agent's request.
- **Reverse proxies (frp) are refused outright**, in both directions, before the access group is
  read (`isVpnKindRefusedForAi`). An frp proxy makes a port on the user's own machine reachable
  from the frp server — from the internet — and an approval dialog is not a meaningful control
  there, because "Start VPN office" reads nothing like "publish port 5432 to the internet" to the
  person clicking it. If an frp profile is to run, the user starts it in ShellPilot themselves.
- **There is no tool that creates or edits a VPN profile.** No `add_vpn`, no `edit_vpn`, and this
  is asserted by a test rather than left to reviewer memory. An agent can run a profile the user
  wrote; it can never author where one points.

None of the built-in groups grants `vpnControl` outright: **Read Only** denies it, and **Read &
Write**, **Sudo Access** and **Full Access** all set it to ASK. A group saved before this version
existed backfills to DENY if it is custom, and to the fresh-install value if it is built in
(`backfillCapabilities`, `policyStore.ts`) — an upgrade never silently widens what a group permits.

What this does *not* do is make a granted `vpnControl` safe. If you approve a start prompt without
reading it, you have moved your traffic, and the audit entry — `Start VPN "office" (wireguard,
userspace, 2 listeners)` — will record that you meant to.

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
