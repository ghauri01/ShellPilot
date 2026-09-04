# AI & MCP — technical guide

This is the detailed reference for ShellPilot's [MCP](https://modelcontextprotocol.io) bridge —
how it's built, what each screen does, and how to connect Claude Code, Claude Desktop, Codex or
another MCP client. For the short pitch and the security summary, see the
[README's AI Agent Access section](../README.md#ai-agent-access). For the threat model, see
[AI-SECURITY.md](AI-SECURITY.md).

## Contents

- [Architecture](#architecture)
- [The MCP server](#the-mcp-server)
- [Sessions](#sessions)
- [Workspaces](#workspaces)
- [Access Groups](#access-groups)
- [Approvals](#approvals)
- [Audit Log](#audit-log)
- [Credential isolation](#credential-isolation)
- [The `shellpilot` CLI and pairing](#the-shellpilot-cli-and-pairing)
- [Connecting Claude Code](#connecting-claude-code)
- [Connecting Codex, Gemini CLI and other HTTP clients](#connecting-codex-gemini-cli-and-other-http-clients)
- [Connecting Claude Desktop](#connecting-claude-desktop)
- [Troubleshooting](#troubleshooting)

## Architecture

![Architecture: AI agent to MCP to ShellPilot policy to approval to SSH/SFTP/database to servers](images/ai-mcp-architecture.svg)

1. An MCP client (Claude Code, Claude Desktop, Codex, Gemini CLI, ...) sends a tool call over
   MCP — either **stdio** (via the `shellpilot` CLI's `bridge` subcommand) or **Streamable HTTP**
   with an `Authorization: Bearer <token>` header, directly to ShellPilot.
2. ShellPilot's MCP server (`src/main/services/mcpServer.ts`) is an HTTP server bound to
   **`127.0.0.1` only** (`startMcpServer`, `mcpServer.ts`). Nothing outside the machine can reach
   it, regardless of firewall or network configuration.
3. Every tool call authenticates the bearer token against a session (`mcpAuth.ts`), then resolves
   the target server **by friendly name** (`serverResolver.ts`) — never by hostname, IP or username,
   because the tool call never carries one.
4. The **access group** governing that server/workspace is evaluated for the specific capability
   the tool needs (`policyEngine.ts`), producing `allow`, `ask` or `deny`.
5. `ask` blocks on a human decision (`approvals.ts`) before anything happens. `deny` returns an
   error immediately. `allow` proceeds.
6. Only at this point does ShellPilot resolve the server's actual SSH/database credential
   (`credentialResolver.ts`) and open the connection — using the exact same connection-pooling
   path (`ssh.ts`) an interactive terminal session uses.
7. Command/file output is redacted (`secretRedaction.ts`) before it is returned to the agent, and
   the whole exchange is written to the audit log (`auditLog.ts`).

## The MCP server

`src/main/services/mcpServer.ts` registers **15 tools**:

| Tool | Capability gating it | What it returns |
|---|---|---|
| `list_workspaces` | — | The workspace(s) this session is scoped to |
| `list_servers` | `viewServer` | Friendly names only, filtered to what the session can see |
| `get_server_details` | `viewServer` | Name, OS, access group, effective ALLOW/ASK/DENY per capability — **never hostname/IP/username** |
| `execute_command` | `terminal` (+ `sudo` if the command is sudo/doas, + file path rules for any absolute path it names) | stdout/stderr/exit code, redacted |
| `read_file` | `readFiles` + `sftpDownload` (+ file path rules) | File contents, redacted |
| `write_file` | `writeFiles` + `sftpUpload` (+ file path rules) | Bytes written |
| `list_files` | `readFiles` + `sftpDownload` (+ file path rules) | Directory listing |
| `get_server_metrics` | `serverMetrics` | CPU/memory/disk/uptime |
| `add_server` | `manageServers`, resolved on the **workspace** | The name the new connection was saved under |
| `list_databases` | `viewServer` | Friendly names and engines, never a hostname or credential |
| `query_database` | `databaseAccess` for reads; `+ writeFiles` and always ASK for anything that writes | Rows, capped |
| `list_tunnels` | `sshTunnel` | Configured tunnels and whether each is running |
| `set_tunnel` | `sshTunnel`, always ASK to start | Confirmation, with the bound port |
| `list_vpns` | `vpnControl` | Names, engine, mode and state — **never an endpoint, key or listener address** |
| `set_vpn` | `vpnControl`, always ASK to start; **frp refused outright** | Confirmation, with a listener count |

Each tool carries a `title`, an MCP annotation set (`readOnlyHint`, `destructiveHint`,
`openWorldHint`) and a description of every parameter, and the server sends `instructions` on
initialize. That metadata is what stops an agent reaching for `execute_command` when a
purpose-built tool exists — see [Tool discoverability](#tool-discoverability).

### File rules apply to shell commands too

`execute_command` is checked against the same per-path rules as the SFTP tools. Absolute paths are
extracted from the command line — operands of known file-reading and file-writing commands,
redirection targets, `cp`/`mv` sources and destinations, `dd if=`/`of=` — and each is evaluated
before the command runs. `cat /etc/shadow` is refused exactly as `read_file /etc/shadow` is, and
`sudo` does not bypass it.

This is best-effort by design: only absolute paths and only recognised commands, because a
relative operand cannot be matched against a pattern without knowing the remote working directory.
`cd /root/.ssh && cat id_rsa` still gets through. It closes the direct form and can only ever
narrow a decision, never widen one.

### Databases, tunnels and VPNs

`query_database` classifies the statement before running it. Reads are governed by
`databaseAccess` alone; anything that modifies data or schema is additionally bounded by
`writeFiles` — a group whose point is that it cannot change anything should not be able to change
a row either — and can never resolve better than ASK. That clamp exists because `databaseAccess`
defaults to ALLOW in every built-in group, so honouring it plainly would have handed a Full Access
agent a silent `DROP TABLE`.

A read cannot smuggle a write behind a semicolon, comments cannot hide the verb, and an
unrecognised verb counts as a write: there are too many dialects to enumerate and guessing
"harmless" is the expensive direction to be wrong in. Mongo shell syntax is classified separately,
since `db.users.find({})` leads with the collection rather than the verb.

`set_tunnel` can only start or stop a tunnel the user has already defined — it cannot create one or
change where an existing one points. Starting always requires approval whatever the group says,
because it binds a listening port on the user's own machine. Stopping does not, being the safe
direction.

`set_vpn` is the same shape one step further out, and gated on `vpnControl` rather than
`sshTunnel`. It can start or stop a VPN profile the user has already defined; it cannot create one
or change where one points, and **there is no `add_vpn` or `edit_vpn` tool** — not an omission to
be filled in later, but a decision, because a profile determines which network everything
downstream of it travels over. Starting is always ASK, even for a group set to ALLOW
(`evaluateVpnControl`, `policyEngine.ts`). Stopping is ASK too whenever live sessions depend on the
VPN, so "close 3 sessions" is never something an agent does quietly.

**Reverse proxies (frp) are refused unconditionally.** An frp proxy makes a port on the user's own
machine reachable from the frp server — which is to say from the internet — and an approval prompt
would not help, because "Start VPN office" is indistinguishable, to the person clicking it, from
consent to publish a port. So it is not a permission an administrator could raise: the refusal is
hard-coded (`AI_REFUSED_VPN_KINDS`, `policyEngine.ts`), the same treatment as unrestricted root
shells, and it applies to stopping as well as starting.

`list_vpns` reports which profiles exist, which engine carries each one, whether it is up, and
frp's per-proxy status table. It never reports an endpoint, a key, or a listener's bind address —
the cached shape it reads from does not contain them at all (`CachedVpn`, `mcpDataCache.ts`), so a
future template string cannot leak one by accident.

### `add_server`

An agent can add an SSH connection, including its credential, when the workspace's access group
grants `manageServers`. Only **Read & Write**, **Sudo Access** and **Full Access** grant it, and all
three set it to ASK, so every add surfaces an approval dialog naming the connection, the user and
the server. The credential itself never appears in that dialog or in the audit log — only the fact
that one was supplied. It goes straight to the OS keychain and cannot be read back through the
bridge.

A capability a saved access group predates — `manageServers`, and now `vpnControl`, for any group
written before the version that introduced it — evaluates as DENY, never as an accidental grant.
On load, built-in groups are backfilled with the value a fresh install would have given them and
custom groups with DENY (`backfillCapabilities`, `policyStore.ts`), so an upgraded install neither
silently gains a permission nor quietly loses a feature with nothing in the UI explaining why.

## Tool discoverability

Descriptions are written to route an agent to the narrowest tool that does the job:

- The server's `instructions` state that servers are addressed by friendly name, that
  `list_servers` must be called first, that credentials are never visible, and which capabilities
  do not exist at all (tunnels, port forwarding, databases) so an agent does not shell out to
  reach them.
- `execute_command` names its four alternatives; `read_file`, `list_files` and
  `get_server_metrics` each say why they are preferable.
- Every `serverName` parameter points back at `list_servers`, because a hostname or IP will not
  resolve.

`tests/toolMetadata.integration.test.ts` asserts all of this through a real MCP client, so a tool
cannot be added without it.

There is no `vault` tool. The MCP server has no code path into the Vault at all — an AI session
cannot read a Vault entry no matter what access group it holds, including when a server's
credential is stored there.

The server also exposes two unauthenticated bootstrap endpoints used only by the CLI pairing flow:
`POST /pair/start` and `POST /pair/confirm` (see [Pairing](#the-shellpilot-cli-and-pairing) below).

## Sessions

![Creating an AI agent session under AI & MCP → AI Agents](images/ai-agents.png)

A session (`McpAgentSession`, `shared/mcp.ts`) is created from **AI & MCP → AI Agents**, or via
CLI pairing. Each one has:

- an **agent name** (a label, e.g. "Claude Code")
- **one or more workspaces**, chosen explicitly — never "all workspaces including future ones"
- exactly **one access-group ceiling**
- an **expiry**: 15 minutes, 1 hour, 8 hours, 7 days, or never (CLI pairing always issues 8 hours —
  `TTL_MINUTES = 480` in `cliPairing.ts`)
- a bearer token, shown **once** at creation

Only the token's SHA-256 hash and a 4-character preview (`tokenPreview`) are ever persisted
(`mcpAuth.ts`) — there is no way to recover a lost token from ShellPilot's own storage. Revoking a
session, or the global **Stop all AI access** switch (Security tab), sets `revoked: true`
immediately; a revoked or expired token fails authentication on its next use.

![Active Sessions: every session that exists, with Revoke and Stop all AI access](images/ai-active-sessions.png)

Sessions are stored at `shellpilot-mcp-sessions.json` in ShellPilot's userData directory.

## Workspaces

A session's workspace grant is a hard boundary, not a filter applied after the fact. A session
can be created with one workspace or several — chosen explicitly at creation, never "all
workspaces including future ones" — and every tool resolves servers against exactly that set:
`listCachedServers(session.workspaces.map(w => w.id))` (`mcpDataCache.ts`) only ever loads servers
belonging to a granted workspace in the first place. A workspace left out isn't denied to the
session — it is invisible, because it's never in the candidate list `serverResolver.ts` searches.

Policy resolution still happens per server, not per session: `serverGroupFor()` (`mcpServer.ts`)
looks up the access group governing a server using **that server's own workspace**, not "the
session's workspace" — which matters once a session spans more than one, since a server's
governing group can differ per workspace even inside the same multi-workspace session.

CLI-paired sessions (`shellpilot claude`/`codex`/`run`) are a special case: there's no workspace
picker at pairing time, so a paired session is granted every workspace that exists at the moment
of pairing (`confirmCliPairing`, `cliPairing.ts`). A session scoped to specific workspaces still
has to be created by hand under **AI & MCP → AI Agents**.

## Access Groups

![Access group capabilities, file path rules, and workspace/server assignment](images/ai-access-groups.png)

An access group (`AccessGroup`, `shared/mcp.ts`) is a policy across **12 capabilities**
(`AI_CAPABILITIES`): view server, execute terminal commands, read files, write files, SFTP
download, SFTP upload, SSH tunnels, database access, sudo/privilege escalation, server metrics,
add servers to the workspace, VPN & reverse proxies. Each is independently `allow`, `ask` or
`deny`.

Four built-in groups ship with ShellPilot (`policyStore.ts`) — **Read Only**, **Read & Write**,
**Sudo Access**, **Full Access** — and every field on them, including capabilities, is editable.
They cannot be deleted (so an assignment referencing one never dangles), but there is no
hard-coded three-tier model underneath; create as many custom groups as you want.

**Two layers always win over policy, no exceptions:**

- **Reverse proxies are hard-refused for AI.** `set_vpn` refuses any profile whose kind is `frp`
  before the access group is consulted (`isVpnKindRefusedForAi`, `policyEngine.ts`). There is no
  capability value, on any group, that reaches past it.
- **Unrestricted shells are hard-denied**, independent of any capability setting. `evaluateCommand`
  (`policyEngine.ts`) checks the command against a fixed pattern list — `sudo -i`, `sudo -s`,
  `sudo su`, `sudo bash`/`sh`/`zsh`/`dash`, bare `su`/`su -` — and returns `deny` before the access
  group is even consulted. There is no ALLOW that reaches this branch.
- **The most restrictive of two applicable groups always wins.** A server/workspace assignment
  decides the *server's* group; the session's own group (chosen at creation) is a ceiling on top
  of that. `effectiveCapability`/`effectiveCommand`/`effectiveFilePath` (`mcpServer.ts`) evaluate
  both and take whichever is stricter (`mostRestrictive`, `policyEngine.ts`) — a session can never
  do more than either side allows on its own.

**File path rules** override the blanket `readFiles`/`writeFiles` capability for specific paths.
Rules are glob patterns (`**` crosses directories, `*` stays within one segment); when more than
one rule matches a path, **the longest pattern string wins** (`evaluateFilePath`,
`policyEngine.ts`) — not "most specific" in any deeper sense, just the longest string. A path
matching no rule falls back to the blanket capability.

**Server & workspace assignment**: an access group has no effect until it's assigned. Assign a
default group per workspace, then override individual servers; a server with no override inherits
its workspace's default, and a workspace with no assignment at all is **No AI Access**
(`resolveGroupId`, `policyEngine.ts`).

![File path rules and per-server/workspace assignment](images/ai-access-groups-assignment.png)

## Approvals

Any capability evaluating to `ask` calls `requestApproval` (`approvals.ts`), which blocks the MCP
tool call on an in-memory pending request — nothing is written to disk until it resolves. The
request only clears when:

- a human clicks **Approve once** or **Deny** on the **Approvals** screen (`respondToApproval`),
- it times out (`approvalTimeoutSeconds` in Security, 1–10 minutes) and is treated as denied, or
- **Stop all AI access** denies every pending request at once (`denyAllPending`).

There is no code path from the MCP/HTTP surface into `respondToApproval` — approving a request
requires the renderer's IPC handler, which only the human-facing UI calls. An agent cannot approve
its own request by construction, not by convention.

## Audit Log

![Audit Log showing agent, workspace/server, action and result](images/ai-audit-log.png)

Every gated action — allowed outright, approved, denied, or failed — is appended to
`shellpilot-ai-audit.jsonl` (`auditLog.ts`) as one JSON object per line, **append-only** (a crash
mid-write can corrupt at most the last line). Every free-text field (`action`, `error`) is passed
through the same redaction (`secretRedaction.ts`) used for tool output before it's written, so the
audit trail itself never becomes a place secrets end up.

## Credential isolation

`credentialResolver.ts` is the only place a server's stored SSH secret is ever read for the MCP
path — the exact same function (`resolveSecrets`/`resolveChainSecrets`) an interactive
terminal/SFTP session uses. The MCP tool handlers never see the resolved value; they build an SSH
config carrying only a `serverId`, and `resolveChainSecrets` fills in the password/key/passphrase
from the OS-keychain-backed store just before connecting. `knownSecretValuesForServer` separately
exposes the *raw values* only to `secretRedaction.ts`, so they can be blanked out of anything that
comes back — never to a response.

Jump hosts resolve independently: every hop in a chain gets its own credential lookup
(`resolveChainSecrets`), so a multi-hop path to a bastion doesn't skip this for the intermediate
servers.

## The `shellpilot` CLI and pairing

`src/cli/index.ts` is a small Node launcher, built to `out/cli/index.js` and wrapped by
`bin/shellpilot.cmd` / `bin/shellpilot.sh`:

```
shellpilot claude            Registers ShellPilot with Claude Code, then launches `claude`
shellpilot codex             Registers ShellPilot with Codex, then launches `codex`
shellpilot run -- <command>  Sets SHELLPILOT_MCP_COMMAND/ARGS, then launches <command>
```

`shellpilot bridge --token <token> --port <port>` is the fourth, internal subcommand these three
configure their target client to run — a pure stdio↔HTTP relay (`src/cli/bridge.ts`) with no
tool/session/policy logic of its own. Whatever client spawns it gets the exact same
authenticated, audited, policy-gated path an HTTP client talking to ShellPilot directly would.

**Pairing** (`getOrPairSession`, `src/cli/pairing.ts`; `startCliPairing`/`confirmCliPairing`,
`src/main/services/cliPairing.ts`) is a device-code-style flow:

1. The CLI `POST`s `/pair/start` with an agent name and gets back a `pairingId` — never a code.
2. ShellPilot generates a random 6-digit code and shows it **only in the ShellPilot window**,
   never over the HTTP response. The code expires in **60 seconds** (`CODE_TTL_MS`).
3. You read the code off your screen and type it into the terminal running the CLI.
4. The CLI `POST`s `/pair/confirm` with the code. **5 wrong attempts** (`MAX_ATTEMPTS`) expires the
   pairing outright; the same code cannot be replayed once accepted.
5. On success, ShellPilot mints a real session (8-hour TTL) in the first workspace with the first
   access group, and hands back the token — which the CLI then caches
   (`~/.config/shellpilot/cli/sessions.json` on Linux, `%APPDATA%\ShellPilot\cli\sessions.json` on
   Windows, `~/Library/Application Support/ShellPilot/cli` on macOS) so it doesn't re-pair on
   every launch.

The property this buys: completing a pairing proves the human at the keyboard can see **both** the
ShellPilot window and the terminal — the same property a TV-app or `gh auth login` device code
relies on, from a physically separate screen. Nothing sent back to the CLI process ever contains
the code, so a local process cannot complete a pairing purely on its own, without a human reading
the code off the ShellPilot window.

## Connecting Claude Code

**AI & MCP → Security** generates the exact snippets below with your real port and token filled
in, and is also where the bridge is enabled/disabled and the approval timeout is set:

![Security tab: enable toggle, port, approval timeout, and connection snippets](images/ai-security.png)

Once you have a token (from **AI & MCP → AI Agents**, or via pairing):

```bash
claude mcp add --transport http shellpilot http://127.0.0.1:<port>/mcp --header "Authorization: Bearer <token>"
```

Or skip the manual token entirely:

```bash
shellpilot claude
```

First run shows a one-time 6-digit code in ShellPilot; type it into the terminal. Every later run
reuses the cached session until it expires.

## Connecting Codex, Gemini CLI and other HTTP clients

Most clients that take a JSON MCP config accept a Streamable HTTP entry:

```json
{
  "mcpServers": {
    "shellpilot": {
      "type": "http",
      "url": "http://127.0.0.1:<port>/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

Two in-app screens can generate this for you, and they differ slightly: **AI & MCP → Security**
includes `"type": "http"` explicitly (as above); the block **AI & MCP → AI Agents** copies right
after you create a session omits it (`url` + `headers` only) — add `"type": "http"` by hand if
your client doesn't auto-detect a Streamable HTTP server without it.

## Connecting Claude Desktop

Claude Desktop is **not** one of those clients, and the HTTP entry above will not work in it.

Entries under `mcpServers` in `claude_desktop_config.json` are launched as stdio subprocesses —
Desktop reads `command`/`args`/`env` there and ignores `url` and `headers` entirely. Its
remote-MCP support is a separate, account-level Connectors feature that expects a publicly
reachable server with OAuth, and offers no field for a bearer token against `127.0.0.1`.

Use the stdio bridge instead. `shellpilot bridge --token <token> --port <port>`
(`src/cli/bridge.ts`) is a pure protocol relay: stdio in, Streamable HTTP out, `Authorization`
header attached on the way. No tool, session or policy logic lives in it, so a stdio client is
subject to exactly the same Access Group checks, approval prompts and audit entries as an HTTP
one.

1. Create a session under **AI & MCP → AI Agents** and copy its token (shown once). Set
   **Expires** to *Never* — a Desktop client has no way to re-pair when a token lapses.
2. Add this to `claude_desktop_config.json`
   (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS,
   `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "shellpilot": {
      "command": "/Applications/ShellPilot.app/Contents/MacOS/ShellPilot",
      "args": [
        "/Applications/ShellPilot.app/Contents/Resources/app.asar.unpacked/out/cli/index.js",
        "bridge", "--token", "<token>", "--port", "<port>"
      ],
      "env": { "ELECTRON_RUN_AS_NODE": "1" }
    }
  }
}
```

   On Windows the two paths are `%LOCALAPPDATA%\Programs\ShellPilot\ShellPilot.exe` and
   `%LOCALAPPDATA%\Programs\ShellPilot\resources\app.asar.unpacked\out\cli\index.js`.

3. Restart Claude Desktop.

`ELECTRON_RUN_AS_NODE=1` runs ShellPilot's bundled Electron binary as plain Node, so the bridge
needs no separate Node install and does not depend on `PATH` — which Claude Desktop does not
inherit from a login shell. `out/cli/**` and `bin/**` are kept outside the asar archive
(`asarUnpack` in `electron-builder.yml`) precisely so they can be spawned as real files.

**AI & MCP → Overview → Connect Claude Desktop** writes this block for you, filling in the paths
and a fresh token; the manual steps are here for anyone who would rather see what it does.

If you lose the token before pasting it, there's nothing to recover — revoke that session under
**Active Sessions** and create a new one.

Codex specifically can also be wired up with `shellpilot codex`, which splices a
`[mcp_servers.shellpilot]` block into `~/.codex/config.toml` (`registerCodexMcp`,
`src/cli/agents.ts`) inside a marked, safely-removable region, the same way `shellpilot claude`
calls `claude mcp add`.

`shellpilot run -- <command>` works for anything else that reads
`SHELLPILOT_MCP_COMMAND`/`SHELLPILOT_MCP_ARGS` environment variables to find an MCP server to
launch.

## Troubleshooting

**"Could not reach ShellPilot on 127.0.0.1:`<port>`."** — ShellPilot Desktop isn't running, or
**AI & MCP → Security → Enable AI & MCP access** is off. If it's on a non-default port, set
`SHELLPILOT_PORT` before running `shellpilot claude`/`codex`/`run`.

**"This token is not recognized" / "revoked" / "expired."** — The session behind that token was
deleted, revoked (individually or via Stop all AI access), or its expiry passed. Create a new
session, or re-run `shellpilot claude`/`codex` to re-pair.

**"No AI access is assigned to this server."** — The server's workspace has no access-group
assignment (defaults to No AI Access), and there's no server-level override either. Assign one
under **AI & MCP → Access Groups → Server & workspace assignment**.

**A `sudo` command is denied even though the access group allows sudo.** — Check whether it
matches an unrestricted-shell pattern (`sudo -i`, `sudo su`, `sudo bash`, plain `su`, ...) — those
are denied unconditionally, independent of the group's `sudo` capability.

**Connecting from inside WSL to a ShellPilot instance running on Windows.** — The bridge only
binds to `127.0.0.1`, so WSL2 needs to actually reach the Windows loopback address. If a request
from WSL to `127.0.0.1:<port>` times out or is refused even though ShellPilot is running on
Windows, check `wslinfo --networking-mode`: `mirrored` networking mode shares the network
namespace directly and is the most reliable option; if `.wslconfig` requests `networkingMode=mirrored`
but this still reports `nat`, run `wsl --shutdown` from **Windows** PowerShell (not from inside
WSL) and reopen your WSL terminal.
