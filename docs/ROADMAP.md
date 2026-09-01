# ShellPilot roadmap

Ten things we intend to build, what each one actually rests on in the code today, and what is
genuinely hard about it. Written after 0.8.0.

This is a statement of direction, not a schedule. Sizes are rough and relative — "weeks" means a
focused person, not a calendar quarter. Where something is a real unknown it says so rather than
guessing, because the cost of a wrong estimate here is a commitment nobody can keep.

## The through-line

ShellPilot is becoming the place a small team operates its infrastructure from: shells, files,
databases, tunnels and secrets in one window, with AI agents able to act through it without ever
holding a credential. Almost everything below is that same sentence extended to another kind of
target — a container, a scheduled job, a process, a workflow — or to another kind of consumer.

Two properties are not negotiable as this grows, because they are what the app is:

- **Credentials do not leave the app.** Every feature that touches a remote thing resolves its
  secret inside `credentialResolver.ts` and hands the caller a connection, never a password.
- **Anything an agent can drive is gated and audited.** A new capability means a new entry in
  `AI_CAPABILITIES`, a policy decision, and an audit row — or an explicit, tested decision that the
  surface is human-only, the way the local terminal is.

---

## Near term — mostly assembly, not invention

These three are largely UI and glue over machinery that already exists and is already tested. They
are first because the ratio of value to new risk is the best on this list.

### 1. pm2-style process monitoring, local and remote

Run, watch, restart and read the logs of long-lived user processes — a dev server, a worker, a
one-off script — on this machine or on any server already configured.

**What exists.** Nearly all of it, in a place nobody would look for it. `vpn/supervisor.ts` was
built to keep VPN engines alive and already implements the entire pm2 core: exponential backoff with
jitter, crash-loop detection over a rolling window, restart policies (`never` / `on-failure` /
`always`), readiness probes, optional periodic health checks, a bounded in-memory log ring, PID
records that survive an app restart, and orphan reaping on launch. `SupervisedSpec` is a general
process description that happens to be used for VPN.

**What is actually new.** Lifting `Supervisor` out of `vpn/` and generalising the naming; a
persistent process list; a UI; and the remote half — the supervisor spawns locally, so remote
processes need either an agent-side runner over SSH or a `systemd --user` / launchd translation. The
remote design is the real decision, and it is worth taking slowly: shipping "we run your process
over an SSH channel we hold open" is a promise about reliability the current transport does not make.

**Size.** Local: weeks. Remote: materially more, and gated on the design question above.

### 2. ngrok-style tunnel UX over frp

"Give me a public URL for localhost:3000" as one action, rather than a form with a bind address, a
remote port and a server to run it on.

**What exists.** All of the transport. frp shipped in 0.8.0 with its own manager, profile form,
proxy editor and supervised lifecycle. This item adds no networking.

**What is actually new.** The UX, and the honesty around it. ngrok's magic is that it owns the
public endpoint; frp does not, so somebody has to point a domain at a server they control. The
feature is only pleasant if we make that setup a guided one-time thing and then never mention it
again. There is also a real safety question — publishing a local port to the internet from one
click deserves the same treatment `vpnControl` already gets, which is why frp is refused to agents
entirely today.

**Size.** Weeks, almost all of it design.

### 3. Alert channels — Slack, WhatsApp, Twilio, webhooks

Send what the Fleet Monitor already knows somewhere a person will see it when the app is closed.

**What exists.** The signal. `hostHealth.ts` already decides what needs attention — failed units,
disk pressure — and `get_server_metrics` reports the same. Desktop notifications exist, but only for
MCP approval requests (`main/index.ts:586`).

**What is actually new.** Outbound delivery, and everything that comes with it: per-channel
credentials in the vault, retry and rate limiting, deduplication so one flapping unit does not send
two hundred messages, and an explicit decision about what a message may contain. That last one is
load-bearing — an alert naming a host and a unit is useful; an alert carrying a log line can carry a
secret out of the app to a third-party API, and `secretRedaction.ts` exists precisely because that
is easy to get wrong.

**Size.** Weeks for one channel, then days each. Start with a generic webhook: it is the one that
cannot be wrong about anyone's API, and Slack is a webhook.

---

## Natural extensions of what 0.8.0 shipped

### 4. Docker and Kubernetes

List containers and pods, exec into them, read logs, see state — against a local daemon or any
configured server.

**What exists, and it is the important part.** `TerminalTransport` (`renderer/src/lib/transport.ts`)
was introduced in 0.8.0 to make the terminal indifferent to what is on the other end. It has two
implementations today, SSH and local. `docker exec -it` and `kubectl exec -it` are both "a PTY over
a channel", which is the same shape. A container shell should be a third implementation and a new
`PaneTarget` variant, not a new terminal.

**What is actually new.** Discovery and state — container and pod listing, contexts and namespaces,
image and restart metadata — plus deciding whether we shell out to the `docker` and `kubectl`
binaries or speak the APIs. Shelling out is far less work and inherits the user's existing auth,
including cloud provider plugins we would otherwise have to reimplement; it costs us structured
errors and a dependency on binaries being present. The policy surface is not free either: a
capability that lets an agent exec into a container is a capability to run code on a host.

**Size.** Docker: weeks. Kubernetes meaningfully more — contexts, namespaces and RBAC are a product
in themselves, and doing it badly is worse than not doing it.

### 5. Backups to and from multiple targets

Encrypted backups to somewhere other than a local file, and restore from any of them.

**What exists.** The hard half. `backup.ts` already does password-derived encryption, export,
inspect-before-import and import, over the whole persisted store. The format and the crypto do not
change.

**What is actually new.** Destinations — SFTP to a configured server, S3-compatible object storage,
a local directory, a network share — plus scheduling, retention, and restore-from-remote. Two things
deserve care: a backup contains the vault, so where it lands is a security decision the UI must make
obvious rather than bury; and an automatic backup is a scheduled job, which is item 6, so these two
should be built in that order or they will grow two schedulers.

**Size.** Weeks. Less if it lands after cron.

### 6. Cron and scheduled jobs, local and remote, across OSes

See, create and edit scheduled work on any target, without remembering which of four mechanisms that
box uses.

**What exists.** The execution path — `execute_command` over SSH, policy, approvals and audit — and
now local shells too.

**What is actually new.** Four different systems behind one model: crontab on Linux and macOS,
systemd timers where they are preferred, launchd on macOS for anything user-scoped, and Task
Scheduler on Windows, which is XML over `schtasks` and shares nothing with the others. Reading is
already awkward; *editing* is where this gets dangerous, because a bad write to a crontab is a
silent outage and a bad `schtasks` invocation is worse. Round-tripping a file we did not write,
preserving comments and unfamiliar syntax, matters more here than the UI does.

**Size.** Read-only across all four: weeks. Safe editing: significantly more, and the honest
sequencing is to ship read-only first and let it prove the parsing before anything writes.

---

## New subsystems

### 7. API credential proxy

Let a process — a script, a dev server, an AI agent — make authenticated calls to a third-party API
without ever holding the key. ShellPilot injects the credential at the boundary and logs the call.

**Why this one matters more than its position suggests.** It is the same idea the app is already
built on, pointed at a new class of secret. `docs/AI-SECURITY.md` says an agent never receives an
SSH password or a database credential because ShellPilot resolves it server-side; this extends that
sentence to API keys, which is where most of the leakage risk in an AI-assisted workflow actually
lives. It also composes with everything above — the alert channels in item 3 need credentials, and
this is where they should live.

**What exists.** The vault, `credentialResolver.ts` with its vault/keychain/inline sources, the
policy engine, the audit log, and `knownSecretValuesForServer` for redaction. The storage and the
gating are done.

**What is actually new.** A local HTTP proxy that rewrites outbound requests, per-destination rules
about which credential applies, and TLS interception or an explicit base-URL rewrite. That choice is
the whole design: interception is transparent and requires trusting a local CA; rewriting is honest
and requires the caller to opt in by pointing at us. **Recommend the rewrite.** A tool whose pitch
is "your secrets never leave" should not ship a CA into the user's trust store.

**Size.** Weeks for the rewrite model. The interception model is a different and larger product.

### 8. Ghostty for local shells

**Read this one carefully, because the obvious version of it is not the useful one.** A feasibility
study before 0.8.0 established, by inspection of the shipped artifacts:

- **libghostty-vt contains no PTY.** Zero pty/spawn/exec symbols across its 30 public headers, zero
  PTY functions among the 189 exports of its WASM build. It is a VT parser and terminal state
  machine. It does not replace `node-pty` and cannot; cmux pairs it with `portable-pty` for exactly
  this reason.
- **The full libghostty renderer cannot be embedded in Electron.** Its platform enum admits macOS
  and iOS only, and its surface type is an `NSView`.

So "local shell support with ghostty" cannot mean swapping out how we spawn shells. What it can
mean, and where there is real value:

**A WASM libghostty-vt in the main process for terminal state, behind a flag.** It is a 262 KB
gzipped, zero-import module — no native code, no signing, no per-platform binary — and it ships
`snapshot.h`: CRC-protected binary encode and restore of complete terminal state, scrollback and
unfinished parser input included. That is precisely the primitive session restore and
detach/reattach need, and xterm.js has no equivalent; the alternative is replaying raw bytes.

**What is actually new.** Hand-written FFI against an API whose authors say it will change without
warning, and a decision about what owns terminal state. Keep xterm.js rendering in the renderer
regardless — it works, and replacing it buys nothing this list needs.

**Size.** A scoped experiment first. Do not start it as "adopt ghostty"; start it as "can we
serialise and restore a session", which is a question with an answer.

### 9. n8n embedded for workflow management

Visual workflow automation inside the app: on this alert, run that command, then call that API.

**Be clear-eyed about what embedding means.** n8n is a full Node application with its own database,
its own auth, its own editor UI and a large dependency tree. "Embedded" realistically means running
it as a supervised sidecar process and framing its web UI, not linking a library. That is
achievable — the supervisor from item 1 is exactly the right tool for keeping it alive — but the
result is two applications sharing a window, with two update cadences, two security models and two
sets of stored credentials.

**The question to answer before any code.** Is the value in n8n specifically, or in "if this, then
that" over ShellPilot's own primitives? Because items 1, 3 and 6 together already give alerts,
scheduling and execution, and a small purpose-built rule engine over those would integrate with the
policy layer, the audit log and the vault — none of which an embedded n8n will do without
significant bridging. Licensing needs checking too: n8n is fair-code under the Sustainable Use
License, not open source, and bundling it in a distributed app is a question for a lawyer rather
than for us.

**Size.** Large, and the largest part is not engineering.

---

## The one that changes every estimate above

### 10. Migration to Tauri

Replace Electron with Tauri: a Rust backend and the OS webview instead of a bundled Chromium.

**The case for it is real.** Installers drop from ~120 MB to a fraction of that. Memory footprint
falls. A Rust core is a better place for the privileged work this app does — the supervisor, the
PTY layer, the VPN engines — than a Node main process. Several of the sharper problems in 0.8.0 —
native modules under a hardened runtime, `spawn-helper` and asar unpacking, per-architecture
prebuilds — simply do not exist in that world.

**The cost is the whole main process.** `src/main` is not a thin shell: SSH and SFTP over `ssh2`,
five database drivers, the MCP server, the vault and OS keychain integration, the VPN subsystem with
its privileged helpers and elevation paths per platform, the supervisor, metrics parsing, the policy
engine, the updater. That is the majority of roughly 48,000 lines of TypeScript, and almost none of
it ports — it is rewritten in Rust against different libraries with different behaviours. The
renderer largely survives; everything under it does not.

**And the webview is not Chromium.** WebKit on macOS, WebView2 on Windows, WebKitGTK on Linux — with
per-platform rendering differences the terminal, which is performance-sensitive and pixel-sensitive,
will find first.

**How to hold this.** Not as a scheduled item, and not as something to start "when there is time",
because started halfway it doubles the maintenance surface indefinitely. Treat it as a standing
direction with two gates: (a) new privileged subsystems get designed so their logic could move —
clear boundaries, no Electron API bleed into business logic; and (b) it becomes a real project only
when someone has ported one hard subsystem end to end — the VPN engine supervisor is the right
candidate — and measured what it actually cost. Anything before that measurement is a guess about a
year of work.

**Size.** Quarters, and it invalidates the estimate on everything else while it is in flight.

---

## Suggested order, and why

1. **pm2-style monitoring (local)** — the machinery exists; it proves the general supervisor.
2. **Alert channels, webhook first** — makes every monitoring feature useful when the app is closed.
3. **ngrok-style frp UX** — pure UX over shipped transport; high visible value, low risk.
4. **Cron, read-only** — proves the parsing before anything writes.
5. **Docker** — the transport abstraction is already the right shape.
6. **Backups to remote targets** — after cron, so it uses one scheduler.
7. **Credential proxy** — strategically the most aligned; slot earlier if API-key handling becomes
   the pressing problem.
8. **Cron editing, Kubernetes, ghostty snapshot experiment** — each gated on what the item before it
   taught us.
9. **n8n** — after the "build or embed" question has an answer.
10. **Tauri** — behind the port-one-subsystem gate, always.

Two dependencies worth stating plainly: **backups should follow cron** or the app grows two
schedulers, and **alert channels should follow the credential proxy** if the proxy is going to own
third-party API keys, or they will grow two credential stores.
