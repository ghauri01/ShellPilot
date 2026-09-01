# ShellPilot roadmap

Sixteen things we intend to build, what each one actually rests on in the code today, and what is
genuinely hard about it. Written after 0.8.0.

Items 1–10 were the original list. **Items 11–16 were not, and five of the six outrank most of what
was** — they came out of asking what changes when one person runs fifteen servers instead of three,
which is the actual user, and then reading the code to check the answers.

Item 16 was the one to read first: not a feature, but the reason two of the highest-ranked features
could not be built at all — which the first version of this document ranked around without noticing.
It has since been built, and this document keeps the finding rather than quietly deleting it,
because "we ranked a blocked item first" is the kind of thing worth remembering the next time an
ordering looks obvious.

The ordering at the end is the useful part of this document; the write-ups exist so that ordering
can be argued with.

This is a statement of direction, not a schedule. Sizes are rough and relative — "weeks" means a
focused person, not a calendar quarter. Where something is a real unknown it says so rather than
guessing, because the cost of a wrong estimate here is a commitment nobody can keep.

## Built since this was written

On `main`, not yet released. Kept here rather than deleted, because the write-ups say why each
was built and that reasoning outlives the ticket.

| Item | State |
|---|---|
| **16. Background metrics sampling** | **Built.** `fleetSampler.ts` in main, scheduled, survives the monitor being closed. Off by default. |
| **3. Alert channels** | **Webhook built** — generic HTTPS JSON POST, which is what Slack, Discord and Teams all accept. Named integrations for WhatsApp and Twilio are not built and may never need to be. |
| — | **Failed-unit alerts**, which were not on this list and are the case that prompted it: four failed units found by opening the app and looking. A failed unit does not move a CPU graph, so no threshold would have caught it. |
| **13. Fleet-wide search** | **Built.** Searches units, ports and hosts across the workspace from data the sampler already had and discarded. Reports what it could NOT search — never sampled, no systemd, no port probe, gone unreachable — because results without that gap are a lie by omission. |
| **11. Run one command across many servers** | **Built.** Approval model settled and tested first: confirmation scales with blast radius, nothing is safe by omission, cancel means queued hosts never start. Three at a time. Not exposed to the MCP bridge. |
| **12. Live log tailing across hosts** | **Built.** journalctl or tail -F, several hosts interleaved and colour-keyed. The remote command is built from a validated source and never from user text. |
| **6. Cron, read-only** | **Built.** Crontabs, /etc/cron.d and systemd timers across the estate. Read-only until the parser is proven — the user-field trap is a silent misread, not an error. |

Two things those unlocked, now unblocked rather than done: **fleet-wide search** (item 13) can now
index a complete estate rather than whatever was last looked at, and any future scheduled work has
a scheduler to live in.

### What the pre-release review changed

Three adversarial reviewers went over both features before release and returned about thirty
findings. Two patterns account for most of them, and both are worth remembering rather than
just fixed.

**The main process was built carefully and the renderer used only its happy path.** `fleet.status()`,
`fleet.sampleNow()`, `webhook.delivery()`, `clearUnitAlerts()`, `useFleet.forget()` and
`clearServer()` were each wired through IPC with a docstring saying what they prevented, and each
was called from nowhere. The settings screen showed a webhook as healthy while alerts were being
dropped; the monitor rendered nothing on first run; a deleted server kept counting in the status
bar. None of that was visible from the main-process side, where everything looked complete.

**Four tests asserted only negatives or literals, and each passed against the bug it was written to
catch.** One checked a packaging glob by asserting the pattern string rather than running it — the
pattern matched nothing and shipped two Windows binaries that should not have been there. Every fix
in this round was verified by reverting it and watching its test fail, and one new test had to be
tightened when that check showed it passing against the bug (`toContain` on an array is exact
equality, so a forged line with a trailing suffix slipped past it).

Two defects were already live in 0.8.0. `get_server_metrics` passed systemd unit descriptions,
process names and the kernel string to the agent verbatim through a `readOnlyHint` tool that needs
no approval — an injection channel from any host under an attacker's control. And the capability
grid still said "Server metrics" after that tool began returning a full service and port inventory,
so consent had been given for something narrower than what was taken.

### Measured against a real estate, 2 Sep

Run on the author's own machine against two live hosts, background checking on at a 2-minute
cadence. 174 samples over ~45 minutes, counting ShellPilot's own sockets by PID.

| | |
|---|---|
| Additional connections from background checking | **none** |
| Steady state | 1 connection per server, shared with the foreground monitor |
| Held with zero foreground sessions | yes, indefinitely |
| `sshMasterIdleMinutes` (set to 15 min) applied | **no** — as the settings rows now disclose |
| Main-process RSS | 125–151 MB |

The pool keys on `srv:${serverId}` (`hopKey` in ssh.ts), so the monitor, the sampler and the MCP
bridge share one connection per server rather than opening three. Sessions were closed at 00:52 and
the connections were still up at 01:08, past the 15-minute idle setting — the refcount never reaches
zero, so the idle timer is never armed. That is now measured rather than argued.

**What this does NOT answer.** Two hosts, direct, no bastion. The open question was fifteen hosts
behind jump boxes, and a chained hop pools *per hop* — so bastion load scales differently and none of
this measures it. Treat the zero-additional-connections result as true for direct estates and
unproven for chained ones.

**Two findings came out of running it, both shipped.** Background checking was silently paused on a
locked vault, with the only indication one line in a Settings pane nobody opens — now a status-bar
chip. And the alert-threshold row claimed "alerts fire wherever you are in the app" while the
sampler sat paused, because it read the setting rather than the running state. Neither was findable
by reading the code.

**Not verified against a real estate.** The sampler has unit tests and the webhook has been proved
against a live local endpoint, but nobody has yet turned background checking on with fifteen hosts
behind bastions and watched what happens to connection count, bastion load or battery. That is the
decision item 16 flagged and it needs a real fleet to answer.

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

## The prerequisite the roadmap was ranking around without seeing — now built

### 16. Background metrics sampling — BUILT

Sample the estate on a schedule from the main process, independently of what the renderer is
rendering.

**This was not a feature. It was why two features above could not be built at all**, which the
first version of this document ranked without noticing. Built; the write-up below is kept as the
reasoning, in the past tense where it describes what was wrong.

**The problem.** `App.tsx` renders the Fleet Monitor as `{activity === 'monitor' && <FleetMonitor />}`.
Leave that tab and every `ServerMonitorCard` unmounts, `useServerMetrics` stops, and sampling ends.
The `useFleet` store says so in its own comment: *"Every value here came from a sample some other
component already paid for."* Fleet data exists only while someone is looking at it.

So **alerts are not unbuilt, they are impossible**: you cannot notify a person about a failure you
only detect while they are staring at the screen that would have shown it. `checkResourceAlerts`
already exists in `store/alerts.ts` and is called from that same renderer loop — the alerting logic
is written and just as trapped as the sampling. And **fleet-wide search** would index whatever
happened to be sampled recently rather than the estate.

**What exists.** More than half of it, in the right place. `metricsSample()` lives in main, is
already called from the MCP path under its own `mcp:${id}` key, dedupes in-flight calls, caches
briefly, and returns a full `HostMetrics`. The connection pool is already shared with SSH sessions.
The renderer's chained-not-interval polling — wait for one sample to land before scheduling the
next, so a slow link cannot queue polls faster than they finish — is the right design and should
move rather than be rewritten.

**What is actually new.** A scheduler in main, a per-server opt-in, and pushing results to the
renderer instead of the renderer pulling them.

**The decision this forces, and it should be made deliberately.** Sampling fifteen servers on a
timer means the app maintains connections to the whole estate whether or not anyone is looking.
That changes battery use, bastion load and audit noise, and it needs the vault unlocked to resolve
credentials at all — so a locked vault has to degrade to "not sampling" rather than to an error
loop. Background cadence should be far slower than the 2s a focused view uses; the interesting
number is minutes, not seconds.

**Size.** 1–2 weeks. Unblocks items 3 and 13, and gives items 6 and 12 a scheduler to live in.

---

## The fleet gap — what fifteen servers need that three do not

These were not on the original list and belong near the top of it. They share a shape: each is
about the *estate*, and each is invisible until the server count passes roughly ten. The reference
user runs ~15 hosts behind two jump boxes, across prod, staging and database tiers.

### 11. Run one command across many servers

Select a group — a tag, a workspace, a hand-picked set — and run one command against all of it, with
the results readable side by side.

**Why it is the largest gap on this page.** It is the defining problem of managing fifteen servers
instead of three, and nothing else here touches it. "Check disk on every prod box", "restart nginx
on the three web servers", "which of these has the old package" is fifteen tabs and fifteen pastes
today. MobaXterm has multi-exec and Termius has it; a tool positioned against both cannot not have
it.

**What exists.** More than it looks. `execute_command`, the policy engine, approvals and the audit
log are all per-server already, and the supervisor gives a model for running many things at once
and collecting their output. Fan-out is orchestration over machinery that exists.

**What is actually new, and it is not the execution.** It is the results view — fifteen outputs that
have to be scannable, with "same on all twelve, different on these three" as the primary reading
rather than a wall of text. And it is the safety model, which deserves more thought than the
feature: one approval for fifteen hosts is a categorically different decision from fifteen
approvals, and a command aimed at a tag that silently acquired a production box is exactly how
outages happen. Dry-run, an explicit resolved target list shown before execution, and a hard stop on
first failure as the default all matter more than throughput does.

**Size.** Weeks for a solid version. The policy question is worth settling before any of it.

### 12. Live log tailing across hosts

Follow a file, a unit or a container across several servers at once, merged and filtered.

**Why.** The Fleet Monitor now says `uwsgi` failed. It cannot say why, and "why" is the next thing
anyone asks. `tail -f` on one box is easy; merged, filtered, colour-coded tailing across three web
servers is the daily reality of running a tier, and no GUI client does it well.

**What exists.** The streaming half. The SSH data plane already handles continuous output with
coalescing and backpressure, and `TerminalTransport` is the right abstraction to hang this on.

**What is actually new.** Merging streams with per-host attribution, filtering that does not lose
the stream while you type, and bounded buffers so a chatty host cannot exhaust memory. Also a
decision about `journalctl` versus files versus `docker logs`, which is really the same target
model that items 4 and 6 need.

**Size.** Weeks.

### 13. Fleet-wide search

"Which host has port 5432 open?" "Where is this unit running?" "Which boxes have this process?"

**Why this one is nearly free, and worth more than it sounds.** The Fleet Monitor *already collects*
every listening socket with its owning process and every systemd unit on every reporting host, on
every sample. That is a searchable index of the estate that exists in memory and is thrown away
after being rendered as a table. Exposing it is a small feature that makes the data already being
gathered worth gathering — and it is the kind of thing nobody else has, because nobody else is
already holding the data.

**What is actually new.** An index and a query surface. Note the honest limits up front: it reflects
the last sample, not the present, and a host that could not report is a gap in the answer rather
than an absence of the thing — the same `null`-is-not-empty distinction the monitor already respects
must survive into search results, or the feature will confidently tell someone a port is closed.

**Size.** Days to weeks. The best value-to-effort ratio on this page.

### 14. Human session audit

A record of what *you* did — commands run, files changed, on which host, when.

**Why.** There is a meticulous audit log for what agents did and nothing for what the operator did.
"What did I change on Tuesday" is a real question during an incident, and for anyone in a regulated
environment it stops being a convenience and becomes a procurement requirement.

**What exists.** `auditLog.ts`, the redaction pipeline, and — from 0.8.0 — the precedent of a
*separate* log file for a different question, since local terminal sessions already write to
`shellpilot-local-sessions.jsonl` rather than polluting the AI log.

**What is actually new.** Deciding what is recorded, and being conservative. Commands and targets,
yes. Full terminal output, no: it is enormous, it is full of secrets that redaction will not
reliably catch, and a log of everything a person's shell printed is a more attractive target than
most of what it was meant to protect. This should follow the local-session log's shape — metadata,
never content — and it should be off by default with a clear switch, because recording a person's
work is a different consent question from recording an agent's.

**Size.** Weeks, most of it deciding what not to store.

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

### 15. A plugin system — so nobody ships or runs what they do not use

Not every user needs Kubernetes, or n8n, or five database drivers. The app should not carry them for
everyone.

**Separate the two things this phrase usually means, because only one of them is cheap.**

**(a) Optional first-party modules.** Features that ship with the app but are off until enabled, and
whose weight is not paid until they are. This is what "we don't want to ship bloatware" actually
asks for, and it introduces no new trust boundary — the code is still ours, still reviewed, still in
the repo. It is achievable now.

**(b) A third-party extension API.** Code we did not write, running inside the app. This is what
"plugin system" usually means and it is a fundamentally different proposition here, for a reason
specific to this product: ShellPilot's entire thesis is that credentials never leave it. A plugin
that can call `credentialResolver` is a vault with no lock, and an ecosystem where the answer to
"can I trust this extension" is "read its source" is not a security model. Not impossible — it needs
a real sandbox and a capability-scoped API — but it is a product in itself, not a refactor.

**Do (a) first, and do not let it drift into (b) by accident.** The two share a registry and almost
nothing else.

**What (a) actually costs.** Less than it looks, because the pieces exist:

- **Gating is already a solved pattern here.** `AI_CAPABILITIES` plus the policy engine is a working
  model of "this surface is available, this one is not", including the important default: an absent
  capability reads as denied rather than as permitted. A module registry can borrow that shape
  directly, including `backfillCapabilities`'s rule that a new thing does not silently switch itself
  on for existing installs.
- **The UI already hides what does not apply.** The activity bar, the tab kinds and the viewbar all
  branch on what a tab or workspace supports. A disabled module is one more branch, not a new
  mechanism.
- **Lazy loading is already how the risky thing loads.** `localPty.ts` imports `@lydell/node-pty`
  inside `loadPty()`, on first use, so a machine where it cannot load still gets a working app. That
  is exactly the pattern a module needs.

**What is actually new, and it is the interesting half: weight that is not paid.** Toggling a
feature off in the UI does not shrink the installer. Today's ~120 MB is mostly Electron, but the
five database drivers — `pg`, `mysql2`, `mssql`, `mongodb`, `ioredis` — are bundled for everyone,
and something like n8n or a Kubernetes client would dwarf all of them. Real modularity means heavy
dependencies are **fetched on enable rather than bundled**, and that is a supply-chain decision, not
a packaging one: a download at runtime needs a pinned version, a checksum and a signature, or it is
a remote-code-execution feature with a friendly button. The good news is that the pattern already
exists — `resources/bin/manifest.json` plus `resolveBundled()` verifies a SHA-256 before executing
any engine binary, on every run. Extend that, do not invent something new beside it.

**The rule that must hold whatever gets built.** A module may not read the vault, resolve
credentials, register an MCP tool without a policy entry, or reach the local terminal. Those are the
four things the security model is made of, and `tests/localTerminalNotExposed.test.ts` already shows
how to enforce a boundary like that by walking the real import closure rather than trusting a
convention.

**Interaction with Tauri.** Doing (a) well *helps* item 10 — clean module boundaries with no
Electron API bleeding into feature logic is exactly the precondition a port needs. Doing (b) first
would harm it badly: a third-party extension API is a compatibility promise, and rewriting the host
underneath one is how migrations die.

**Size.** (a) is weeks for the registry and the UI, plus real time per module to actually separate
it. (b) is quarters and should not be scheduled until (a) has shipped and someone has asked for it
with a concrete use case.

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

Ordered for the user this app is actually for: someone running a real estate from one machine —
roughly fifteen hosts behind jump boxes, across prod, staging and database tiers. That user changes
the ranking, and the biggest change is that **the three highest-value items were not on the original
list at all.**

**First — stop making the operator go and look.**

1. ~~**Background metrics sampling (item 16).**~~ **Built.** Was the prerequisite: alerts could not
   be built at all until the app sampled when nobody was watching. It reached the front of this list
   only after reading the code — the first version ranked alerts first without noticing they were
   blocked.
2. ~~**Alert channels, generic webhook first.**~~ **Built**, along with failed-unit alerts, which
   were not on this list and are the case that actually prompted it. Named Slack/WhatsApp/Twilio
   integrations remain unbuilt and may stay that way: they all accept a webhook.
3. ~~**Run one command across many servers.**~~ **Built.** The approval model was settled and
   tested before the executor, as this said to do. Both inputs count: a destructive command on one
   host needs typed confirmation because the command is the danger; an ordinary command on twelve
   hosts needs it because the count is.
4. ~~**Fleet-wide search.**~~ **Built**, and it did ship before 3 as this predicted. The value was
   where this said it would be — the data was already in memory — but the work was not in matching,
   it was in reporting honestly what could not be searched.

**Then — answer the question the monitor raises but cannot.**

5. ~~**Live log tailing across hosts.**~~ **Built.**
6. ~~**Cron, read-only.**~~ **Built.** Read-only did prove the parsing: two silent misreads were
   found by writing the tests, and both would have been invisible in a UI — a six-word sentence
   parsed as a job, and a schedule described by the fields it understood while skipping the one that
   decided when the job actually ran.

**Next, and now the front of the list.** Cron *editing* is the natural follow-on and is deliberately
not automatic: the read-only parser has been proven against fixtures, not against a real estate, and
the whole argument for shipping it read-first is that it should be run against real crontabs before
anything writes. After that, the plugin system (item 15) is still best done before Docker/k8s/n8n so
those arrive as modules rather than being retrofitted.

**Then — reduce weight, and pick up the rest.**

6. **Optional first-party modules (plugin system, part a).** Best done before Docker/k8s/n8n land
   rather than after, so those arrive as modules instead of being retrofitted into them.
7. **Docker** — the transport abstraction is already the right shape. Kubernetes later and
   separately; contexts and RBAC are their own product.
8. **Credential proxy** — move this up if API keys are already a live problem; it is the most
   strategically aligned item on the list either way.
9. **Backups to remote targets** — after cron, so there is one scheduler.
10. **Human session audit, ngrok-style frp UX, cron editing** — real, none of them urgent for a
    single operator.
11. **pm2-style monitoring** — kept, but **deliberately demoted from where a generic ranking puts
    it**. Remote processes are systemd units the Fleet Monitor already reads; supervising them
    ourselves largely re-solves a solved problem. Its value here is as *plumbing* for other features
    rather than as a feature. It rises sharply for a user whose workloads are local.
12. **Ghostty snapshot experiment, n8n, third-party extension API, Tauri** — each behind a gate
    stated in its own section, and none of them visible to a fleet operator's day.

**Dependencies worth stating plainly.** Backups should follow cron, or the app grows two schedulers.
Alert channels should follow the credential proxy if that is going to own third-party API keys, or
they grow two credential stores. Modules should precede the heavy features, or they become a
refactor instead of a shape. And the third-party extension API should never precede the Tauri
decision, because an extension API is a compatibility promise and rewriting the host underneath one
is how migrations die.

**One caveat on all of the above.** This ordering assumes the reference operator: many hosts, mostly
systemd, mixed prod and staging, one person. A team of five reorders it — human session audit and
shared runbooks rise immediately. A containerized estate moves Docker and Kubernetes to the top. The
ordering is a consequence of the user, not a property of the features.
