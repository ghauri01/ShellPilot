# ShellPilot roadmap

Sixteen things we intended to build, what each one actually rests on in the code today, and what is
genuinely hard about it. Written after 0.8.0, and maintained since: 0.9.0 through 0.9.3 shipped
nine of the sixteen, and 0.9.4 through 0.9.7 were stability releases, and this document keeps their write-ups rather than deleting them, because the
reasoning outlives the ticket.

Items 1–10 were the original list. **Items 11–16 were not, and five of the six outrank most of what
was** — they came out of asking what changes when one person runs fifteen servers instead of three,
which is the actual user, and then reading the code to check the answers.

Item 16 was the one to read first: not a feature, but the reason two of the highest-ranked features
could not be built at all — which the first version of this document ranked around without noticing.
It has since been built, and this document keeps the finding rather than quietly deleting it,
because "we ranked a blocked item first" is the kind of thing worth remembering the next time an
ordering looks obvious.

**Items A–C and 17–28 were added after 0.9.7**, from a second pass that asked a different question:
not "what does an operator want to see" — which the shipped work answers well — but "what does an
operator want to *do*", measured against a real sysadmin's week. The answer put three pieces of
plumbing in front of every feature on that list, which is why they are lettered rather than
numbered. They are not features and should never be sold as any.

The ordering at the end is the useful part of this document; the write-ups exist so that ordering
can be argued with.

This is a statement of direction, not a schedule. Sizes are rough and relative — "weeks" means a
focused person, not a calendar quarter. Where something is a real unknown it says so rather than
guessing, because the cost of a wrong estimate here is a commitment nobody can keep.

## Built since this was written

Shipped in 0.9.0 through 0.9.3, and hardened across 0.9.4 to 0.9.7. Kept here rather than deleted, because the write-ups say why each
was built and that reasoning outlives the ticket.

| Item | State |
|---|---|
| **16. Background metrics sampling** | **Built.** `fleetSampler.ts` in main, scheduled, survives the monitor being closed. Off by default. Resumes when the vault is unlocked rather than sitting silently paused. |
| **3. Alert channels** | **Webhook built** — generic HTTPS JSON POST, which is what Slack, Discord and Teams all accept. Named integrations for WhatsApp and Twilio are not built and may never need to be. Only three kinds fire: `cpu`, `memory`, `unit-failed`. See item 19 for what is missing and why disk is the surprising one. |
| — | **Failed-unit alerts**, which were not on this list and are the case that prompted it: four failed units found by opening the app and looking. A failed unit does not move a CPU graph, so no threshold would have caught it. |
| **13. Fleet-wide search** | **Built.** Searches units, ports and hosts across the workspace from data the sampler already had and discarded. Reports what it could NOT search — never sampled, no systemd, no port probe, gone unreachable — because results without that gap are a lie by omission. |
| **11. Run one command across many servers** | **Built.** Approval model settled and tested first: confirmation scales with blast radius, nothing is safe by omission, cancel means queued hosts never start. Three at a time, 60s per host, output capped at 20 kB. Not exposed to the MCP bridge. Those three bounds are correct for a command and wrong for a task — see item B. |
| **12. Live log tailing across hosts** | **Built.** journalctl, `tail -F` or `docker logs`, several hosts interleaved and colour-keyed, with a real source picker across all three modes. The remote command is built from a validated source and never from user text. |
| **6. Cron, read-only** | **Built.** Crontabs, /etc/cron.d and systemd timers across the estate. Read-only until the parser is proven — the user-field trap is a silent misread, not an error. |
| **15a. Optional first-party modules** | **Built.** Six modules behind the registry. Borrows the AI_CAPABILITIES shape: absent reads as OFF, and an upgrade never switches a new module on for an existing install. Enforced twice — `MODULE_FORBIDDEN_IMPORTS` by walking the real import closure, and `MODULE_FORBIDDEN_BRIDGE` for the `window.shellpilot` namespaces a closure walk cannot see. Part (b) is not started and `tests/moduleBoundaries.test.ts` guards against drifting into it. |
| **4a. Docker** | **Built** as the first module behind that gate, off by default. Shells out to the host's own binary. The work was in telling the three failures apart: missing binary, stopped daemon, and permission denied have three different fixes. Now beyond listing: start/stop/restart with graded confirmation, `docker exec` as a third `TerminalTransport`, container logs followed live, and `docker system df` parsed down to reclaimable bytes per type. |
| **4b. Kubernetes** | **Built, read-only plus one write.** Pods, nodes, deployments/statefulsets/daemonsets with ready-versus-desired, namespace events, `kubectl top` where a Metrics API answers, and a diagnosis view. The single mutation is `kubectl rollout restart`. It deliberately does not switch contexts, exec into a pod, or delete anything, and `src/shared/kubernetes.ts` states why in the file rather than in a commit message. This document previously said Kubernetes should stay "separate and later"; it arrived earlier because the Docker module's failure classification and sudo discipline transferred wholesale. |

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

A third property became visible only after 0.9.7, and is the reason for the operator-console
section further down: **almost everything the app does today is a read.** Watching, searching,
tailing, asking an agent — those are one verb, and the other half of an operator's job is the
other one. Extending the sentence above to another kind of target is no longer the only axis;
extending it to another kind of *action*, safely, is now the larger one.

---

## Who this is for — and who it is not

Every ordering below is a consequence of this section. Change the customer and the ranking changes,
which is why it is written down before the numbers rather than left implicit inside them.

**The target operator.** One person, or a team of two or three without a dedicated platform
engineer, running **ten to fifty mixed Linux hosts** — some bare metal, some VPS, some small cloud —
behind one or two jump boxes, across a production tier, a staging tier and a database tier. Mostly
systemd. Docker or Compose on several of them. Maybe one small Kubernetes cluster, maybe none. They
own the estate end to end: they patch it, back it up, hold its credentials, and get paged for it.

**What they do not have**, and this is the part that matters more than what they do:

- **No Ansible, Puppet, Salt or Chef.** They looked, decided the setup cost exceeded the payoff at
  their size, and run commands by hand. This is the single most important fact about them.
- **No Prometheus, Grafana or Datadog.** Or a Prometheus somebody set up once that nobody maintains.
- **No PagerDuty, no on-call rotation.** Alerts go to a phone, or nowhere.
- **No compliance regime** forcing an audit trail — yet. Some of them acquire one, and that is when
  item 14 stops being a convenience.
- **No budget approval process.** They install what they want.

**Why this customer and not a larger one.** An enterprise SRE team has already solved every problem
on this page — with Ansible, Prometheus, Vault and a pipeline — and solved it better than a desktop
app ever will. Selling to them means competing with their existing stack on its own terms and losing.
The ten-to-fifty-host operator has the same problems and *none* of that machinery, because every
piece of it costs more to run than their estate justifies. They are doing this work in fifteen
terminal tabs right now. That gap is the entire opportunity, and nobody is serving it: MobaXterm and
Termius are better terminals, and the config-management tools start above where this user stops.

**The anti-personas, stated so a feature request can be measured against them.**

- **The enterprise platform team.** Has a stack. Not a customer. Do not build for their reviewers.
- **The Kubernetes-native shop.** Their estate is a control plane, not hosts. `kubectl`, k9s and
  Lens serve them, and matching those is a product we are not building. This is why item 22 ranks
  where it does, and why applying manifests stays refused.
- **The single-server hobbyist.** One box, one tab. Everything in this document is overhead for
  them. They are welcome, they are not who the ordering serves, and no feature earns its place by
  helping them.
- **The person who wants a prettier PuTTY.** Already served, by the terminal that shipped in 0.8.0.
  Nothing below is for them either.

**The one-sentence test for anything proposed after this.** *Does it remove a task the
ten-to-fifty-host operator currently does by hand, in tabs, on a schedule they resent?* If not, it
needs a different justification than "a sysadmin might want it" — because a sysadmin might want
everything.

---

## Near term — mostly assembly, not invention

These three are largely UI and glue over machinery that already exists and is already tested. They
were first because the ratio of value to new risk looked best on this list.

**Superseded, and kept for the reason it was wrong.** "Cheap and low-risk" was measured against the
code and not against the operator. Item 3 was built and mattered; items 1 and 2 rank in the Defer
quadrant of the leverage table below, because pm2-style supervision serves about a quarter of the
target operators and the frp UX about a fifth. Assembly cost is a poor proxy for value, and this
section is the evidence.

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

## The operator console — what running an estate needs that everything above does not give it

Everything shipped so far answers one shape of question: **what is happening?** Watch the fleet,
search it, tail it, ask an agent about it, and react by hand. That is an observation deck, and it is
a good one.

A sysadmin's actual week is a different shape: **patch these forty packages, coordinate the reboots,
back that up, restore it somewhere to prove the backup works, drain that node, rotate that key, and
show me on Friday what changed.** Almost none of that is a thing to look at. It is a thing to run —
usually for longer than a minute, usually on a schedule, and always with a record afterwards.

Measured against that week honestly, the gap is not twenty missing panels. It is three missing
pieces of plumbing that nearly every one of those tasks needs, and which nothing in the app has:

| Missing | What the code says today | What it blocks |
|---|---|---|
| **Somewhere to keep history** | `store.ts` is a single JSON blob, rewritten whole on every save. `fleetSampler` holds a `Map` in memory and `delete`s a host's entry the moment it goes unreachable. There is no database dependency in `package.json` and no time series anywhere in the renderer. | Capacity forecasting, alert hysteresis, job history, drift detection, "what changed on Tuesday" |
| **Somewhere to run long work** | `broadcast.run` is a buffered `exec` — three at a time, 60 seconds each, output capped at 20 kB, nothing surviving a dropped channel. Correct bounds for *a command*; wrong ones for *a task*. | Patching, OS upgrades, backups, restore tests, drains, migrations — every maintenance job |
| **Something that knows what a host IS** | A target is a connection config. `HostMetrics` carries a kernel string and a hostname; nothing reads `/etc/os-release` anywhere in the repo. | Patch management, inventory reporting, compliance, drift, "which boxes still have the old openssl" |

Build those three and most of what follows is one to three weeks each. Skip them and every feature
grows its own scheduler, its own storage and its own timeout bug — which is the mistake this
document already warns about for backups versus cron, generalised.

They are lettered rather than numbered because they are not features and must never be shipped as
one. Nobody wants a database; they want next Tuesday to be answerable.

---

### A. A durable store

Persist samples, events and facts, rather than rendering them once and dropping them.

**What exists.** Everything that produces the rows. `fleetSampler` already sweeps the estate on a
schedule and builds a complete `HostMetrics` per host, including units and listening sockets. It is
thrown away after being rendered. The alert path, the broadcast results and the two JSONL logs are
each a stream of events with no queryable home.

**DECIDED: `node:sqlite`, measured rather than assumed.** The obvious answer was
`better-sqlite3`, and the obvious objection was that this app has already paid the
native-module bill once — `@lydell/node-pty` cost a lazy loader with a kill switch, two
asarUnpack patterns, a files-exclusion glob that shipped two unsigned Windows binaries
into the first 0.8.0 build, a force-install in the release workflow so Intel Macs are not
handed `MODULE_NOT_FOUND`, a 9 KB verify script, a three-OS CI job, and library validation
switched off in the hardened runtime. None of that is hypothetical; all of it is in the
repository.

It turns out neither is needed. Electron 43.4.1 bundles Node 24.18.1, which ships SQLite
3.53.1 as `node:sqlite` — inside the binary this app already distributes. Verified by
running it: `DatabaseSync`, `StatementSync`, `backup` all exported, no experimental
warning, WAL accepted, and a `WITHOUT ROWID PRIMARY KEY(ts, host, metric)` table measured
at **21.9 bytes per row**, where the primary key *is* the table and there is no second
B-tree to pay for.

So the store costs **zero new dependencies, zero prebuilds, zero packaging surface, zero
signing surface**, which is the "one tool, no external dependencies" constraint met
literally rather than approximately. The trade is a dependency risk for a platform-version
risk: the version is whatever Electron bundles. That is the cheaper of the two here, and
the escape hatch stays open because `better-sqlite3` has near-identical `prepare/run/get/all`
semantics — provided the SQL never leaves one repository file. Three tables carry
almost everything below: samples (host, metric, timestamp, value), events (alerts raised and
resolved, jobs, changes, approvals) and facts (host, key, value, first seen, last seen).

**The trap the arithmetic missed, and it is 5x the whole budget.** `HostMetrics` carries
`services: ServiceUnit[] | null` and `listeners: PortListener[] | null`, sampled on every
sweep like everything else. A host with forty systemd units stored naively as samples is
28,800 rows a day *for one host* — 432,000 a day across fifteen, five times the entire
metric budget, none of it changing between sweeps. Units and ports are **facts**, written
only when they change, with the change itself recorded as an event. That is what items C
and 25 want anyway. Decide it before the first write, not after.

**What is genuinely hard, and it is not the schema.** Retention. Fifteen hosts at a two-minute
cadence with eight metrics is roughly 86,000 rows a day — nothing for SQLite, and 30 million a year,
which is a file somebody eventually notices. This needs a downsample rule (full resolution for a
week, hourly means after that, dropped after a quarter) decided before the first write, not after
someone's disk fills. A tool that alerts on disk pressure must not become a cause of it.

Measured, not estimated: the naive schema is 730 MB a year, and 1.27 GB if a separate
index is added. Seven days at full resolution plus eighty-three days of hourly
average/min/max, then dropped, holds **~16 MB in the database in steady state and never
grows** — 19.1 bytes a row, measured on the checkpointed primary, times 843,840 rows. Call
it **~32 MB on disk**: a full `.bak` is taken at every clean launch, so the steady state is
the database twice, and `historyBytes()` counts both because that is what the user's disk
gives up. Ship the retention pass on day one; a store that only gains a retention rule after
someone complains has already written the year of rows.

The `localPty.ts` discipline still applies even without a native module: import lazily
behind an interface, keep a kill switch, and let a machine where the store will not open
still get a working app running on today's in-memory behaviour.

**Size.** 1–2 weeks. Unlocks items 19, 25, 26 and 14, and makes 17 and 5 auditable.

---

### B. A job engine

A job is a command or a sequence, against a target set, whose output streams, whose state is
persisted, and which survives the panel closing, the laptop sleeping and the link dropping.

**What exists, and it is more than half.** Three separate pieces, each already tested:

- **The orchestration.** `broadcast.ts` has bounded concurrency, per-host state, cancel semantics
  where queued hosts never start, and outcome classification.
- **The approval model, which is the hard half of any executor.** `policyEngine.ts`,
  `policyStore.ts` and `approvals.ts`, with `broadcastApproval.test.ts` and
  `accessGroupSummary.test.ts` behind them. Confirmation already scales with both inputs — a
  destructive command on one host because the command is the danger, an ordinary command on twelve
  because the count is. A job engine does not need to invent any of that.
- **The streaming.** `logTail` already carries continuous multi-host output with bounded buffers,
  per-host attribution and backpressure, which is exactly what a running job's output is.

**What is actually new, and it is one question.** What happens when the channel dies mid-task.
Raising `BROADCAST_TIMEOUT_MS` is not an answer: a longer wait still loses everything when the
laptop lid closes at minute nine of an `apt upgrade`. The honest options are to run detached on the
remote side and poll for a marker (`nohup`/`setsid` plus a status file, or a `systemd-run --unit`
where systemd exists), or to accept that jobs die with the connection and say so plainly. The first
is the useful one and costs a real design decision about naming, orphan reclamation and what
happens when two ShellPilots poll the same job.

Everything else follows: a job list, a persisted history in A, resumable output, and per-job audit
rows that item 14 can read.

**The finding that reframes this item, and item 17 with it.** The status quo is not "a job
dies with its connection". `sshExec` on timeout resolves and abandons without signalling the
remote process, and when the socket dies sshd sends SIGHUP — which `apt` and `dpkg` do not
ignore. Minute nine of an `apt upgrade` across an estate is therefore not lost output, it is
**`dpkg` interrupted on every host**, and the recovery is `dpkg --configure -a` on each. Item
17 cannot ship on the attached path at all; the attached path is worse than not offering the
feature.

**Decided: a detached launch with a marker directory.** `setsid` writing `cmd`, `instance`,
`pid`, `out` and `rc` under the target user's own state directory, `rc` written
temp-then-renamed so its presence means it is complete. Resume reads from a byte offset,
which is an exact monotonic cursor. Three honest states fall out that today's vocabulary
cannot express — `detached` (launched, channel gone), `orphaned` (marker present, pid gone,
no exit status) and `foreign` (started by another ShellPilot instance) — and today an
*expected* reboot classifies as `unreachable`, which is the opposite of the truth.

Nothing is installed: no binary, no package, no service, no cron entry, nothing that runs
after the job. One directory, reaped on read, with a Settings switch that turns detached
jobs off entirely and degrades to the honest ephemeral behaviour per host. `systemd-run` is
strictly better where it works and cannot be the only backend — system scope needs root,
which would make every job run as root and invert the risk model that assessed the command
as the user typed it; user scope needs lingering, which is a persistent change to the host.
It belongs later, capability-detected, behind the same interface.

**B3 shipped, and it settled the correction below rather than merely acknowledging it.** The
approval record is `CommandApproval` in `shared/broadcast.ts`, minted where the human answers and
stored whole in `job.approval`: the step text and the resolved target list exactly as confirmed, the
risk, the confirmation kind, and the phrase actually typed. `verifyApproval` re-derives the plan and
refuses on disagreement, at launch and again at resume, and it is called from BOTH surfaces —
`BroadcastPanel` no longer computes a plan and throws it away. The re-consent rule is written down
in `shared/jobs.ts`: a job resumed **within one process lifetime** carries its approval; a job
adopted **after a restart** finishes the hosts already running and may not start one it never
reached, because finishing is not an action and starting is. That makes B2's `reclaim()` refusal
principled rather than incidental. Decisions are written to `shellpilot-job-approvals.jsonl` — a
third log, not a second caller of `recordAudit`, for the reason the local terminal already has its
own file, and because `auditLog.ts` sits inside the agent-reachable import closure that
`tests/jobsNotExposed.test.ts` guards.

**Correcting this document.** An earlier revision justified the estimate with "the approval
model — the hard half of any executor — is built and tested", naming five files as one
system. They are **two systems with no shared code**: the human confirmation model lives
entirely in `shared/broadcast.ts` and is enforced in the renderer, and the AI capability gate
lives in `policyEngine`/`policyStore`/`approvals`. The two tests cited as proof test the two
different halves, and neither produces what a durable job needs — a **persisted approval
record**. `BroadcastPlan` never reaches main at all; `broadcast:run` takes a run id, a command
and targets, and `main/index.ts` states deliberately that main does not re-derive the model.
A job resuming after a restart therefore has no memory of the dialog that authorised it, and
fixing that reverses a settled decision rather than extending one.

**Split, so item 17 does not wait for all of it.**

| | Scope | Size |
|---|---|---|
| **B1** | Durable one-command jobs on the existing attached path, the store, and a job list | 1.5–3 wk |
| **B2** | The detached backend, the four new states, reconnect with backoff, reclaim and reap, the remote-shell matrix | +2–3 wk |
| **B3** | ~~A persisted approval record, and moving enforcement into main~~ **SHIPPED** | +1 wk |
| **B4** | Stages, the health gate, reboot-and-wait, jump-host exclusion | +1.5–2 wk |

**Size.** **6–9 weeks** for the whole of it, not 1.5–3. B1 alone is the old estimate and is
the version that does *not* unblock item 17. B4 overlaps what item 17 already budgets for
reboot coordination — it belongs here, and item 17 shrinks accordingly rather than paying
twice.

**One guard this item needs that broadcast did not.** Durability defeats revocation: `deny
all pending` resolves requests that are *pending*, and can do nothing about a job already
detached on fifteen hosts, because nothing is pending. An agent-reachable job engine would be
a standing capability the stop-all-AI-access switch cannot revoke. It stays human-only, with
the three-layer guard the local terminal already uses.

---

### C. Host facts

What a host *is*, as opposed to what it is currently doing.

**What exists.** The collection path. `fleetSampler`'s sweep and `metricsSample()` already run
probes over a pooled connection and already respect the distinction that matters most here.

**What is actually new.** A slow-cadence probe — hourly, not every two minutes, because a distro
does not change between samples — reading `/etc/os-release`, the kernel, the package manager, the
count of pending updates and of *security* updates specifically, the reboot-required flag, the
virtualisation type, and the machine's own idea of its uptime. Stored in A, surfaced through the
fleet search query surface that already exists.

**The finding that changes item 17, and it is not a detail.** "Security updates, counted
separately" is item 17's headline number. Research against the real package managers says
it cannot always exist:

| Manager | Pending | Security | Why |
|---|---|---|---|
| apt | yes, from cache, no root | **yes** | `apt-check`, or origins ending `-security`. Best-supported path. |
| zypper | yes | **yes, best of any** | SUSE genuinely models patches by category. |
| dnf / yum | yes (exit 100 means updates) | **only where `updateinfo` exists** | Rocky and Alma publish it, Fedora publishes it, CentOS Stream historically does not, and many internal mirrors strip it. When it is missing dnf returns **zero rows**, which is indistinguishable from "no security updates". |
| pacman | yes, from the local sync DB | **never** | Arch has no security channel. |
| apk | yes | **never** | Alpine tracks secfixes in build metadata, not the installed index. |

So on two of five managers the number can never exist, and on a third it silently reads
zero during exactly the week it matters. A silent zero is the precise failure this item
exists to prevent, so `unsupported` is a first-class status distinct from both `0` and
"not checked", it must render differently in the table, in the fleet-search coverage
sentence and in anything an agent is told — and item 17 must promise "security updates
where the distribution publishes them", not "security updates".

Detecting the dnf case is required work, not a nicety: probe `updateinfo summary`, and if
it answers nothing while pending updates exist, the security count is `unsupported`.

**Three things already exist and shrink the probe.** Kernel, total memory and uptime are
already in `HostMetrics`. Do not collect them twice.

**Two mechanical traps.** `metrics.ts`'s `exec` discards the exit code, and exit status is
the API for three of these probes — dnf signals updates with 100, zypper reboot-needed
with 102, `needs-restarting -r` with 1. And `section()` cuts at the next `__MARKER__`, so
a `PRETTY_NAME` containing one truncates its own section and shifts every later fact.
`cron.ts` already solved the second by accumulating status in a shell variable and
printing it once at the end, where nothing read out of a file can forge it. Copy cron,
not metrics.

**Never mutate.** No `apt update`, no `pacman -Sy`, no `dnf makecache`. All three hit the
network, take seconds, and `pacman -Sy` creates the partial-upgrade state that is the
classic way to break an Arch box. Read the cache and **report its age** — "0 pending
updates" from metadata refreshed forty days ago is a lie of the exact kind this item
forbids. That is a second staleness axis: the fact's own age, and the age of the data
behind it.

**Never source the file.** `. /etc/os-release` on a host under an attacker's control is
arbitrary code execution as the SSH user. Read it and parse in TypeScript.

**What is genuinely hard.** The same `null`-is-not-empty discipline the monitor and fleet search
already enforce, applied where it is most tempting to skip. "No pending updates" and "could not
check for updates" must stay visibly different, or the feature lies during exactly the week a CVE
matters. A host whose facts are four days stale should say so rather than presenting them as now.

**Consent, decided.** This gets its own `hostFacts` capability rather than widening
`serverMetrics`. "How many unpatched security updates, and which kernel" is a
vulnerability report about the host and is arguably the most attacker-useful thing the
bridge could return — materially different from "CPU and memory". The 0.8.0 finding above
was exactly a consent that had drifted wider than its grid text, and the standard it set
is that the grid must describe what is actually taken. A new capability backfills to DENY
for every existing group, which is the correct default here.

**Size.** Revised to **2–3 weeks**, and honestly 1.5 only if apt and dnf ship first with
the other three managers marked `unsupported` on day one. The roadmap assumed the
collection path was the work. It is not — the distribution matrix and the honesty plumbing
are. Item 17 cannot start without it; items 24, 25 and 26 are much weaker without it.

---

## The maintenance tier — the week itself

### 17. Patch and update management

One view: every host, its pending updates, its security updates counted separately, whether it needs
a reboot. Select a set, apply in stages, coordinate the reboots.

**Why this is the flagship.** It is the single most common recurring task in the job the app is
named for, it is on every sysadmin's list without exception, and nothing in the product touches it
today. A user patching fifteen hosts currently opens fifteen tabs.

**What exists.** Nothing directly — and almost everything indirectly. Items B and C are the feature;
`broadcast`'s risk assessment and typed confirmation are the safety model; fleet search is the
"which hosts" query.

**What is actually new, and it is not the package managers.** Abstracting apt, dnf, zypper and pacman
is a day's work and mostly `--dry-run` parsing. The feature is **reboot coordination**, and it is
where this can do real damage: do not reboot both replicas of a database, do not reboot the bastion
you are connected through, do not proceed to host four when host three came back with a failed unit.
That means an explicit ordering, a health gate between stages, a hard refusal to reboot a host that
is a jump host for anything else in the workspace, and a resolved target list shown before anything
runs — the same discipline broadcast already applies to a one-shot command, extended over time.

**What it should not do.** Decide *whether* to patch. Reporting that twelve hosts have security
updates and letting a person choose is honest; auto-patching an estate from a desktop app is a
promise about unattended correctness this app cannot keep.

**Size.** 3–4 weeks after A, B and C. Nothing else on this page is worth more.

---

### 18. Database operations — SHIPPED

**Postgres and MySQL/MariaDB shipped in `c008c8d` and were hardened in `971c47d`. MongoDB and
Redis are now built too**, in four commits: the captured fixtures, the pure command/parse/judge
layer, the collectors, and the panel. Eight questions for MongoDB and nine for Redis — the ninth
is `cluster`, which cannot fold into `replication` because a cluster in state `fail` refuses a
third of the keyspace while every node's `INFO replication` reports a healthy master.

**SQL Server is deliberately not covered**, and `DB_OPS_UNSUPPORTED_NOTE` says so on the page
rather than leaving an empty tab to be discovered: nothing here has been run against one, and a
set of questions written from documentation agrees with whatever its author assumed rather than
with the server.

What the MongoDB and Redis pass cost was not the commands. It was that both engines report a dead
thing with a number that reads as healthy, in the same shape MySQL does and with different field
names. A MongoDB member that is unreachable reports `health: 0` alongside `pingMs: 0`, `uptime: 0`
and an `optimeDate` of the Unix epoch; a Redis replica whose master has gone reports
`master_last_io_seconds_ago: -1`. Neither is a measurement, and every clamp a reviewer would ask
for turns both into zero. Both were captured from real containers rather than reasoned about, and
`tests/fixtures/dbops/README.md` records what could NOT be captured — no sharded cluster, no Redis
Cluster, no Sentinel, no AOF, no `mongodb+srv` — rather than filling the gaps with invention.

The write-up below is kept as the reasoning that produced it.

The five engines are connected and can be queried. That is a client. An operator needs the other
half: backups, replication health, connection counts, slow queries, locks, growth.

**Why it is the best value-to-effort item on this page.** `pg`, `mysql2`, `mssql`, `mongodb` and
`ioredis` are already bundled, already connected through the credential resolver, and already used
for nothing but ad-hoc queries. `dbshell.ts` already runs each engine's native shell. Every answer
below is a query over a connection the app is already holding.

**What is actually new.** Per engine, roughly eight questions and a display: Postgres —
`pg_stat_replication` lag, WAL and archive state, autovacuum age per table, `pg_stat_activity`
counts, `pg_locks`, database sizes, `pg_stat_statements` when installed. MySQL/MariaDB —
`SHOW REPLICA STATUS`, binlog inventory and disk cost, the slow log, `SHOW PROCESSLIST`, table and
index sizes. MongoDB — `rs.status()`, oplog window in hours rather than bytes, index usage,
connections. Redis — `INFO memory` with the eviction policy, persistence state and last save,
replication, `SLOWLOG`, keyspace growth.

**What is genuinely hard.** Nothing technically, and two things editorially. Which eight questions
per engine actually matter — the wrong eight is a dashboard nobody reads. And rendering a number as
a judgement: "replication is 4h 12m behind" belongs in the alert path from item 19, not in a table
cell in a tab nobody has open.

Backups belong to item 5, not here — a database dump is a job with a destination, and building a
second backup path beside `backup.ts` is exactly the two-schedulers mistake in another costume.

**Size.** 1–1.5 weeks per engine. Postgres and MySQL first covers most estates.

**What the estimate got right and wrong.** The eight-questions-per-engine framing held for both
new engines, and the editorial half was indeed the hard part. What it missed is that "roughly
eight questions" is the cheap half of a week and the fixtures are the expensive half: every
finding that changed a judgement came out of a container, and none of them out of documentation.

---

### 19. Alerting, completed — BUILT

**19a (disk) shipped in `7f4e1e2` and was hardened in `1a4cfaa`. 19b is now built**, in six
commits: durable suppression, flap damping, inodes and load, the kinds that have no number, their
producers, the inbox, snooze and acknowledge, and per-host thresholds. Ten kinds fire today —
`cpu`, `ram`, `disk`, `inode`, `load`, `host-unreachable`, `job-failed`, `tunnel-down`,
`db-alarm`, `db-watch` — plus `unit-failed`, which is a set of unit names rather than a crossing
and has always been its own shape.

**Two named kinds are deliberately NOT built**, and the reason is the same for both, first written
down in `a2b06a5`: each needs a new remote probe whose SCOPE is a product decision nobody has taken
— which journal window counts as "recent" for an OOM kill, and which certificates on which paths
count as "ours" for expiry. A half-probe that reports "no OOM kills" when it could not read the
journal is precisely the alert this item spends its length refusing to ship, because a metric that
could not be measured is not zero. They are a separate item, not a loose end in this one.

"Backup failed" is not built either, for a shorter reason: item 5 has not been built, so there is
no backup that could fail. "Replication lag from item 18" IS built, as `db-alarm` and `db-watch` —
item 18 already decides the level and writes it to the durable store with the numbers attached, and
alerting reads that verdict rather than reaching one of its own.

The write-up below is kept as the reasoning, in the past tense where it describes what was wrong.

Three kinds fire today: `cpu`, `memory`, `unit-failed`.

**The surprising gap is disk, and it is subtler than "missing".** `hostHealth.ts` treats disk as a
first-class signal already — `DISK_DANGER = 85`, `diskCritical` per host, `diskHosts` in the fleet
summary, `diskLine()` rendering "2 hosts low on disk", and disk pressure is one of exactly two
things that mark a host as needing attention. There is even a comment ranking failed units above it
deliberately, because a unit that is down is an outage already and a disk that is filling is one
that has not happened yet.

What is missing is that disk is not an `AlertKind`. It is computed, ranked and rendered — and then
reaches nobody. A filling disk shows on a screen you have to already be looking at, which is
precisely the failure mode item 16 was built to end. **This is half a day of wiring an existing
signal into an existing bus**, and it should not wait for anything else on this page.

**Then the rest, which does need A.** Inode exhaustion, load, OOM kills from the journal, host
unreachable, job failed, backup failed, replication lag from item 18, certificate expiry for certs
on hosts we manage, tunnel or VPN down. Plus per-host thresholds, hysteresis, flap suppression,
snooze, and an alert *inbox* with a history rather than transient toasts — a disk alert that fires
forty times overnight gets the whole feature muted, which is worse than not shipping it.

**Size.** Disk: half a day. The rest: 2–3 weeks, most of it after A.

---

### 20. Compose

**What exists, and this was underestimated.** `docker.ts` already reads
`com.docker.compose.project` and `com.docker.compose.service` labels — asked for as a separate probe
that is allowed to fail, and carrying `composeLabels: 'read' | 'unavailable'` so "no compose
projects here" stays distinct from "could not read labels". Containers already group by project in
the panel. The mental model is built.

**What is actually new.** The file half: finding compose files on a host (`docker compose ls` where
the engine is new enough, a bounded filesystem search where it is not), parsing and validating them,
showing declared services against running state, `pull` and `up -d` as jobs from item B, and editing
an image tag.

**What is genuinely hard.** `.env` handling, which is the reason this cannot be a thin wrapper.
Compose environment files hold credentials, and displaying them is the one thing this app exists not
to do. They must route through the vault and the redaction pipeline or the feature is a secrets
leak with a nice table.

**Why it ranks above Kubernetes work.** The reference user's estate is compose, not k8s. Most
single-operator infrastructure is.

**Size.** 1.5–2 weeks.

---

### 21. Docker housekeeping

**This is a decision, not a feature.** `docker system df` is already parsed down to reclaimable bytes
and percent per type, and `broadcast.ts` already classifies `docker`/`podman`
`rm|rmi|stop|kill|prune|down` as destructive. The comment in `docker.ts` explaining why prune was
not shipped is the correct instinct: `docker system prune -a` has ruined days.

**SPLIT, after research contradicted the plan.** `docker.ts` already refuses `prune`, and
its stated reason is falsifiable rather than a preference: *"its blast radius is not knowable
from the UI that offers it."* That is an objection to `prune`, not to reclaiming disk — and
it is answered by making the blast radius a literal list of ids.

Research also found the `-a` case is worse than its flag reads. `system prune -a` removes
every stopped container **first**, so images whose only reference was a stopped container
become unreferenced within the same command and are then deleted too. A preview built by
listing images beforehand cannot show them. That is not a race; it is a preview that is
structurally wrong. `-a` is refused, not deferred.

**21a — the itemised view. Shipping now.** `docker system df -v` gives what the summary
cannot: per-image `UNIQUE SIZE`, per-volume size and link count, per-container state, build
cache. Read-only, no deletion. This satisfies the existing comment's own remedy — *"the
disk-usage panel exists precisely so the operator can decide what to remove themselves, in a
shell, with the numbers in front of them"* — by giving them the numbers per item instead of
per category. **3–5 days.**

**21b — reclaim by id. Deferred, and costed honestly.** Not `prune`: `docker rm`/`rmi`/
`volume rm` against exactly the ids the preview displayed, so anything that became eligible
afterwards is untouched and the crashed container you were about to debug survives. It needs
a re-preview-and-refuse-on-diff step, a per-item selection UI, podman fixtures nobody has
yet, and a rewrite of three prose blocks and a forty-line test suite that currently assert
the opposite. **1.5–2 weeks**, which is what moved it out of the cheap-wins wave.

**Engine age, without phoning home.** `{{.Server.BuildTime}}` gives an absolute age that
cannot go stale and cannot be wrong. A baked table of release versions was considered and
rejected: it needs an owner and a refresh cadence, and a table that rots states something
false. Age alone is honest and free.

**Size.** 21a: 3–5 days. 21b: 1.5–2 weeks, unscheduled.

---

### 22. Kubernetes lifecycle

`kubernetes.ts` refused exec, delete and context switching, and gave reasons that were right at the
time. Two of the three said what the precondition was, so this item is those preconditions.

**Cordon, drain and uncordon.** The file already explains why drain is the dangerous one: ownership
references tell you a pod will be recreated, they do not tell you the workload can afford to lose it
right now. A one-replica Deployment's pod is "safe" by ownership and an outage in fact. Drain needs
endpoint state at the moment of the click and PDB awareness, and without both it should stay unbuilt.

**Exec into a pod**, behind the broadcast approval model — which is what the file said the
precondition was, and which now exists.

**Reads that are missing and cheap.** PVC capacity, ingress, RBAC bindings, secrets *existence*
without values, deprecated API scan against the cluster version, Helm release listing.

**Still not this.** Applying manifests. That is a GitOps pipeline's job and putting it behind a
desktop button is how a staging manifest reaches prod.

**Size.** 3–5 weeks. After Compose, deliberately.

---

### 23. Fleet key and access management

Which key opens which host, whose it is, and removing one everywhere at once.

**What exists.** Very little, and it is worth being precise: `authorized_keys` appears exactly once
in the repo, in `sshKeys.ts`, as a filename to *skip* when listing a user's own private keys. This
is close to greenfield on top of B, C and the vault.

**Why it is a genuine differentiator.** No GUI SSH client does fleet-wide key inventory well.
"Which of my fifteen hosts still trusts the laptop I sold" is a question every operator has and
nobody can answer quickly. The data is one file per user per host.

**What is actually new.** Read and fingerprint every `authorized_keys` across the estate, attribute
keys to people, cross-reference against last-login where the host will say, and add or revoke across
a selection. Adjacent and nearly free once the reader exists: expired or locked accounts, sudoers
membership, and an access-review export.

**What is genuinely hard, and it deserves fear.** Writing `authorized_keys` is the highest-consequence
write the app could make — a bad one locks you out of the host you would use to fix it. Three rules,
non-negotiable: never remove the key the current session is authenticated with, always verify a
second independent session succeeds before committing the change, and always leave a timestamped
backup of the previous file on the host.

**Shipped, and narrower than the item's title.** The read half answers the question this
item exists for across the whole estate. The write half does not: the staged write resolves
`$HOME/.ssh/authorized_keys` on the host, so one approved command covers a selection — and can
therefore only ever edit the **connecting account's** file. A revoke aimed at another account
is refused rather than silently rewriting the wrong file, which would fail the count check,
change nothing, and report the wrong reason for having done nothing.

Combined with rule 1, which needs sshd to report the session key, revoke works on the
connecting account on hosts with `ExposeAuthInfo` enabled. That is a real capability and it is
not "fleet key management" in the sense the panel's title suggests. Widening it means a
per-account staged write and therefore a per-account approval, which is a different shape of
job, not a bigger loop.

Two follow-ons, both small and both named so they are decisions rather than oversights: the
panel must state the scope before an operator selects a target, and a key revoke — the most
audit-worthy write in the application — currently leaves **no approval-log row**, because
`recordJobApproval`'s surface vocabulary has no value for it.

**Size.** 2–3 weeks, of which the read half is one.

---

### 24. Security posture — reading state, not scanning

Firewall rules (ufw, firewalld, raw iptables/nftables), SELinux or AppArmor mode, sshd config against
a hardening baseline, failed-login summary, and pending security updates specifically.

**The scope discipline is the whole item.** Do not build a vulnerability scanner. The distribution
already knows which of its packages carry security fixes, and `apt list --upgradable` with
`debsecan`, or `dnf updateinfo --list security`, is a better answer than anything a desktop app will
compute from a CVE feed. This item consumes that; it does not recompute it.

**What exists.** Item C collects the update counts already. Everything else is a read probe of the
kind the sampler runs a dozen of.

**Size.** 2–3 weeks.

---

### 25. Configuration drift

Snapshot a file or a setting on one host, compare it across the fleet, alert when it diverges.
"All twelve web servers have this nginx.conf. Three do not."

**What exists.** Fleet search's cross-host query shape, SFTP read, and item A for the baseline.

**What is genuinely hard.** Defining a difference. Whitespace, generated timestamps, hostnames and
per-host stanzas make naive diffing useless within a day of shipping. This needs normalisation rules
per watched file and the honesty to say "differs in ways I was told to ignore".

**Size.** 2–3 weeks.

---

### 26. Capacity trends

"This disk fills in eleven days."

**Why it is small.** Once item A exists this is a query and a chart, not a subsystem. It is listed
separately only so that item A is not judged on the day it ships, when it appears to do nothing.

**What it must not become.** A metrics warehouse. Storing enough history to answer an operator's
question is the goal; competing with Prometheus is not, and that fight is both lost and not worth
entering.

**Size.** 1–2 weeks after A.

---

### 27. A rule engine — the honest answer to item 9

"When this alert fires, run that job, then call that webhook."

**Why this and not n8n.** Item 9 asks the right question and answers it with the wrong thing.
Once items A, B and 19 exist, the app already has events, execution and delivery; a small rule engine
over its own primitives integrates with the policy layer, the audit log and the vault, and an
embedded n8n would need significant bridging to reach any of the three — while adding a second
database, a second auth model, a second credential store and a licence question.

**What it must not do.** Grow into a workflow language. Three clauses — on event, matching filter,
run action, with a rate limit — covers the cases people actually ask for. Anything beyond that is
someone else's product.

**Size.** 1–2 weeks after A and B.

---

### 28. Runbooks attached to alerts

When the disk alert fires, show the three commands that fixed it last time.

**The only part of "documentation" worth building here**, and only because item A makes it nearly
free: the events are already stored, and the jobs run against them are too. A runbook is a note
attached to an alert kind, plus the history of what was actually run the last three times it fired.
Everything else about documentation — diagrams, architecture, inventory prose — belongs in a wiki and
this app should link to one rather than become one.

**Size.** 1–2 weeks.

---

## What this deliberately will not build

A roadmap that only says yes is a wish list. Each of these was considered against the sysadmin week
in the section above and declined, with the reason, so that adding one later is a decision rather
than a drift.

| Not building | Why |
|---|---|
| **DNS and TLS certificate management** | It is a provider-API product — Route 53, Cloudflare, ACME — with almost nothing in common with an SSH console. The only piece worth keeping is certificate expiry as an alert kind in item 19, for certificates sitting on hosts we already manage. |
| **A configuration management DSL** | Not becoming Ansible. The useful subset is about eight idempotent operations — package, service, user, file, key, line-in-file — and everything past that is a language, a compiler and a decade. |
| **A metrics warehouse** | Store enough to answer an operator's question and to forecast. Item 26 says the rest. |
| **A vulnerability scanner** | Item 24: the distribution already knows, and its answer is better than ours. |
| **Embedded n8n (item 9)** | Item 27 gets most of the value with full access to the policy engine, the vault and the audit log, and without a second database, a second auth model and a licence question. |
| **A third-party extension API (item 15b)** | Unchanged and worth restating: a plugin that can call `credentialResolver` is a vault with no lock. `MODULE_FORBIDDEN_IMPORTS` and `MODULE_FORBIDDEN_BRIDGE` exist to make drifting into it impossible by accident. Not before the Tauri decision — an extension API is a compatibility promise, and rewriting the host underneath one is how migrations die. |
| **Ticketing, on-call rotation, incident management** | Webhook out to the tool that already does it. |
| **Ghostty (item 8)** | Cut by the owner. The feasibility study still stands and is worth keeping: libghostty-vt has no PTY at all — zero spawn symbols across its thirty public headers — so it could never replace node-pty, and the full renderer admits macOS and iOS only with an NSView surface, so it cannot be embedded here. The one real prize was `snapshot.h` for session restore, and it is not worth a hand-written FFI against an API whose authors say it will change without warning. |
| **Tauri (item 10)** | Cut by the owner, and the case got weaker while this roadmap was executed rather than stronger. The port was always "rewrite the whole main process": SSH and SFTP over ssh2, five database drivers, the MCP server, the vault, the VPN subsystem with its privileged helpers, the supervisor, the policy engine. This work then added a job engine with detached remote execution, a SQLite store, a host-facts probe, a database-operations layer, an access collector and a posture collector — all of it main-process, none of it portable. Installer size was the prize; the price is now most of a year of rewriting things that work. |
| **Documentation generation, diagrams, architecture prose** | Except item 28, which earns its place by being nearly free once item A exists. |
| **Applying Kubernetes manifests** | Item 22. That is a pipeline's job. |
| **Unattended auto-patching** | Item 17. Reporting and staging, yes. A desktop app quietly upgrading an estate is a promise about unattended correctness this app cannot keep. |

---

## Leverage against cost

The tiers above say what each thing is. They do not say what to build on Monday, because tier is not
priority: the maintenance tier contains both the highest-value item on the page and one that serves
a quarter of the target operators.

### How leverage is scored

Leverage is one number from 1 to 10, and it is a judgement rather than a measurement. It is written
down anyway, because a number that can be argued with beats an instinct that cannot. Four inputs:

- **Reach** — what share of the operators described above hit this at all. A feature for a quarter of
  them starts at a quarter of the score, however good it is.
- **Frequency** — daily, weekly, monthly, per-incident, rare.
- **Pain today** — how bad the current workaround is, 1 to 5. "Fifteen terminal tabs" is a 5.
  "The docker CLI already does this fine" is a 2.
- **Moat** — whether anything else the operator already owns does it. Strong moat raises the score;
  a thing every monitoring tool does lowers it, because it is table stakes rather than a reason to
  choose this app.

Cost is weeks for one focused person, split into **direct** (the item itself) and **blocked-by**
(enablers that must exist first). An item with a small direct cost and an unbuilt dependency is not
a cheap item, and treating it as one is how a quarter disappears.

### The matrix

| # | Item | Reach | Freq | Pain | Moat | **Lev** | **Direct** | Blocked by | Quadrant |
|---|---|---|---|---|---|---|---|---|---|
| 19a | ~~**Disk alert**~~ | 100% | continuous | 4 | none | **8** | **SHIPPED** | — | Done |
| 21a | ~~**Docker itemised disk view**~~ | 60% | monthly | 3 | some | **5** | **SHIPPED** | — | Done |
| 21b | **Docker reclaim by id** | 60% | monthly | 3 | some | **5** | 1.5–2 wk | podman fixtures | Deferred |
| C | ~~**Host facts**~~ | 100% | continuous | 4 | strong | **3 / 21** | **SHIPPED** | — | Done |
| A | ~~**Durable store**~~ | — | — | — | — | **0 / 30** | **SHIPPED** | — | Done |
| B | ~~**Job engine B1+B2+B3**~~ | — | — | — | — | **0 / 38** | **SHIPPED** | B4 remains | Part done |
| 18 | ~~**Database operations**~~ | 70% | weekly | 4 | strong | **8** | **SHIPPED** | mssql not covered, stated | Done |
| 17 | ~~**Patch management**~~ | 100% | weekly | 5 | strong | **10** | **SHIPPED** | — | Done |
| 5 | ~~**Backups to real targets**~~ | 90% | weekly | 5 | strong | **8** | **SHIPPED** | — | Done |
| 19b | ~~**Alerting, the rest**~~ | 100% | continuous | 4 | none | **8** | **SHIPPED** | — | Done |
| 23 | ~~**Fleet key management**~~ | 100% | quarterly | 5 | very strong | **7** | **READ SHIPPED** | write gated, needs a real host | Part done |
| 20 | ~~**Compose**~~ | 60% | daily | 3 | some | **6** | **SHIPPED** | — | Done |
| 6e | ~~**Cron editing**~~ | 80% | monthly | 3 | some | **5** | **SHIPPED** | — | Done |
| 24 | ~~**Security posture**~~ | 60% | monthly | 3 | some | **5** | **SHIPPED** | — | Done |
| 26 | ~~**Capacity trends**~~ | 70% | monthly | 3 | some | **5** | **SHIPPED** | — | Done |
| 27 | ~~**Rule engine**~~ | 40% | continuous | 3 | some | **5** | **SHIPPED** | — | Done |
| 22 | **Kubernetes lifecycle** | 25% | weekly | 4 | weak | **5** | 4 wk | B | Defer |
| 7 | ~~**Credential proxy**~~ | 30% | daily | 3 | very strong | **5** | **SHIPPED** | — | Done |
| 25 | ~~**Configuration drift**~~ | 50% | rare | 4 | strong | **4** | **SHIPPED** | — | Done |
| 28 | ~~**Runbooks on alerts**~~ | 40% | per-incident | 3 | some | **4** | **SHIPPED** | — | Done |
| 14 | ~~**Change log**~~ | 30% solo | per-incident | 3 | strong | **4** / **8** team | **SHIPPED** | — | Done |
| 1 | **pm2 supervision** | 25% | daily | 3 | some | **4** | 2.5 wk local | — | Defer |
| 2 | **frp ngrok UX** | 20% | rare | 2 | some | **3** | 2.5 wk | — | Defer |
| 8 | ~~**Ghostty snapshot**~~ | — | — | — | — | — | **CUT** | — | Not building |
| 10 | ~~**Tauri**~~ | — | — | — | — | — | **CUT** | — | Not building |

### The four quadrants, and the trap in the middle

**Do first — high leverage, trivial cost.** The disk alert at half a day and Docker housekeeping at
a week. Both are finishing something already 90% built. Nothing on this page has a better ratio and
nothing should be built before them.

**Enablers — zero direct leverage, and the highest total leverage on the page.** A, B and C would
each rank last in a naive value-over-effort sort, because on the day they ship a user sees nothing.
That sort is exactly how a roadmap stalls: every high-value item stays permanently "blocked", each
one gets built with its own private scheduler and its own private storage instead, and eighteen
months later there are four schedulers and no history. **Score an enabler by what it unlocks, never
by what it shows.** Their unlock numbers — 30, 38 and 21 leverage points across six, seven and four
downstream items — are the whole argument for building them before anything expensive.

Item C is the exception worth naming: it is the one enabler that ships something visible on its own
day, because "every host, its OS, its version, its pending updates" is a screen operators want
regardless of what it later enables. Build it second for that reason, not third.

**Invest — high leverage, real cost, worth it.** Patching, backups, the rest of alerting, Compose.
These are the product. Each is three to four weeks and each is the reason someone chooses this app
over a terminal with tabs.

**Defer — good features, wrong customer or wrong moat.** Kubernetes lifecycle is the clearest case
and the most likely to be argued: it is genuinely valuable, it is four weeks, and it serves a quarter
of the target operators against k9s and Lens, which are free and better at it. It ranks below Compose
for the same reason Compose ranks above it — most estates this size are Compose. The frp UX and pm2
supervision are the same shape with smaller numbers.

### Two numbers that reorder everything

**Time to first value.** The enablers are five and a half weeks during which a user sees one new
screen (item C's inventory). That is a real risk for a small team — no feedback, no release, no
evidence the direction is right. The plan below deliberately front-loads three weeks of visible,
shippable work first, because the two cheapest wins plus database operations cost less than the
plumbing and can be released while it is still being designed.

**Cost of the dependency, not the item.** Item 17 reads as 3.5 weeks and is really 9 with its
enablers. Item 26 reads as 1.5 weeks and is really 3. Every "quick win" further down this table that
sits behind A or B is quoting the direct number. That is why the enablers are not optional and not
last: **after they exist, eight separate items become one-to-three-week features.** Before they
exist, each of those items is a rewrite of the same missing plumbing.

---

### 29. A renderer that can be tested

**Found while fixing something else, which is how this kind of gap is always found.** Two
defects in the itemised disk view shipped without a test — a stale read rendering one host's
containers under another host's name, and an error state with no way out — because there is
no jsdom, no happy-dom and no testing-library in the tree. `vitest` runs in the node
environment. **No component in this application can be rendered in a test.**

**What exists.** 2280 tests, almost all of the main process, and a genuine workaround in the
panel suites: they read `.tsx` files with `readFileSync` and assert regexes against the
source. That catches "somebody added a second call site" and cannot catch "this renders the
wrong thing".

**Why it ranks where it does.** Every renderer defect found across both waves so far was
found by reading code, not by running it. The operator only ever touches the renderer, the
stated goal is a tool stable enough to daily-drive, and the two largest new surfaces on this
plan — the job list and the inventory table — are both renderer work. Retrofitting tests
after those ship is how the gap becomes permanent.

**Size.** A day for jsdom, testing-library and the first real component test. Then it is
per-feature cost like any other test, rather than a project.

### 30. Two gaps in the gates themselves

Both found while building item 29, both predating it, and both the same species: a check that
exists and does not check.

**`npm audit` already fails, so the gate that runs it is decoration.** CI runs it as a step,
and it exits non-zero today on three transitive advisories that have fixes available. A gate
that is red before anyone touches it cannot report that a change made things worse — the
signal is indistinguishable from the standing noise. Either fix the three, or pin them with a
stated reason and make the gate assert *that* set rather than emptiness. **Half a day.**

**None of the tests are type-checked.** `tests/` belongs to no tsconfig, so `npm run
typecheck` covers `src/` and skips all 2333 test files. They are linted, which catches style
and unused variables, and not type-checked, which is what catches a test asserting against a
shape the code no longer has. A test that no longer compiles against its subject is the one
most likely to be quietly wrong. **A day, plus whatever the first run turns up — and it will
turn something up.**

**Why these rank at all.** The stated goal is a tool stable enough to daily-drive, and both
of these are places where the project believes it has a check and does not. That is worse
than a known absence, because it is budgeted for.

---

### 31. The firewall rules themselves, not a count of them

**Raised by item 24 rather than planned, and it needs a decision rather than an implementation.**

What shipped reads the firewall in both layers — the front end and the kernel beneath it,
because "ufw is inactive" is not "nothing is filtering" on a cloud image with a boot-loaded
nftables ruleset — and reports scalars: which tool, whether it is active, the default policy,
a rule count, a deny count, the zones. Every one of those goes through the single-line
unforgeable path, which is the strongest safety property this collector has.

**But an operator reading "ufw · 12 rules · in deny" cannot tell whether 3306 is open to the
world**, which is the question they came to ask. The next increment is a bounded, per-line
sanitised list of the actual rules.

**Why it was not built, and why that is a product decision.** A list of what is exposed on
every host is the single most attacker-valuable thing this feature could hold, and it changes
the threat model of the collector's output — which currently carries only counts and fixed
vocabulary, and would then carry addresses and ports. That is the same widening the 0.8.0
review caught when a metrics tool began returning a full service and port inventory under a
consent that described something narrower. It should be decided deliberately, with its own
line in the capability grid, not added because it is obviously useful.

**Size.** Days to build, and the decision is the part worth taking time over.

---

### 32. A retention horizon per event kind

**Raised by item 28, and it is a defect at a boundary rather than a missing feature.**

Job rows are kept for a year; alert events for ninety days. The runbook joins the two — "what
was run between this alert raising and clearing" — so it is bounded by the shorter of them.
The consequence is precise and wrong: **a host with a quarterly problem reads "this has never
fired here" while the job that fixed it in January is still on disk.** The evidence survives
and the anchor that would find it does not.

The honest fix is a longer horizon for the `alert` event kind specifically, which means
retention stops being one number and becomes a policy keyed on kind. That is a change to the
store's own retention rules, and item 28's author declined to smuggle it in — correctly, since
retention is the one part of that store that must not acquire exceptions casually. It is
cheap and it is somebody's deliberate decision.

**Size.** A day, most of it deciding what the second number should be and proving the pass
still terminates.

---

## The plan — six months, one focused person

Weeks are sequential because the constraint is one person, not one team. Where two items could be
parallelised by a second person, it says so. Each block names **what a user can see when it lands**,
because a block that ships nothing visible for a month is a block that needs justifying.

### Weeks 1–3 · Ship the cheap wins first

| Week | Build | What the user sees |
|---|---|---|
| 1 (½ day) | **19a. Disk alert** | A filling disk finally reaches a phone instead of a screen nobody is looking at |
| 1 | **21a. Docker itemised disk view** | Which images, volumes and containers are holding the space, per item, with honest per-item sizes |
| 2–3 | **18. Database operations — Postgres** | Replication lag, connection counts, table bloat, slow queries, on a connection the app already holds |

**Why this order and not the plumbing.** These cost three weeks between them, depend on nothing, and
are the only items on the page that are near-complete already. Shipping them first buys a release,
user feedback on the direction, and three weeks of thinking time on the job engine's one hard
question — which is worth more than three weeks of earlier plumbing.

### Weeks 4–9 · The plumbing

| Week | Build | What the user sees |
|---|---|---|
| 4–5 | **A. Durable store** | Nothing. This is the block to defend. |
| 6–7 | **C. Host facts** | Every host with its OS, version, pending updates and reboot flag — a screen worth having on its own |
| 8–9½ | **B. Job engine** | Long-running work that survives closing the panel, with a job list and history |

**The rule for these six weeks.** Do not let them stretch. Every one of them has an obvious "while I
am in here" extension, and each extension delays item 17 by its own length. A is three tables and a
retention rule, not a query language. B is detached execution and a status file, not a workflow
engine.

### Weeks 10–13 · The flagship

**17. Patch and update management.** Every host, its pending and security updates, staged apply,
reboot coordination with an ordering, a health gate between stages, and a hard refusal to reboot a
host that is a jump host for anything else in the workspace.

This is the release the whole plan exists for. At the end of it the product does something no GUI
SSH client does, for the task its user does most often.

### Weeks 14–21 · The maintenance product

| Week | Build | Note |
|---|---|---|
| 14–15 | **18. Database operations — MySQL/MariaDB** | Second engine; Mongo and Redis follow later at a week each |
| 16–17 | **20. Compose** | Label grouping exists; this is file discovery, validate, pull and redeploy as jobs |
| 18–21 | **5. Backups to real targets** | Destinations, retention, database dumps as jobs, and a restore test that actually verifies |

### Weeks 22–26 · Proof and the differentiator

| Week | Build | Note |
|---|---|---|
| 22 | **23a. Key inventory, read-only** | Which key opens which host, whose it is. One week, and nobody else has it |
| 23–24 | **19b. Alerting, the rest** | Hysteresis, inbox, the missing kinds. Needs A, which now exists |
| 25–26 | **23b. Key add and revoke** | Behind the three non-negotiable rules in its section |

### What that adds up to

At week 26 the app patches an estate, backs it up and proves the backup restores, answers database
health, manages Compose, alerts properly with history, and can tell you which keys open which hosts.
That is not a better terminal. That is the console this operator does not currently have.

**After week 26, in rough order and no longer scheduled:** 6e cron editing, 24 security posture,
26 capacity trends, 14 change log, 27 rule engine, 28 runbooks, 18 for Mongo and Redis, then 22
Kubernetes lifecycle and 7 the credential proxy — with 7 promoted immediately if API keys turn out
to be a live problem for real users, because it is the most strategically aligned item in this
document and only its reach keeps it low.

---

## How the ranking moves if the customer moves

The ordering above is a consequence of the operator in "Who this is for". These are the reorderings
that follow from plausible alternatives, written so that a change of target is a deliberate decision
rather than a slow drift in the backlog.

| If the customer becomes… | What rises | What falls | Net effect on the plan |
|---|---|---|---|
| **A team of three to five** | 14 change log (4 → 8), 28 runbooks, shared approvals | Little | Change log moves into the first six months. The plumbing does not change. |
| **Anyone under a compliance regime** | 14 (4 → 9), 23 access review, 24 posture | 20, 21 | 14 and 23 move ahead of Compose. A gains an audit-retention requirement on day one. |
| **A containerised estate** | 20 Compose (6 → 8), 22 Kubernetes (5 → 8), 21 | 17 patching (hosts matter less), 23 | Compose and Kubernetes move ahead of backups. Patching stays, aimed at nodes. |
| **Local-first developers** | 1 pm2 supervision (4 → 8), 8 Ghostty session restore | 17, 5, 23 — all fleet features | A different product. The plumbing survives; almost nothing else does. |
| **Enterprise SRE teams** | — | Everything | Do not. They have Ansible, Prometheus and PagerDuty, and every item here competes with a better incumbent. |

**The pattern worth seeing.** A and B survive every column. The three enablers are the only things on
this page that are correct regardless of which customer is chosen, which is a second and independent
argument for building them early: they are the part of the plan that cannot be wrong.

---

## Dependencies, stated plainly

- Everything that **remembers** follows **A**.
- Everything that **runs longer than a minute** follows **B**.
- **Patching** follows **C**, and is the reason C is not optional.
- **Backups** follow the scheduler in **B**, or the app grows two schedulers.
- **Alert channels** follow the **credential proxy** if that is going to own third-party API keys, or
  they grow two credential stores.
- **Modules** precede heavy features, or they become a refactor instead of a shape. Already done.
- The **third-party extension API** never precedes the **Tauri** decision, because an extension API
  is a compatibility promise and rewriting the host underneath one is how migrations die.
