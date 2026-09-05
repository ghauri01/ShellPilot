# ShellPilot roadmap

What we intended to build, what each one actually rests on in the code today, and what is genuinely
hard about it. It began as sixteen items and grew to thirty-two as the work found things the plan
had not; the next section says where all of them now stand, and the rest of this document is kept
because the reasoning behind an ordering outlives the ordering. **Items 33–48 were added on 5 Sep
from a gap audit** — thirty operational areas checked task by task against the code at 0.15.2 —
and they are the section to read if the question is "what do we build next".

Written after 0.8.0, and maintained since: 0.9.0 through 0.9.3 shipped
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

## Where this stands, as of 0.16.x

**The three items that were "part done" are closed.**

*Item 18* now covers SQL Server, the fifth and last engine, verified against a
real server rather than from the documentation — which changed three readings:
`user connections = 0` means unlimited, an empty availability-replica list means
"no AG configured" rather than "no replicas healthy", and a NULL in the backup
history means never rather than long ago.

*Item 23*'s write half is opt-in rather than unreachable. Every blocker the
adversarial review raised has been built — the independent re-authentication,
the judgement that refuses a pooled or too-early session, the `systemd-run
--user --scope` watchdog ladder — and the gate comment that still said otherwise
was three of those behind. What remains unobserved is one thing, named where the
operator turns it on: nobody has watched the rollback fire on a real RHEL 9
server with `KillUserProcesses=yes`. A gate nobody can open is a gate nobody can
test, which is why it is now a switch.

*Item 1*'s remote half is a refusal with an argument, not a gap: supervising
over a held-open SSH channel is a reliability promise the transport does not
make. The successor worth building is named in `src/shared/processes.ts` — a
`systemd --user` unit editor and a `systemctl --user` reader, letting the
server's own supervisor own the restart policy.

*Item 21b* has now been run against a real podman 5.8.4, and the caveat was
pointing at the wrong thing. Every template renders identically and `system df`
matches, so no parsing changed — but `resolveBinary('docker')` was hard-coded at
nine call sites and a stock podman install has no `docker` binary at all, so the
panel reported the runtime absent on a server full of containers. Writing the
test found a second bug: `logs` was the one command that did not resolve its
binary, making it the only thing that failed without sudo and worked with it.
Port mappings remain unverified — podman nested in Docker cannot publish a port
— and nothing was changed on the strength of that reading.

## Where this stood, as of 0.13.1

**Every item in the matrix below is shipped, cut, or gated on something only a real host can
answer.** Four releases did it: 0.10.0, 0.11.0, 0.12.0 and 0.13.0, with 0.13.1 as a fix.

| | |
|---|---|
| **Shipped** | 24 of the 26 matrix rows, plus items 29–32 which were raised by the work rather than planned |
| **Cut, deliberately** | Ghostty (8), Tauri (10), n8n (9) and DNS/TLS — see the cut list |
| **Built but switched off** | Item 23's write half: key revoke. `ACCESS_WRITE_ENABLED` is `false` |
| **Not built, and correctly so** | Item 15(b), a third-party extension API. 15(a) — optional first-party modules — shipped |
| **Tests** | 2,215 → 4,648 |
| **Runtime dependencies added** | None. Every item above is built on `node:sqlite`, `ssh2` and what was already here |
| **Gap audit, 5 Sep** | Nineteen areas partial, five near-full, six refused by decision. Items 33–48 in "The gap audit" below say exactly what is missing in each and in what order to close it |

**The one thing waiting on the physical world.** Item 23 can stage a key revoke, and the code is
written and tested. It is off because a claim in its design has never been checked against a host
that behaves the way the claim assumes: a RHEL 9 machine with `KillUserProcesses=yes`, where ending
the session kills the user's processes. Stage a revoke there, end the session, and see whether the
authorized_keys file comes back. Until someone does that, shipping the write would be shipping a
rollback nobody has watched roll back. The read half is shipped and useful on its own.

**What has never met a real estate.** Patch management, detached execution, Kubernetes drain and the
access collector are tested against real servers, real Postgres and MySQL, a real MinIO and a real
`kind` cluster — each of which found bugs no double did — but not against a production fleet under
load. That is the next thing that will teach us something, and it is not a thing more tests can
substitute for.

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
| **4b. Kubernetes** | **Built, read-only plus one write.** Pods, nodes, deployments/statefulsets/daemonsets with ready-versus-desired, namespace events, `kubectl top` where a Metrics API answers, and a diagnosis view. The first mutation was `kubectl rollout restart`; cordon, uncordon, drain and a one-command exec followed under item 22. It deliberately does not switch contexts, apply, scale, or delete anything, and `src/shared/kubernetes.ts` states why in the file rather than in a commit message. This document previously said Kubernetes should stay "separate and later"; it arrived earlier because the Docker module's failure classification and sudo discipline transferred wholesale. |

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

## The gap audit — 5 Sep, against 0.15.2

Every write-up above says what an item was meant to do. This section says what each operational
area can and cannot do **today**, read from the code rather than from the write-ups, so that the
next round of building starts from the gap and not from the intention.

**How it was done.** Thirty operational areas — the ordinary week of the ten-to-fifty-host operator
from "Who this is for" — were broken into their typical tasks and each task was checked against
the working tree at `bb4620b`, in eight independent read-only audits. Every task was classified
one of four ways, and the fourth is the one that matters most:

| | |
|---|---|
| **DONE** | Achievable in the app, end to end, with tests |
| **PARTIAL** | A real piece exists; the task as an operator would phrase it is not covered |
| **MISSING** | Nothing usable exists |
| **REFUSED BY DESIGN** | The code or this document states a deliberate non-goal, with a reason. **Not a gap.** Listed so nobody rebuilds the argument from scratch |

Five areas came out near-complete (monitoring, alerting, Compose, frp, inventory). Six are
refused or absent by decision (Kubernetes backup, DNS/TLS, documentation, vulnerability
scanning, a configuration DSL, unattended patching). The nineteen in between are what this
section is about, and they are numbered from 33 onward so they can be argued with the way
items 1–32 were.

### Three findings that reorder the work

**1. Almost every write the operator asks for lands on one missing surface.** The job engine
shipped in full — waves, health gate, reboot-and-verify, detached execution, approval record —
and **no renderer composes a job.** `jobs.run` is called from exactly one place,
`PatchPanel.tsx:294`, and `jobs.list`/`jobs.get` are called from nowhere; job history is visible
only through the change log. So "restart nginx on twelve hosts", "install a package everywhere",
"push this config", "run VACUUM in a window I chose" are all the same missing thing wearing
different clothes: a job composer plus a handful of *typed* step kinds whose text is built in
main rather than typed by hand. Item 33 is that composer and item 34 the step kinds. Half the
partial areas below close on those two.

**2. Five refusals share one precondition, and it is a lab host.** Firewall edit
(`posture.ts:118-125`), host quarantine (`posture.ts:100-105`), per-account key revoke
(`index.ts:1257-1272`), sudoers edit and SSH key rotation all say, in their own words, "not until
there is a staged write with an independent re-authentication and an automatic revert." That
protocol exists — `access.ts:2814-3140`, 56 tests against a real shell — and is switched off at
`ACCESS_WRITE_ENABLED = false` pending the RHEL 9 `KillUserProcesses=yes` check named at the top
of this document. Nothing else on this page unblocks as much per day of work as that check.
Item 36.

**3. Three defects were found that are not features.** `policyEngine.ts:425` classifies a
statement by its leading verb, so `SELECT pg_terminate_backend(123)` and `ANALYZE` are `read`
and run through `query_database` with **no approval** under the default group. `ComposePanel.tsx:162-181`
mints a job approval without a dialog, which is correct for a one-host `pull` and wrong the
moment `sudo` makes the plan ask for `confirm`. And `assessCommand`'s docker/podman destructive
rule (`broadcast.ts:223-230`) is not applied to `execute_command`, so an agent's `docker volume rm`
is graded `high` only if it says `sudo`. Item 35, and it goes first.

### Corrections to this document

Found while auditing, fixed in the sections above where they were one-line; listed here where
they were not.

- **Item 32 is shipped**, not open: `EVENT_RETENTION_TIERS` at `history.ts:440-458` keeps alerts
  400 days and `RUNBOOK_LOOKBACK_DAYS` mirrors it. Two comments still say JSONL logs have no
  retention (`shared/changelog.ts:154-158`, `services/changelog.ts:57-63`); they do, since
  `jsonlPrune` was wired at `index.ts:884-892`.
- **B4 is in code**, not remaining: stages, gate, reboot-and-wait and jump-host exclusion are all
  in `jobRunner.ts:962-1214` and tested. The matrix row and the split table were wrong.
- **Kubernetes execs into pods.** `modules.ts:259` and the 4b row above still said it never
  would. Exec shipped behind `approvalFor`/`verifyApproval` (`kubernetes.ts:74-79`).
- `jobs.ts:316-329` describes an `access` job kind that `JOB_KINDS` does not contain and
  `access.ts:2462` says was removed. `access.ts:385` mentions a `sudoIsProxy` field that does not
  exist on `AccessAccount`. Both are stale comments, not code.
- The first of item 23's two follow-ons ("the panel must state the scope before selecting a
  target") is done — `ACCESS_WRITE_SCOPE` renders at `AccessPanel.tsx:421`. The second, the
  missing approval-log row, is not, and is folded into item 35.

### Where every partial area stands

One row per area. "Done" is the part an operator can lean on today; "gap" is the exact thing
missing, with the item that closes it. Sizes are for one focused person.

| Area | Done today | Exact gap | Item |
|---|---|---|---|
| **Linux fleet** | Patch apt/dnf/yum/zypper/pacman/apk; security counts where the distro publishes them; reboot waves with boot-id proof, health gate, jump-host and same-wave-DB refusals; failed units read | No package install/remove/hold; no `systemctl` verb; no fsck/LVM/mount; no "kernel installed vs running" fact. OS release jumps refused on the patch path (`patch.ts:133-136`) and should stay so | 34, 46 |
| **Fleet automation** | Broadcast with blast-radius confirm; detached durable jobs; nine fact sources hourly; event rules with pinned approval | **No job composer or job list in the renderer.** No fleet file push. No user primitives. Rules have no time trigger (refused: `rules.ts:6-16`). No tag-seeded target pick, no stop-on-first-failure | 33, 34 |
| **Access & SSH** | Every `authorized_keys` fingerprinted and attributed; locked/expired accounts; admin groups; last login; jump chains | Key add/revoke built, **switched off**, connecting account only. Sudo is group membership, not `sudoers`. No export. No service-account classification | 36, 46 |
| **Security** | Firewall in both layers with rule lines behind their own consent; sshd vs baseline; SELinux/AppArmor mode; failed logins; OOM kills; cert inventory with 30-day alert; drift over seven watches; app-side audit | No firewall/sshd/MAC writes (refused until 36); no secrets rotation; no auditd posture; per-package security list absent; drift watches fixed | 36, 43, 46 |
| **Docker** | Start/stop/restart graded; exec; logs one-shot and followed; stats; `system df -v` per item; reclaim by id with re-preview; health status parsed | No `pull`/`build` as a job (comment-only today); networks reclaimable but never listed; no targeted engine upgrade; no scanner consumer; podman unproven | 42 |
| **Compose** | Discover, parse, declared-vs-running, edit image tag with stale-check, `pull` and `up -d` as jobs, `.env` names only | Per-service scope built but not wired; no compose `restart`; validation errors surface as "nothing this parser could read"; `depends_on`/volumes/`restart:` parsed and not rendered; no `.env` write; approval minted without a dialog | 35, 42 |
| **Kubernetes** | Pods with reason-over-phase, workloads ready/desired, events, describe, previous logs, `top`, PVCs, ingress, RBAC bindings, secret names, deprecated APIs, helm list; rollout restart, cordon/uncordon, drain with seven refusals, exec | No node conditions/allocatable/taints; no requests/limits; no HPA; PDBs only inside the drain; no Role rules; no PV/StorageClass; no cert expiry of any kind; helm list parse unproven | 39 |
| **K8s lifecycle** | Each primitive as a separate click; API scan with stated blind spots | Nothing chains cordon → patch → reboot → uncordon; the job engine does not know a host is a node; gate is systemd-only. Upgrades, helm upgrade/rollback, `rollout undo` contradict the module's own reasoning | 40, 41 |
| **PostgreSQL** | Dump to local/SFTP/S3 with read-back; replication, archiver, vacuum age, connections, locks, sizes, `pg_stat_statements` — nine judged questions | Dumps are manual, plaintext, 512 MB in memory, no restore. No slots/`pg_wal` size. Slow queries have no alarm level. Locks show the blocked, not the blocker. No write of any kind (routed to jobs by `dbOps.ts:33-35`) | 37, 38 |
| **MySQL/MariaDB** | As Postgres, plus binlog inventory and buffer pool | No top-N slow statements (only whether the log is on); no binlog purge; no `KILL`/`OPTIMIZE`; no binlog position in dumps | 37, 38 |
| **MongoDB** | Replica set, oplog window, index usage, connections, current ops, sizes, asserts | **No `mongodump`** (stated absence, `backupTargets.ts:702`); no index build monitor; `mongos` out of scope; index sizes never populated (`dbOps.ts:700-720` does not pass `sizes`) | 37, 38 |
| **Redis** | Memory, eviction, persistence, replication, slowlog, keyspace, cluster, clients | No backup path at all; AOF, Sentinel and Cluster judged but never exercised; no trend | 37, 38 |
| **Backup/DR** | Encrypted app bundle to three destination kinds, retention with three refusals, read-back + decrypt verify; PG/MySQL dumps | The bundle is app state, never host data; dumps have no schedule, encryption, retention or restore test; no volume backup; see 38 | 38 |
| **Logging** | journald/file/container tail across hosts with preflight, pause buffer, priority/since, client filter; K8s pod logs one-shot | No search across hosts or history; no error-rate kind; no rotation read; auditd/sudo logs tailed as files only | 43 |
| **Incident response** | Inbox, ack, snooze, dedupe, flap damping, hysteresis, 400-day history; runbook per kind; rules alert → job | No alert → log deep-link; no systemd restart button; no rollback of anything; no DB restore; quarantine refused until 36; no incident span | 43, 44 |
| **Change management** | Waves with gate; drift; change log over four records | No maintenance window; no rollback plan on the approval; no per-package version inventory | 44, 46 |
| **Housekeeping** | Docker reclaim by id | Nothing reads logs, tmp, journald usage, autoremove candidates, LVM snapshots, stale K8s objects; dead users/keys have no verdict | 45 |
| **Storage** | Root-filesystem disk and inode %, alerted at 85; PVC request and capacity; Docker disk per item | **`/` only** — a full `/var` or `/data` is invisible. Inode is measured and never stored. No LVM, mdstat, SMART, zfs, NFS read of any kind | 47 |
| **Capacity** | cpu/memPct/diskPct trends over 7 d full + 90 d hourly, forecast with eight refusals and a 90-day horizon | No inode trend (one day); no DB growth series; no K8s allocatable-vs-requested; no fleet-level "N hosts cross in 30 days"; nothing over MCP | 47 |
| **OpenVPN / WireGuard** | Client side is complete: sanitised import, OTP, split/full tunnel, management-interface health; WireGuard userspace *and* system mode (Linux/Windows), peers, allowed IPs, handshake age, bytes, keygen with derived public key | Nothing touches a VPN **server**: no `wg set`, no easy-rsa, no CRL. No `vpn-down` alert kind. Client cert `notAfter` never read (`<cert>` is opaque). `latencyMs` exists in the type and no driver fills it. Sidecar reports one handshake and a peer *count*, not per-peer rows | 48 |

### What is refused and stays refused

The audits found these written down, each with a reason that still holds. They are collected here
so a future request can be answered by citation rather than re-argued.

| Refused | Where the reason is | Note |
|---|---|---|
| OS release jump inside a patch run | `patch.ts:133-136`, `:203` | A separate opt-in "release jump" job is not formally refused; every argument in `patch.ts:30-62` weighs against it |
| App-side schedules and time-triggered rules | `patch.ts:37-67`, `rules.ts:6-16` | Host-side cron edit (6e) is the sanctioned route. A window *filter* on rules does not contradict this |
| `prune` in any spelling, `-a`, `--force`, build-cache removal | `docker.ts:568-600`, `:1972-1974` | Blast radius must be a literal list of ids |
| `compose down`, `down -v`, `rm`, `kill`; `.env` values on screen | `compose.ts:1070-1085`, `:28-67` | Shipped stricter than the write-up asked |
| Kubernetes context switch, apply, scale, edit, single-pod delete, agent reach | `kubernetes.ts:34-65`, `tests/jobsNotExposed.test.ts:865-941` | `rollout undo` and `helm upgrade`/`rollback` fall under *edit* by the file's own taxonomy — see item 44 |
| Any write from the database operations panel | `dbOps.ts:16-83` | "If a session must die, that is a job" — item 37 is that job |
| sshd_config write, `systemctl restart sshd`, `setenforce`, fail2ban ban/unban | `posture.ts:127-139` | Sawing the branch off |
| Drift push-to-fix | `drift.ts:1040-1063` | A canary upgraded first looks exactly like a host that drifted |
| Firewall edit, host quarantine — **conditionally** | `posture.ts:100-125` | Precondition is item 36's protocol, proven on a real host |
| `sudo` in the access write | `access.ts:2307-2313` | The decision per-account revoke and sudoers edit must overturn first |
| SQL Server operations | `dbOps.ts:4354-4359` | Never run against one |
| `KEYS`/`SCAN` on Redis | `dbOps.ts:78-83` | Big-key analysis needs an argued exception |
| Full tunnel in WireGuard system mode; macOS system mode; a kill switch; any script directive in a VPN config; agents starting frp or seeing an endpoint or key; an elevated run restarting itself | `drivers/wireguard.ts:1445-1464`, `docs/VPN.md:50-62, 289-294`, `parsers/ovpn.ts:49-175`, `policyEngine.ts:520-524`, `managerApi.ts:34-38` | Unchanged |
| Vulnerability scanner, config DSL, metrics warehouse, ticketing, DNS/TLS management, Kubernetes manifests, unattended patching | The table above this section | Unchanged |

---

### 33. A job composer, and a job list

**The finding above, made concrete.** `src/preload/index.ts:168-199` exposes
`list/get/run/cancel/setDetached/capabilities/onProgress/onOutput`; IPC is wired at
`index.ts:1812-1830`; `planJob` (`jobs.ts:442`) sizes the confirmation on the largest cohort;
`jobApprovalFor` (`:506`) mints the record; `planWaves` (`patch.ts:711-728`) splits targets; the
gate and halt are tested (`tests/jobStages.test.ts:190-396`). `PatchPanel.tsx:286-312` is the only
caller and is a copy-able template. `RulesPanel.tsx:245-255` already composes a multi-step
`command` spec from a textarea.

**What is new.** A `JobsPanel` — list, detail, live output, cancel — and a "New job" composer:
steps textarea, hand-picked targets, wave size, gate toggle, an optional `reboot` flag on a step,
and the confirmation dialog `planJob` asks for. "Re-run as new job" is allowed only if it
re-mints the approval; a saved *template* may hold steps and never targets (`broadcast.ts:13-15`).
Two small broadcast follow-ons ride along: seeding a selection from a folder or tag — a seed,
never a persisted set — and "halt remaining hosts on first failure", which the engine already
does per host (`tests/jobRunner.test.ts:328`) and not across hosts.

**What it must not do.** Reach the bridge (`tests/jobsNotExposed.test.ts`), skip the dialog the
way the rules surface refuses a "run now" button (`rules.ts:613-619`), or run a gate without the
sampler on (`GATE_SAMPLER_NOTE`, `patch.ts:1090-1093`).

**Size.** 1–1.5 weeks. Everything in item 34 is a step kind inside it.

### 34. Typed step kinds: service, package, file, user

This document's non-goal table says the useful subset of configuration management is "about eight
idempotent operations — package, service, user, file, key, line-in-file — and everything past
that is a language." Item 33 gives those operations somewhere to run; this item is four of them,
each a builder in main so the approval record holds structured intent rather than free text, and
each an OFF-by-default module (`modules.ts:82-95`).

| | Exists | New | Refused neighbour | Size |
|---|---|---|---|---|
| **34a service** | Failed units and `unit:` facts (`fleetSampler.ts:172-183`); `assessCommand` already grades `stop\|disable\|mask` destructive and `restart\|reload` elevated (`broadcast.ts:203,215`); `DockerAction` as the typed-action precedent | `start\|stop\|restart\|reload\|enable\|disable` on a unit name validated against the fact set; a "Restart" affordance on a failed-unit row; a verify step reusing `buildRebootVerify`'s failed-units parse (`patch.ts:303-359`); exclude `ssh.service`/`sshd.service` (`posture.ts:113-116`); reuse `sameWaveDatabaseBlocks` as a refusal for `stop` on a DB unit | Restart from a *remembered* runbook command is refused (`runbooks.ts:42-45`); from a live fact it is not | 1–1.5 wk |
| **34b package** | `patchCommandFor` per manager (`patch.ts:138-238`); `install\|remove\|purge` already `elevated` (`broadcast.ts:217-222`) | `install\|remove\|hold\|unhold` per manager (`apt-mark hold`, `dnf versionlock`, zypper `al`, pacman `IgnorePkg`, apk has no hold); a JobKind `'package'` in `JOB_KINDS` (`jobs.ts:342`); "which hosts have X at Y" needs item 46's package facts | `autoremove` inside a patch run (`patch.ts:133-137`) — a separate typed job is fine | 1.5–2 wk |
| **34c file push** | Single-host SFTP (`sftp.ts:89-97,141-186`); drift's per-file read and three-way verdict; cron edit's read-modify-write with a host-side "file has not moved" check and approval (`cronEdit.ts:19-52`) — the pattern to copy | Content sha256 in the step text so `verifyApproval`'s literal comparison (`broadcast.ts:742-751`) covers the bytes; per-host pre-read shown as a diff; backup-then-rename like `access.ts:2267-2278`; optional post-step (`nginx -t && systemctl reload nginx`, which is 34a) | Drift "never writes a file back" (`modules.ts:171`) is drift's scope, not a product refusal. Directory upload stays refused (`sftp.ts:167`) | 2–3 wk |
| **34d user** | Account inventory (`access.ts:1-30`); `userdel\|groupdel` destructive (`broadcast.ts:190`) | `useradd`, `usermod -aG`, `usermod -L`, `chage -E`; `userdel` with home removal as its own typed-confirm; a password must come from the vault and never appear in a step string (pattern redaction is not enough) | Key add/revoke is item 36, not this | 2 wk |

**Order.** 34a first: it is the smallest, it is the one the inbox needs (item 43), and it proves
the typed-step shape before 34c spends three weeks on it.

### 35. Defects first: the classifier, the silent approval, and the missing rows

Not a feature. Four things the audit found that should land before anything above is built on
top of them, because each is a hole in a safety property this document claims.

1. **`policyEngine.ts:425`.** The `READ` regex keys on the leading verb, so `SELECT
   pg_terminate_backend(…)`, `SELECT pg_switch_wal()`, `SELECT pg_stat_statements_reset()` and
   `ANALYZE` are `read` → `low` risk → no prompt with `databaseAccess = allow`, which every
   built-in group grants (`:410-411`). Treat `pg_terminate_backend`, `pg_cancel_backend`,
   `pg_switch_wal`, `*_reset` as mutating and move `analyze` out of `READ`. A day.
2. **`ComposePanel.tsx:162-181`** auto-fills the phrase and calls `jobs.run` with no dialog.
   Correct while `confirmationFor(ordinary, 1)` is `none`; wrong once `sudo` makes the step
   `elevated`. Reuse the job confirm dialog whenever `jobPlan.confirmation.kind !== 'none'`. Half
   a day, and every new compose verb inherits it.
3. **`execute_command` risk.** `mcpServer.ts:833` grades `high` only on `sudo`. Apply
   `assessCommand`'s docker/podman rule (`broadcast.ts:223-230`) so `docker volume rm` from an
   agent is `high`. A day.
4. **Approval-log vocabulary.** `JobApprovalEntry.surface` is `'broadcast' | 'job'`
   (`jobs.ts:557`) and `ApprovalSurface` is `'broadcast' | 'job' | 'k8s-exec'`
   (`broadcast.ts:603-605`). Key add/revoke (`index.ts:1309-1400`), `kubectl exec`, cordon, drain
   and every item-37 statement need a row in `shellpilot-job-approvals.jsonl`. Widen both unions
   once — `'access'`, `'k8s'`, `'db-statement'` — so item 36's first real revoke is recorded.
   Half a day.

**Size.** A week, all four. Nothing else on this page should merge first.

### 36. The access write gate, and the five things behind it

**36a. Flip `ACCESS_WRITE_ENABLED`.** The code is complete: plan and blocks
(`access.ts:2528-2751`), both builders (`:2753-2812`), staged write with backup, count check,
`chmod 600`, watchdog and arming proof (`:2860-2930`), verify and disarm (`:3057-3140`),
`AccessCommitter` over a fresh unpooled session (`services/access.ts:218-341`), main-side
re-derivation (`index.ts:1309-1334`), and the scope statement on screen. What flips it is not
code: stage a revoke on a RHEL 9 host with `KillUserProcesses=yes` and no lingering, end the
session, and watch whether `authorized_keys` comes back. The residual the design admits is at
`docs/plans/roadmap-execution.md:603-608` — the arming proof catches a watchdog that never
started and cannot catch one killed afterwards — and the five things to try are at `:614-625`.
Then rewrite the guard test `tests/accessWrite.test.ts:51-58`, keep `:62-84`, and decide whether
a host whose launcher fell through to `nohup` is allowed at all (nothing refuses it today,
`:3018-3019`). **Days, plus a lab host.**

**36b. Sudoers read.** Independent of the gate. Today "sudo" means membership of
`ADMIN_GROUPS` (`access.ts:387`) and the comment at `:1048` says so. Read `/etc/sudoers` and
`sudoers.d/*` as root, parse `Defaults`, specs, aliases, `NOPASSWD`; per-account "can run X as Y
without a password". Attacker-controlled text: tagged-line format, per-value cap, and — like
firewall rule lines — behind its own consent line, not on by default. **1–2 weeks.**

**36c. Per-account revoke.** Blocked in main, not the planner (`index.ts:1257-1272`). Needs a
per-host command (the connecting-account write resolves `$HOME` on the host, `:2860`, so one
text covers a selection; a per-account write cannot), which turns the confirmed-command equality
into per-host equality — the shape `AccessChangePlan.disarm` already has (`:2503-2505`) — and
needs `sudo` in the write, which `:2307-2313` refuses on the ground that an escalated write is
indistinguishable in the sudo log from an attacker. That refusal must be overturned in writing
before a button. **1–2 weeks after 36a.**

**36d. Firewall edit.** Refused at `posture.ts:118-125` until "a staged write, an independent
re-authentication and an automatic revert" exist — 36a's protocol, pointed at `ufw`/`nft`.
`firewalld --timeout` is native and is the safe first slice; `nft list ruleset` → `nft -f` is
the snapshot/restore for the rest. Verify with a fresh session, which proves only that SSH still
passes — the one thing the app *can* prove. Post-change re-read of the rule listing closes the
"reported done, changed nothing" class. **2–3 weeks after 36a; firewalld alone, one.**

**36e. Host quarantine.** 36d with a fixed ruleset (operator's source only). **2 weeks after 36d.**

**Also behind the gate.** SSH key rotation = add → verify → revoke with the old key under
`protect` (`access.ts:2415-2417`) until the fresh session succeeds (2 weeks after 36a).
Sudoers *edit* needs everything 36c needs and would be the first root-escalated write in the app;
recommend not before 36c lands. Local secret-age tracking on vault entries (`vault.ts:47-48`)
needs none of this and is days.

### 37. A database statement job

**Why one item and not twelve.** `dbOps.ts:16-83` refuses every write from the operations panel —
terminate, `VACUUM`, `PURGE BINARY LOGS`, `OPTIMIZE`, `createIndex`, `killOp`, `BGSAVE`,
`CONFIG SET` — and at `:33-35` names where they belong: "that is a job: it goes through the job
engine's approval model." The job engine has no database target. `JobStep.command` is a shell
string (`jobs.ts:346-347`), `JobTargetRef` is a server (`:405-409`), and `ApprovalSurface` has no
database value. Every one of the twelve is one to three days *after* this surface exists and
weeks *without* it.

**The shape.** Mint `approvalFor({surface:'db-statement', commands:[<the literal statement>],
targets:[{serverId: db.id, serverName: db.name}]})` when the human types the phrase, verify with
`verifyApproval` immediately before executing — the pattern `kubernetes.ts:404-422` reuses
unmodified for `kubectl exec`. Run on `openTransient()` (`db.ts:276`), never the shared client;
bind the value where the engine allows and where it cannot (`PURGE … TO '<file>'`) use a
throwing builder enumerated in a `DB_WRITE_STATEMENT_BUILDERS` list so
`tests/dbOpsRegressions.test.ts:78-127` can see it. Its own risk plan — `destructive`,
type-to-confirm with the pid or file name as the phrase. Output to history, redacted. Never in
the bridge's import closure, and close item 35.1 in the same change.

**Then, per engine, in the order an operator would ask:** PG terminate backend and kill blocker;
MySQL `KILL`; MySQL `PURGE BINARY LOGS TO` with a preflight that reads every replica's current
file *from the replicas* (cross-connection, new); PG `VACUUM`/`ANALYZE` and MySQL
`ANALYZE`/`OPTIMIZE` with the lock-time warning the refusal already wrote; Mongo
`createIndexes`/`dropIndexes` plus the in-progress build monitor that `serverStatus` zeroes
today (`dbOps.ts:2612`); Mongo `killOp` fetching `command` for the one opid named; Redis
`BGSAVE` with a poll on `rdb_bgsave_in_progress`; Redis `CONFIG SET` for `maxmemory-policy`.

**Reads that ride along and need no surface** (each 1–3 days, fixtures required): PG
`pg_replication_slots` and `pg_ls_waldir()`; a PG slow-statement threshold in `DB_THRESHOLDS`
(the judge is `ok`/`unknown` only, `:1604-1625`); the PG blocking *tree* (the blocker row is not
fetched unless it is itself blocked, `:1002`); MySQL top-N from
`performance_schema.events_statements_summary_by_digest`; Mongo index sizes (the collector never
passes `sizes`, `services/dbOps.ts:700-720`); Redis `CONFIG GET dir dbfilename`. Fixtures for
Redis AOF, Sentinel and Cluster and a Mongo sharded cluster remain captured-or-nothing
(`tests/fixtures/dbops/README.md:8-14`).

**Size.** 2–3 weeks for the surface; then 1–3 days per action.

### 38. Backups, the second half

Item 5 shipped the bundle: encrypted, three destinations, retention with three refusals, read
back and decrypted after every write. The audit found the *database* half is thinner than the
README row implies, and the bundle never contains host data.

**What a dump proves today** (`services/backup.ts:828-923`): the binary exited 0, stdout was
non-empty, the bytes landed and read back with a matching sha256. It does not prove the SQL is
loadable. `DumpRunReport` "has no retention and no restore test, because it is not an encrypted
bundle and nothing here can open it to check" (`shared/backup.ts:490-493`). Dumps are manual —
`backupTick` (`:975-996`) iterates bundle destinations only — plaintext, 512 MB in memory
(`MAX_DUMP_BYTES`), and refused for any database behind a bastion, a VPN or a URI
(`backupTargets.ts:716-727`).

**In order:**

1. **Schedule, stream, encrypt, retain** — the four things the bundle has and the dump does not.
   Per-database schedule on the existing tick; stream to a temp file instead of a buffer;
   encrypt with the destination's passphrase; a retention class for dumps that
   `planRetention`'s three refusals cover. 1 week.
2. **Dump on the remote host over SSH** as a job, which is what makes bastion/VPN databases
   dumpable and is the only way a large dump ever finishes. Needs the detached path. 1–2 weeks.
3. **`mongodump --archive --gzip`** and a Redis path. Mongo is a stated absence, not a refusal
   (`backupTargets.ts:702-703`), and `--uri` is the *correct* form for it — which inverts the
   URI refusal above and needs a decision on how the credential reaches `mongodump` without
   touching the command line (`shared/backup.ts:449-452`). Redis has no stdout dumper: either
   `BGSAVE` (item 37) then copy `dir/dbfilename` off a host that is a configured server over
   SFTP, or `redis-cli --rdb`. 1 week each.
4. **Restore into a scratch database** — the only restore test that means anything for a dump.
   Needs a target, a scratch-DB policy (DDL, `destructive`), streaming and a job; sits on item
   37. 1–2 weeks per SQL engine.
5. **Restore the bundle's siblings.** `psql < dump` / `mysql < dump` as a job with a typed
   phrase. Host *file* restore is out of scope: the bundle is app state and the README should
   say so where it says "everything".
6. **Binlog position** in MySQL dumps (`--source-data=2`) and `pg_dumpall --globals-only`. Days.

**And the one that is not a database.** A failed scheduled backup reaches a desktop
`Notification` (`index.ts:3517-3531`) and nothing else — no webhook, no inbox row, no history.
`job-failed` is *not* emitted for backups; it comes only from the renderer's job watcher
(`FleetWatcher.tsx:243-250`). A `backup-failed` STATE kind: add to `ALERT_KINDS` and
`STATE_ALERT_KINDS`, a coverage source, a destination-not-host subject (the `hostId: null`
precedent at `index.ts:2809-2811`), raise from `onNewFailure`, resolve on the next `report.ok`,
and surface `skipped` — a vault-locked destination that never runs is the silent failure the file
already warns about (`backup.ts:930-936`). The `Record<Kind,…>` tables fail to type-check until
filled, which is the guard. **2–3 days, and it should go before anything else in this item.**

### 39. Kubernetes reads that are cheap and missing

All reads, all per-`--context`, all with their own `K8sRead` verdict, none agent-reachable. Each
is a few days and none needs a new principle.

| Read | New | Size |
|---|---|---|
| **Node conditions, allocatable, taints** | `MemoryPressure/DiskPressure/PIDPressure`, `.status.allocatable`, `.spec.taints` via jsonpath, keeping kubectl's computed STATUS column for the reason at `kubernetes.ts:1036-1040`; optionally correlate with the host's `unit:kubelet.service` fact, which the sampler already records and nothing consumes | 2–3 d |
| **Requests/limits, node allocatable vs requested** | `.spec.template.spec.containers[*].resources` per workload; a quantity parser (`CPU_RE`/`MEM_RE` at `:1051-1052` validate and do not convert); "no requests set" is an answer, not a gap | 3–5 d |
| **HPA** | `get hpa` → min/max/current/desired/metrics; `<unknown>` renders as unmeasured, never 0 % | 2–3 d |
| **PDBs as a view** | Everything exists inside the drain preflight (`:1635-1652`, `:1849-1871`); add a namespace-scoped read to `buildK8sResourcesCommand` and a per-workload "covered by N budgets / disruptions allowed" column. `matchExpressions` stays "cannot evaluate", not skipped | 1–2 d |
| **Certificates, three ways** | (1) Add `/etc/kubernetes/pki`, k3s/rke2 `server/tls`, `/var/lib/kubelet/pki` to the posture cert roots (`posture.ts:828`) so the existing `cert-expiry` kind fires for control planes — **one day, and it is the best-value line in this table**; (2) kubeconfig client cert or token `NotAfter` decoded on the host, never echoed; (3) cert-manager `Certificate` Ready/`notAfter`/`renewalTime`, CRD absent being a normal answer | 1 d / 2–3 d / 2 d |
| **RBAC rules and `can-i --list`** | What a binding grants; the question `forbidden`'s help text sends people to answer (`:181-183`). Makes the not-exposed argument sharper, not weaker | 2–3 d |
| **PVs, StorageClasses** | Reclaim policy, `claimRef`, `Released`; provisioner and `volumeBindingMode` (the fixture's Pending PVC is `WaitForFirstConsumer`) | 2–3 d |
| **`rollout history` and `rollout status`** on demand | Plain reads; the preview `rollout undo` would need if item 44 ever reverses the header | 1–2 d |
| **Helm** | A recorded `helm list -o json` fixture — the parse at `:3043-3075` is unproven (`tests/fixtures/k8s/README.md:158-160`); then `history` and `status`. `get values` is a secrets read and must be key-only or refused | 2–3 d |
| **Stale objects** | `jobs` Complete/Failed with age; pods `Evicted`/`Succeeded`/`Failed`; PVCs and configmaps no pod references. Report only; deletion stays refused (`:39-52`) | 1 wk |
| **Add-on verification view** | For a label selector: DaemonSet rollout per node, recent Warning events, one-shot `rollout status`. The half of "upgrade the CNI" that is buildable | 2–3 d |

**Untested and now load-bearing** (`tests/fixtures/k8s/README.md:143-168`): a drain where the
remaining nodes cannot fit the evicted pods, a NotReady node, a StatefulSet with an RWO PV, a real
`helm list`, a cluster with metrics-server. Item 41 makes the first two matter.

### 40. A `pod-crashloop` alert kind

The one alerting gap left, and it is harder than it looks because of where the sampler lives.

**Shape.** A STATE kind like `oom-kill` (`webhook.ts:185-205`): the condition can be observed to
become false. `bad` must be `null` — never `false` — when the read was `forbidden`, `no-cluster`,
`unauthorized`, or when `--all-namespaces` fell back to one namespace (`kubernetes.ts:544`).
That is `postureAlertReadings`' asymmetry, and it is why item 19 deferred OOM and certs until
their probe scope was decided. Scope questions here: which contexts, which namespaces, from
which host.

**Identity.** Alerts key on `serverId:kind` (`store/alerts.ts:68`); a cluster is visible from
every host holding a kubeconfig, so one crashloop would raise once per such host. Either "watch
context X from server S" is a setting, or the key becomes `cluster-context:kind` — the
`StoredDbAlertRow` precedent for a subject that is not a fleet host (`webhook.ts:336-345`).

**The constraint that shapes the code.** `fleetSampler` is inside the agent-reachable closure
(`jobs.ts:326-328`; `tests/jobsNotExposed.test.ts:195-215`). Importing `shared/kubernetes` into
it would fail `NE:939-941`. The probe must be built the way `access.ts` was: its own small shared
module declaring only the summary shape — pod, reason, restarts, read verdict — never importing
`K`. The cached summary carries names and counts and nothing else, because `get_server_metrics`
sees the cache.

**Size.** 1–2 weeks, with a fixture recorded from a real crashlooping pod.

### 41. Cordon → patch → reboot → uncordon as one job

Every primitive exists as a separate click. Chaining them is not "call them in order"; it
is seven things the job engine cannot express, and the audit lists them so the estimate is
honest.

1. **Where kubectl runs.** A step runs on the *target* host (`jobRunner.ts:1331-1339`); a kubelet
   kubeconfig cannot drain its own node. Needs a **control-host** step — "run on C about node
   N" — which `JobSpec` and `JobTargetRef` have no field for.
2. **Per-host step text vs. the record.** `verifyJobApproval` compares literal text
   (`jobs.ts:528-538`); the node name differs per host. Either one job per node (the patch
   planner's existing rule, `patch.ts:877-884`) or a structured step kind whose text is built in
   main and whose structured form is what the approval records. The latter is item 34's shape
   and widens `JOB_KINDS`.
3. **Preflight at run time.** The drain assessment is taken at click and re-taken inside
   `drain()` (`services/kubernetes.ts:362-369`). In a staged job the drain step runs hours
   later; the runner needs a pre-step hook that re-takes it and marks the host `refused`, not
   `failed`. `jobRunner.ts:1308-1360` has no hook.
4. **A node-aware gate.** `evaluateGate` knows `unreachable` and `failedUnits`
   (`patch.ts:962-976`), sourced from the sampler by design (`jobRunner.ts:308-312`). After a
   node reboot it should require `Ready=True`, which needs item 40's probe or a deliberate
   exception.
5. **Conditional uncordon.** Not when `verifyReboot` says `degraded` or `not-rebooted`
   (`patch.ts:401-425`). Steps have no condition today.
6. **Drains are per node, waves are per host.** Two drains in one wave race each other's PDB
   headroom. Force `waveSize=1` for drain steps or serialise them.
7. **A third topology fact.** `topology.ts:11-17` holds exactly two and says nothing should be
   inferred. "This server is node N of cluster X via control host C" is typed by the user.

**Unchanged.** `--force` never (`kubernetes.ts:2127-2131`); no override on drain; a transport
failure is `unknown`, not a failed cordon; the reboot-ordering guard stays in main; nothing in
`shared/kubernetes` enters the bridge closure.

**Size.** 3–5 weeks, and the untested drain-under-pressure path becomes the one that matters.
**Version upgrades themselves** (kubeadm/k3s/rke2) are 4–6 weeks more and argue against the
module's own principles; build the *skew and readiness report* (version per node vs server, API
scan, PDB headroom — 3–4 days) and leave the upgrade to the distribution's tooling, refused in
the header the way apply is.

### 42. Docker and Compose, the last quarter

Everything here is small. Listed in the order the operator meets it.

| | Exists | New | Size |
|---|---|---|---|
| **Compose dialog** (item 35.2) | — | — | ½ d |
| **Per-service pull/up** | Builder accepts `services` and validates each (`compose.ts:1131-1137`); `ComposePanel.tsx:165` never passes them | A service picker | 1 d |
| **Compose `restart` one service** | Neither in `COMPOSE_ACTIONS` nor `COMPOSE_REFUSALS` | Route to the existing container `act` via `joinComposeState` rather than a new job verb; if a job, add the `ELEVATED` rule so it confirms like `docker stop` | 1–2 d |
| **Validation wording and lint** | `compose config` runs on every open; errors outside `BLOCK_FAILURE` become "returned nothing this parser could read" (`:856-860`) | Surface the validator's own line; a `config --quiet` block; lint over the parsed model: `:latest`, no `restart:`, `depends_on` naming an undeclared service, interpolated var no `.env` declares | 1–2 d + 2–3 d |
| **Render what is parsed** | `depends_on`, volumes, networks, `restart:` all parsed (`:658-734`), none rendered | Chips per service; declared-vs-running restart policy via one bounded inspect per container; volume join on `<project>_<volume>` | 1 d + 3–4 d |
| **`docker pull` / `build` as jobs** | Comment-only (`docker.ts:1973, 2119`); `up` deliberately omits `--build` and must keep doing so | `pull <ref>` as a job step; `compose build --pull [svc]` / `build --pull -t <tag> <ctx>` with validated context and tag, no free-text build args; decide whether `build` needs an `ELEVATED` rule since a Dockerfile can `RUN curl \| sh` | 2–3 d / 1–1.5 wk |
| **Networks** | `network rm` builder and parser exist; nothing lists networks, so the preview never emits one | `network ls` read; emit only zero-attached, non-default networks | 2–3 d |
| **Targeted engine/compose upgrade** | Engine *age* only, by design | A per-package `PatchScope` (item 34b) for `docker-ce docker-ce-cli containerd.io docker-compose-plugin`; a repo-configured precheck; a caveat that the engine restart takes every container down without `live-restore` | 1 wk |
| **Health log, unhealthy-first** | `Health.Status` parsed via a separate probe (`:1461-1462`) | A second `\|\| true` probe for the last N `Health.Log` entries (healthcheck output can echo a curl URL — redact); an unhealthy-first sort | 2–3 d |
| **`.env` write via the vault** | Names only, by rule (`:28-67`); `writeImageTag`'s one-line write is the precedent (`index.ts:2144-2148`) | Main-only write of `NAME=<vault value>`, value never crossing IPC, new value registered as a known secret before any `up` | 1–1.5 wk, mostly design |
| **Scanner consumer** | Nothing; the refusal is against *computing* CVEs | Run `docker scout cves` / `trivy` / `grype` if present, counts by severity, "not installed" as its own class, never install one | 1–2 wk |
| **Podman** | Stated proof gap | Recorded fixtures for `rm/rmi/volume rm`, `system df -v`, `podman-compose`; possibly a `runtime` fact to disable reclaim where unproven. Blocked without a host | 2–3 d with one |

### 43. Logs, and getting from an alert to one

**Alert → tail deep-link.** `AlertsPanel.tsx` has no navigation to `LogTailPanel.tsx`, and
`unit-failed` already carries the unit names a tail needs (`webhook.ts:73-77`). Seed
`{kind:'unit', target, priority:'err', since:<raise time>}` and re-validate in main as
`logTail.ts:93-98` already does. 2–3 days, and the most-used thing in this item.

**Search across hosts.** A one-shot query mode — `journalctl -u U -g PATTERN --since … -n N`,
`grep -F -m N`, `docker logs --since … | grep -F` — fanned out with the non-streaming exec the
pickers use (`logTail.ts:392-426`), pattern validated to a fixed-string class and never
interpolated, results capped per host, and a "hosts that could not answer" list. Rotated files
need the picker to stop excluding `.gz` (`logtail.ts:680`). Storage of lines stays refused;
a live grep is not storage. 1–1.5 weeks, +3 days for `zgrep`.

**An error-rate kind.** `journalctl -p err --since -Xmin | wc -l` per unit on the facts cadence,
a `log-errors` STATE kind, a threshold row. The scope decision comes first — which units, which
window — exactly as item 19 said for OOM, and "could not read the journal" is not zero. 1–2
weeks after the decision.

**Host rotation and audit posture.** `journalctl --disk-usage`, `SystemMaxUse`,
`logrotate.timer`, top-N under `/var/log` (3–5 days); `auditd` installed/active/enabled,
`auditctl -s` and rule count, journald persistent vs volatile, rsyslog forwarding, and counts —
never names — of `sudo` and `USER_AUTH` events in 24 h, the same vocabulary as failed logins
(1 week). Both read-only, both `sudo -n`, both on `get_host_facts` only with a new capability
line.

### 44. Change management: windows, rollback, incidents

**Maintenance window.** `MaintenanceWindow {hosts[], from, until, note}` in main. On open,
write a `snoozed` row for every kind on those hosts with an absolute `until` — durable, replayed
at launch (`store/alerts.ts:630-640`) — and optionally disable named rules, whose `armedAt` reset
(`rules.ts:316-327`) means re-enabling replays nothing. **Do not** pause the sampler: a gap in
the store is "could not tell", and the patch gate needs fresh samples. **Do not** suppress in
`webhookNotify`: that is the silent discard `webhookAlerts.ts:246-253` forbids. Patch plans may
refuse to start reboots outside a window. 1–1.5 weeks. A window is a standing authorisation to
be silent, so the revocation argument keeps it human-only.

**Rollback on the approval.** An optional `rollback: JobStep[]` on `JobSpec`, shown in the
dialog, covered by the same `verifyJobApproval` hash, run only by a human pressing "roll back"
under a *second* approval — a second blast radius. The gate-halt path must never auto-run it.
1 week.

**Deployment rollback.** Compose: a revert is an image edit to the previous tag, and the app
does not remember the previous tag — a small per-project "last applied image" record is new.
1 week. Kubernetes: `rollout undo` **contradicts the header** — it rewrites `.spec.template`,
diverges from git, and "leaves the cluster somewhere the user has to remember to undo", which is
the file's own definition of `edit` (`kubernetes.ts:52-58`, `:1167-1172`). If wanted it is a
recorded reversal in the header, graded like drain, with a caveat that live now differs from
source; `rollout history` as a read is safe now (item 39). Package downgrade should be refused
in-file for the reason `dist-upgrade` is.

**Incident record.** A named span — start at raise, end at resolve — with a note and the alert
rows and jobs inside it, joined by `runbookJobWindow` (`runbooks.ts:333-340`); its own JSON file
for the reason runbooks are not in the history store. Ticketing stays webhook-out; an internal
span that posts the fixed payload shape stays inside that line. 1–2 weeks.

### 45. Housekeeping as a read, then delete-by-id

The Docker reclaim shape — preview a literal list, re-preview on confirm, refuse `prune` — is
the only housekeeping the app does, and it is the right shape for the rest.

**The read** (1–2 weeks): a `housekeeping` posture-like source per host — journald disk usage,
`/var/log` top-N, `/tmp` size and oldest file, `apt-get autoremove --dry-run` / `dnf autoremove
--assumeno` candidate counts, `lvs -o lv_name,origin,snap_percent` for snapshots. Single-line,
capped, no mutation, "could not read `/tmp`" is not empty. **Delete-by-id** (+1 week): a list of
paths or packages, typed confirm, never a blanket verb. Cloud snapshots are a provider-API
product and refused by the DNS/TLS precedent.

**Dead users and keys** (3–5 days): a pure verdict `staleAccounts(hosts, days)` — live key, not
expired, no login in N days — with "last-login source partial" surfaced so a host without
`lastlog` is `unknown`, not stale. Revoke stays behind item 36. **Stale Kubernetes objects**:
item 39's last row.

### 46. Facts the fleet is still missing

Read-only additions to `hostFacts`, each a new `FACT_SOURCE_IDS` entry, each updating the
`hostFacts` capability grid text because packages-and-versions is attacker-useful in the same way
security counts are.

| Fact | Why | Size |
|---|---|---|
| **Installed packages and versions** | "Which boxes still have the old openssl" (item C's motivating question). Thousands of rows per host: a `pkg:` prefix with `retireFacts`, a cap or its own table, searchable in fleet search | 1–1.5 wk |
| **Per-package security list** | The count exists; the *list* from `apt list --upgradable` filtered by `-security`, `dnf updateinfo list security`, `zypper list-patches --category security` is still consuming the distro's answer, not computing one. CVE ids appear in dnf/zypper output natively. Feeds a "these packages" patch selector | 1 wk |
| **Kernel installed vs running** | Newest of `/boot/vmlinuz-*` / `rpm -q kernel` / `dpkg -l linux-image-*` against `uname -r`; a column and a filter on the patch table. A kernel-only *install* scope sits uneasily with `patch.ts:147-160` and needs its own argument | 3–5 d |
| **Storage layout** | `lsblk -J`, `findmnt -J`, `vgs`/`lvs --reportformat json`, `df --output` — the read half of disk maintenance; the write half (`lvextend -r`, `resize2fs`, `xfs_growfs`, `fsck` at boot as a reboot step) is a new OFF module and needs real hosts across the LVM/ext4/xfs matrix | 1 wk + 1.5–2 wk |
| **Service-account classification** | uid < 1000 / nologin / no password, as a panel filter; "service account with a live key" as a finding; owner/purpose tags stored locally | days |
| **Access-review export** | CSV/JSON of keys, accounts, groups, last login, with the per-host coverage line so a denied host is in the export as denied; never key blobs; a "since <date>" view over the facts already stored | 2–4 d |
| **Bastion as an access object** | "Hosts reachable only through B"; a key on the bastion highlighted as a key to everything behind it; patch's do-not-reboot check reused for do-not-revoke-without-confirming-downstream | days |
| **Certbot timer read** | `systemctl list-timers certbot*`, `/var/log/letsencrypt` last success — the *why* behind a cert inside 30 days, in the spirit of the DNS/TLS cut | days |
| **Drift, operator-chosen watches** | A stored watch (path under `/etc`, regular file, deny-list of credential stores, comment char, rule set) with a one-time typed approval; the `redact → hash → normalise → preview` order kept | 1–2 wk |

### 47. Storage beyond `/`, and capacity beyond three percentages

**The finding.** `metrics.ts:52` runs `df -kP /` and `df -iP /`. That was brevity, not policy —
and it means a full `/var` or `/data` never reaches the disk alert, the forecast or the agent.
Inode is measured every sweep and is not in `METRICS` (`history.ts:76-85`), so it is never stored
and never forecast. Nothing in `src/` reads `lvs`, `vgs`, `mdstat`, `smartctl`, `zpool` (except
as a destroy-guard) or `findmnt`.

**Storage, in order.**

1. **Inode series.** Append `inodePct` to `METRICS` — append-only, never reorder — and to
   `metricsToSamples` with the same null guard as `cpu`; add to `CAPACITY_METRICS` at 90.
   **1 day.**
2. **Per-mount disk and inode.** `df -kP -l` excluding `tmpfs|devtmpfs|overlay` into
   `mounts: DiskMount[] | null`. The decision is fact or series: forty mounts as samples is the
   "5× budget" trap item A warned about, so store mounts as facts and only the *worst* as a
   series, or accept a `(metric, label)` schema change. `disk` is one number per host today
   (`webhook.ts:173`); scoping the kind is the second half. `get_server_metrics` prints the
   extra mounts for free once they are in `HostMetrics`. **1 week, +1 for per-mount series.**
3. **LVM, mdraid, zfs, SMART as facts and state alerts.** `lvs`/`vgs` for `vg-free`,
   `/proc/mdstat` for `[U_]`, `zpool status -x`, `smartctl -H -j` (root and a package —
   `absent` vs `cannot` is what the facts framework already models). Kinds `raid-degraded`,
   `smart-failing`, `zpool-degraded`. Inside the 45-second probe budget. **1.5–2.5 weeks.**
4. **Remote mounts.** `findmnt -t nfs,nfs4,cifs,fuse.sshfs -J` as a fact source — time-boxed,
   because a hung NFS mount blocks `df` and parks the sweep. **2–3 days.**
5. **PVC state alert** would need the Kubernetes read on a cadence, which is item 40's
   sampler question again. Not before 40.

**Capacity.**

| | New | Size |
|---|---|---|
| **DB growth series** | Intern `db:<connectionId>` as a subject (host_key is plain TEXT, `history.ts:650-653`); append `dbBytes` to `METRICS`; record on every `db:ops` read first (gappy, and the forecast's `gap`/`stale` refusals handle gaps honestly), a `dbSampler` later; a *bytes* forecast rule, since `capacity.ts:32-38` accepts percentages only and "flat rise 0.5 %" means nothing in bytes | 1 wk, +3–5 d sampler |
| **K8s allocatable vs requested** | Item 39's requests/limits read summed per node against `.status.allocatable`; pods without requests are the "unbounded" bucket, reported as such and never as zero | 1 wk |
| **Fleet expansion forecast** | One IPC over the sampler's target list returning `{host, metric, crossesAt \| refusal}` soonest first; a status-bar line like `diskLine`. Refusal-first is the feature | 3–5 d |
| **`get_capacity_trends` over MCP** | `CapacityReport` is already wire-shaped (`index.ts:2640-2645`) and carries no free text but host names, already redacted. The first defensible agent-reachable capacity surface | 1–2 d |

**Backup, the parts that are not databases.** The bundle is the app's own store and nothing
streams (`backupTargets.ts:22-26`, "kilobytes"). A **remote file backup** — `tar -C / -czf -
<paths>` over an exec channel on the *same* pooled connection `openSftpIo` acquires — needs a
streaming `put`/`get`, a name that is not `.spbackup` so `planRetention` never counts it as a
generation, its own retention, a path allow-list, a sudo decision for `/etc/shadow`, and an
exposure text like `BACKUP_DESTINATION_EXPOSURE` because host files hold secrets too. Built as a
job kind, not a second scheduler, which is item 5's own instruction. **2–3 weeks.** A **Docker
volume backup** is the same source through `docker run --rm -v <vol>:/v … tar`, with quiescing
graded like any container action. **+1–2 weeks.** A **restore drill** of the oldest kept
generation is 2–4 days; a true scratch import 1–2 weeks. None of it is refused; none of it is
agent-reachable, and the vault inside the bundle is why.

### 48. VPN: the alert, the certificate date, and the server nobody manages

**One correction to the README first.** WireGuard is not userspace-only. `VpnMode` is
`'userspace' | 'system'` (`vpn.ts:16`); system mode creates a real TUN and applies routes and
DNS behind a per-launch elevation, refused on macOS and for full-tunnel profiles. "Your routing
table is never touched" is true of the default mode, and the README row should say so.

**Cheap and missing.**

| | Exists | New | Size |
|---|---|---|---|
| **`vpn-down` alert kind** | `tunnel-down` is renderer-polled over `tunnel.list()` every 10 s (`FleetWatcher.tsx:264-288`) and never looks at VPNs; item 19 wanted "tunnel or VPN down" | Add the kind; a second poll over `vpn:list`; `error` → bad, `connected` → good, `starting/reconnecting` → null, **`stopped` → null** (a person pressing Stop is not an outage); `degraded` as its own kind or `detail`, because up-but-silent and down "call for different reactions" (`VpnStatusCard.tsx:77-79`); never an endpoint in the payload | ½–1 d |
| **OpenVPN client cert expiry** | `<cert>` is captured opaquely (`ovpn.ts:808-830`); the only signal is openvpn's own "certificate has expired" log line, after the connect has already failed. Plan E31 promised the date and it was never built. `certificateNotAfter(der)` — the pure-TS DER walker in `posture.ts:2144` — is in `shared/` and main can import it | PEM→DER at commit in main, a `clientCertNotAfter?: number` on `OpenVpnSpec` beside `remotes` (the non-secret-summary precedent, `vpn.ts:96-98`), never re-reading the vault; feed `checkCertificateAlert` keyed by profile or a sibling kind, since `cert-expiry` is filed under posture coverage and a profile has no posture; refuse to date `pkcs12` | 1–2 d |
| **`crl-verify` carry-over** | Dropped by the parser's default branch (`ovpn.ts:834`) | Carry it as inline-capable material like `ca` | ½ d |
| **WireGuard per-peer stats, latency** | `VpnStats` has rx/tx, handshake age against a pinned clock, endpoint (`vpn.ts:256-268`); the sidecar returns one handshake and `peers: number` (`wireguard.ts:203`); `latencyMs` is never populated; nothing outside the renderer consumes `degraded` | Per-peer rows from `sidecar/netd`; a probe *inside the netstack* for userspace, never a host `ping`; keys stay out of `list_vpns`, which promises they are never included | 3–5 d |
| **Diagnose** | Error vocabulary with fix text; E27 names the public key; no active probe | DNS resolve, UDP/TCP reach, MTU via the netstack, IPv6 leak (already a `RouteConflict` kind), TLS reach for OpenVPN — in-process, unelevated, as a checklist on the card | 3–4 d |
| **OpenVPN edit without re-import; DNS verification** | Body is a vault secret with no editor; `DnsManager.verify()` is WireGuard-system-only | Edit-as-text → re-run the sanitiser → re-commit (cheapest); wire the OpenVPN driver to `verificationFor` after CONNECTED | 1–4 d; 2–3 d |

**The server side, which is a subsystem and not a feature.** Nothing in `src/` runs `wg set`,
`wg show`, `wg syncconf`, `wg-quick`, easy-rsa or `gen-crl`; `/etc/wireguard` and `/etc/openvpn`
are in no search root. A `wgServer` module over SSH would reuse three things: the posture
bounded-multi-line read path for `wg show <if> dump` (one row per peer, host-written, capped,
scrubbed — the *scalar* path is for "a tool name, an on/off, a count", `posture.ts:326-330`);
the cron write discipline for `/etc/wireguard/wg0.conf` — read, byte-compare, timestamped
backup, install, read back, roll back, one status line after a marker (`cron.ts:1500-1532`);
and the broadcast risk table, **which has no row for `wg`** (`broadcast.ts:184-215`), so
`wg set … peer … remove` is `ordinary` today and must not be exposed until it is not. A PSK
goes over stdin of the SSH exec, never argv (`wireguard.ts:57-61`). Then rotate is one action:
mint → add new peer → verify a fresh handshake → remove old. **2–3 weeks.** OpenVPN's server
half (server.conf, easy-rsa, CRL) is the same shape and larger; the whole subsystem is
documented as clients (`docs/VPN.md`, `docs/plans/vpn-tunnel-clients.md`) and that is a scope
statement, not a refusal.

**Over the bridge.** `list_vpns` could carry handshake age, byte totals and "client certificate
expires in N days" without breaking its promise. Import, edit, keygen, peer writes and anything
server-side stay off it; `set_vpn` is start/stop by contract (`managerApi.ts:34-38`).

---

### The order this suggests

Same rule as the plan above: one focused person, sequential, each block naming what a user can
see. The audit changes the ordering in one way that matters — **the composer goes before every
write**, because every write is a step in it, and the two lab-host items are scheduled around
when a host exists rather than when the code is ready.

**Weeks 1–2 · Defects and one-day wins.** Item 35 in full (the classifier, the compose dialog,
the `execute_command` docker rule, the approval surfaces). Then the five things under a day
each that close a hole in something already shipped: inode series (47.1), `vpn-down` (48),
`backup-failed` (38), Kubernetes PKI roots into the cert inventory (39), the OpenVPN cert date
(48). At the end of week two, nothing an agent can do by accident is ungated, and four alert
kinds this document promised exist.

**Weeks 3–5 · The composer and the first step kind.** Item 33, then 34a service. The user sees
a job list for the first time, "restart this failed unit" on the inbox row, and "run this
across twelve hosts in waves" without it being a patch.

**Weeks 6–8 · The database statement job.** Item 37's surface, then terminate, `KILL`, purge
binlogs, `VACUUM`/`ANALYZE`. The ops panel's refusals finally point at a button that exists.

**Weeks 9–11 · Backups, the second half.** Item 38 steps 1–3: scheduled, streamed, encrypted,
retained dumps; dump on the remote host; `mongodump`. The README row about backups becomes
true for four engines.

**Weeks 12–14 · Package, file push, and the facts they need.** 34b and 34c, with 46's
installed-package facts so "which hosts have X" is answerable before "install X everywhere" is
offered.

**Weeks 15–17 · Storage beyond `/`, and windows.** 47.2–47.3 (per-mount, LVM/mdstat/zpool
facts and state alerts), then item 44's maintenance window and rollback-on-approval. The
operator can silence a host for a window and see a full `/data` for the first time.

**Weeks 18–20 · Logs, from the alert.** Item 43: the deep-link, then search across hosts, then
the error-rate kind after its scope decision.

**Weeks 21–24 · Kubernetes reads and the crashloop kind.** Item 39's table in its stated
order, then item 40. Item 41 — the chained node job — waits until a real multi-node cluster
under load exists to record fixtures from; it is the Kubernetes analogue of the RHEL 9 host.

**Whenever the host exists.** Item 36a the day a RHEL 9 lab host is available, then 36c–36e in
order. Item 41 the day a multi-node cluster is. Neither is on the calendar because neither is
blocked on code.

**After week 24, in rough order and not scheduled:** 42 (Docker and Compose, the last
quarter), 45 (housekeeping read then delete-by-id), 47's DB growth series and fleet forecast,
48's server-side WireGuard, the remainder of 46, 44's incident record, 34d users.

**What that adds up to.** At week 24 the operator composes and stages any command as a job,
restarts a unit from the alert that reported it, terminates a session or purges a log from a
button that records who pressed it, has four engines backed up on a schedule and proven by a
restore, sees every mount and every array, silences a window deliberately, reads a log from
the alert it came from, and is told when a pod is crashlooping. Every one of those is a task
the ten-to-fifty-host operator does today by hand, in tabs.

---

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

**21b — reclaim by id. Shipped.** Not `prune`: `docker rm`/`rmi`/`volume rm`/`network rm`
against exactly the ids the preview displayed, so anything that became eligible afterwards
is untouched and the crashed container you were about to debug survives, while anything
that stopped being eligible fails on its own terms in docker's own words, per item.

The re-preview is on the CONFIRM, not on the button that opens the dialog: the window that
matters is the one the operator spends reading the caveats. A re-read that *fails* is a
refusal too. Nothing is pre-selected and there is no select-all, because a select-all is
`prune` reached by a click instead of a flag. Risk is `planK8sRollout`'s shape rather than
`planDockerAction`'s — count is the wrong axis when fifty dangling images are a pull away
and one volume is not — so a volume is destructive and typed-confirm on its own, and
`caveats` rides separately from `reasons`.

Three things are still refused, and each is refused rather than deferred. **`-a`**, for the
structural reason above. **`--force`**, because the checks it overrules are exactly the facts
a preview cannot vouch for. **Build cache**, because a single entry comes out only through
`builder prune --filter`, which is a prune.

**The podman gap remains, and is now stated in the fixtures rather than implied.** Podman's
`rm`/`rmi`/`volume rm` print different success lines and different refusal wording, and no
podman host was available to record on. Nothing was invented to fill it in: an invented
refusal string would read as evidence that podman works. The parser attributes by looking
for the reference inside the line, which is the most runtime-agnostic rule available, and on
podman would most likely report every object as "docker did not say what happened" — the
honest failure rather than a wrong success.

**Engine age, without phoning home.** `{{.Server.BuildTime}}` gives an absolute age that
cannot go stale and cannot be wrong. A baked table of release versions was considered and
rejected: it needs an owner and a refresh cadence, and a table that rots states something
false. Age alone is honest and free.

**Size.** 21a: 3–5 days. 21b: 1.5–2 weeks, spent.

---

### 22. Kubernetes lifecycle — SHIPPED

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

**What shipped, and how the drain decides.** Cordon and uncordon are a plain confirm in both
directions and the plan says out loud, with the pod count, that a cordon evicts nothing — the one
thing everybody misreads about that button. Drain is offered only after a preflight round trip that
reads the node, the pods on it, every PodDisruptionBudget and every EndpointSlice, and it is refused
outright on any of seven things: a pod nothing owns, a budget with `disruptionsAllowed` at zero, a
pod covered by MORE THAN ONE budget, a budget selector using `matchExpressions` that a list read
cannot evaluate, the only Ready endpoint behind a Service, an `emptyDir` volume, and **any read that
did not answer**. That last one is why `safe` is not "no blockers": a Forbidden budget list produces
no blockers because it produces nothing. `--force` and `--delete-emptydir-data` are written
explicitly as false; both turn a blocked drain into a successful one by destroying what blocked it.

The overlapping-budget rule was found by running a drain against a real three-node cluster rather
than reasoning about it: the eviction subresource answers `This pod has more than one
PodDisruptionBudget, which the eviction subresource does not support.` regardless of what either
budget allows, so a check that only read `disruptionsAllowed` would have cleared a drain that cannot
make progress at all. The same recording showed a drain is **not atomic** — it evicted three pods,
stalled on two, and gave up at the timeout with the node cordoned and half empty — which is why the
result carries `partial` and why the check happens before the command is built.

Exec ships behind `approvalFor`/`verifyApproval` from `shared/broadcast.ts`, reused unmodified: the
record carries the command text, so an exec approved as `id` and sent as something else is a
comparison rather than an act of faith. Always type-to-confirm, with no cheap case — `ls` and
`rm -rf /` are the same request from here.

The cheap reads all shipped. Secrets list names and key names and never a value, and that is a
property of the query rather than a rule applied afterwards: a go-template ranging over `$k, $v` and
emitting only `$k` is the only kubectl output form where the value is structurally unreachable.

**Still refused, and unchanged.** Applying manifests, for the reason above. Context switching, which
rewrites the user's kubeconfig for every process on the host. Single-pod deletion — a drain answers
"can this node lose everything on it", which is a question about a node; "can this workload lose
this one pod" is a question about a workload, and `rollout restart` already reaches that remediation
through the controller. And the MCP bridge: none of this is agent-reachable, and
`tests/jobsNotExposed.test.ts` holds the symbols.

**What is untested.** A drain where the remaining nodes cannot fit the evicted pods. Every fixture
came from a `kind` cluster whose nodes are containers on one host and which was never under real
resource pressure; the replacements go Pending, the eviction still succeeds, and `kubectl drain`
still reports the node drained. That path needs a real multi-node cluster with real requests and
limits. See `tests/fixtures/k8s/README.md`.

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
| 21b | ~~**Docker reclaim by id**~~ | 60% | monthly | 3 | some | **5** | **SHIPPED** | podman tested, ports unverified | Done |
| C | ~~**Host facts**~~ | 100% | continuous | 4 | strong | **3 / 21** | **SHIPPED** | — | Done |
| A | ~~**Durable store**~~ | — | — | — | — | **0 / 30** | **SHIPPED** | — | Done |
| B | ~~**Job engine B1–B4**~~ | — | — | — | — | **0 / 38** | **SHIPPED** | — | Done |
| 18 | ~~**Database operations**~~ | 70% | weekly | 4 | strong | **8** | **SHIPPED** | all five engines | Done |
| 17 | ~~**Patch management**~~ | 100% | weekly | 5 | strong | **10** | **SHIPPED** | — | Done |
| 5 | ~~**Backups to real targets**~~ | 90% | weekly | 5 | strong | **8** | **SHIPPED** | — | Done |
| 19b | ~~**Alerting, the rest**~~ | 100% | continuous | 4 | none | **8** | **SHIPPED** | — | Done |
| 23 | ~~**Fleet key management**~~ | 100% | quarterly | 5 | very strong | **7** | **SHIPPED** | write is opt-in, unobserved on RHEL 9 | Done |
| 20 | ~~**Compose**~~ | 60% | daily | 3 | some | **6** | **SHIPPED** | — | Done |
| 6e | ~~**Cron editing**~~ | 80% | monthly | 3 | some | **5** | **SHIPPED** | — | Done |
| 24 | ~~**Security posture**~~ | 60% | monthly | 3 | some | **5** | **SHIPPED** | — | Done |
| 26 | ~~**Capacity trends**~~ | 70% | monthly | 3 | some | **5** | **SHIPPED** | — | Done |
| 27 | ~~**Rule engine**~~ | 40% | continuous | 3 | some | **5** | **SHIPPED** | — | Done |
| 22 | ~~**Kubernetes lifecycle**~~ | 25% | weekly | 4 | weak | **5** | **SHIPPED** | — | Done |
| 7 | ~~**Credential proxy**~~ | 30% | daily | 3 | very strong | **5** | **SHIPPED** | — | Done |
| 25 | ~~**Configuration drift**~~ | 50% | rare | 4 | strong | **4** | **SHIPPED** | — | Done |
| 28 | ~~**Runbooks on alerts**~~ | 40% | per-incident | 3 | some | **4** | **SHIPPED** | — | Done |
| 14 | ~~**Change log**~~ | 30% solo | per-incident | 3 | strong | **4** / **8** team | **SHIPPED** | — | Done |
| 1 | ~~**pm2 supervision**~~ | 25% | daily | 3 | some | **4** | **SHIPPED** (local) | remote refused, successor named | Done |
| 2 | ~~**frp ngrok UX**~~ | 20% | rare | 2 | some | **3** | **SHIPPED** | — | Done |
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

### 32. A retention horizon per event kind — SHIPPED

**Shipped since this was written:** `EVENT_RETENTION_TIERS` in `history.ts` keeps the `alert` kind
400 days and `job-` events 365, with 90 as the default, and `RUNBOOK_LOOKBACK_DAYS` mirrors the
alert tier so the runbook join is no longer bounded by the shorter number. The write-up below is
kept as the reasoning.

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
