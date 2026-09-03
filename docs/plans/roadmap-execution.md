# Roadmap execution — wave log

Working log for implementing `docs/ROADMAP.md` in the priority order that document
establishes. One section per wave. Written as it happens, including what was wrong,
because the corrections are the part worth keeping.

**Branch:** `claude/sysadmin-task-roadmap-20e621`, merged with `main` at 0.9.7.

**Baseline at wave 1 start:** typecheck clean, eslint clean, 2215 tests passing,
1 skipped file.

**The standing rules for every wave.**

1. Research before code. A research pass reads the real code and produces a plan with
   file:line citations. No implementation agent starts from a guess.
2. An adversarial pass reviews the *plan* before anything is written, because a wrong
   plan caught at this stage costs an hour and caught later costs a week.
3. Implementation follows the plan, matching the surrounding code's idiom.
4. An adversarial pass reviews the *diff* — hunting for the failure modes this repo has
   already been bitten by: tests that assert literals rather than behaviour, main-process
   work the renderer never calls, and `null` collapsed into empty.
5. Nothing is done until `npm run typecheck`, `npm run lint` and `npm test` are all green,
   and every new test has been shown to fail against the bug it was written to catch.

**Product constraints, from the owner, applied to every decision.**

- One tool. No external services, no phone-home, no account.
- Stable enough to daily-drive. A crash or a corrupt store is worse than a missing feature.
- Good UI/UX. A feature the operator cannot find has not shipped.
- Native dependencies are a cost to be justified, not a default — see the `@lydell/node-pty`
  history and roadmap item 10.

---

## Wave 1 — the cheap wins (roadmap 19a, 21)

Chosen first because both finish something already ~90% built, both depend on nothing,
and together they cost less than the plumbing that follows. Shipping them buys a release
and real feedback before six weeks of work that shows a user nothing.

| Item | Leverage | Direct cost | Status |
|---|---|---|---|
| **19a. Disk alert** | 8 | 0.5 day | research |
| **21. Docker housekeeping** | 5 | 1 week | research |

### Status

- [x] Merge `main` (0.9.4–0.9.7, all stability fixes; no roadmap item moved)
- [x] Roadmap synced to 0.9.7
- [x] Baseline verified green
- [x] Research: disk alert path
- [ ] Research: docker housekeeping
- [ ] Adversarial review of both plans
- [ ] Implementation
- [ ] Adversarial review of the diff
- [ ] Green gate

### What the disk-alert research found, and why the estimate was wrong

The roadmap called this "half a day of wiring an existing signal into an existing bus".
That is accurate about the wiring and wrong about the feature, for a reason worth keeping:

**Disk is the first alert kind whose condition does not fix itself.** CPU and memory
recover on their own, so a 60-second repeat window (`REPEAT_MS`, `store/alerts.ts:51`)
is a reasonable cadence for them. A disk sitting at 86% recovers never, so the same
window produces a desktop notification and a webhook every minute, forever — about
10,080 of each per week. The existing dedupe was designed for transient conditions and
nothing about it is wrong; disk is simply the first kind it was not designed for.

That is the actual work in 19a. Three latent defects were found alongside it:

1. **A silent webhook drop.** `webhookAlerts.ts:104` whitelists alert kinds with a
   hand-written literal that is not derived from the shared type. Adding `'disk'` to
   `shared/webhook.ts` without touching that line drops every disk webhook inside main,
   with both sides typechecking clean and the drop counter not even incrementing.
2. **A false all-clear.** `metrics.ts:294` yields `diskPct: 0` when the `df` probe
   fails, not `null`. Passing that into `evaluate` makes a host that was alerting at 91%
   post a `resolved` webhook — an all-clear manufactured out of a measurement failure.
   This is the exact `null`-is-not-zero rule the rest of the codebase already enforces.
3. **`store/alerts.ts` has no tests at all**, and cannot be imported under vitest's node
   environment because it touches `window` at module top level. The harness has to be
   built before the first assertion.

Honest estimate: 1.5–2 days, not half a day.

### Decisions taken on the open questions

| # | Question | Decision |
|---|---|---|
| D1 | Repeat cadence for a condition that never clears | Per-kind repeat map. CPU and memory stay at 60s. **Disk repeats at 6 hours.** Transition-only was rejected: miss the one notification and you never hear again about something getting worse. |
| D2 | Should a worsening disk wait for the window | **No — escalate.** Re-notify immediately if the value has risen 5 or more points since the last notification. 86% → 94% should not sit silent for six hours. *Flagged to the adversarial pass as the decision most likely to be wrong, because the repeat window is deliberately not cleared on recovery.* |
| D3 | Chip or silence | **Chip.** A disk alert is a real `ActiveAlert` with a value and belongs in the status bar, unlike `unit-failed` which is transition-only. |
| D4 | Threshold | **Reuse `DISK_DANGER = 85`. No new setting.** Wiring it to `resourceAlertThreshold` would mean a user raising the threshold to 95 for a noisy CPU silently moves their disk alarm to 95%, and a disk alerting at 80 would contradict the Fleet Monitor's own attention list. Per-kind thresholds are 19b. |
| D5 | Wording | Say **"root filesystem"**. `metrics.ts:52` probes `df -kP /` only, so a full `/var` on its own device raises nothing. Do not imply coverage that does not exist. |
| D6 | Re-announcing on every app launch | **Accepted and documented, not fixed.** Alert state is in-memory by design; durable suppression needs enabler A. |

---

## Wave 2 — the plumbing (roadmap A, C, B)

Research started early and deliberately, because item A carries an architectural decision
that the owner's "no external dependencies" constraint puts in direct tension with the
obvious answer (`better-sqlite3` is a native module, and this repo has already paid for
one of those). The honest possible outcomes include "no database at all — extend the
append-only JSONL pattern that already works", and that is worth knowing before, not
after.

- [x] Research: durable store — `node:sqlite`, zero dependencies, verified by running it
- [x] Research: host facts
- [x] Research: job engine — the finding reframed both it and item 17
- [x] **A. Durable store** — shipped `a628ac4`, hardened `6021fd8`
- [ ] **29. Renderer test harness** — in progress, sequenced before C's table
- [ ] **C. Host facts** — main-process half in progress; UI waits on 29
- [ ] B1–B4. Job engine

### What the adversarial pass caught, before any code was written

Four blockers. Three were in decisions taken above, which is the point of running the
pass at all — each would have shipped, and two of them would have shipped silently.

**1. A six-hour silence on a genuinely new disk-full event.** `evaluate` deliberately does
not clear the repeat window on recovery, and the comment explaining why is sound: at a
60-second window the residual suppression is 60 seconds. At six hours it is six hours. A
disk that hits 96%, gets cleared to 40%, and refills to 92% two hours later raises the
status-bar chip and notifies **nobody**. Decision D1 changed one constant and not the rule
that depended on it.

**2. The escalation rule was inert in exactly that case.** D2 was flagged as the decision
most likely to be wrong, and it was, for a reason that was not obvious: "risen five points
since the last notification" needs a baseline map, and that map inherits the
never-cleared-on-recovery semantics. In the trace above the baseline is still 96 from the
first alert, the disk is at 92, and 92 is four points *below* the baseline — so escalation
does not fire either. Both halves of the design failed on the same case.

The fix is to clear the baseline inside the resolve *transition* — not on every
below-threshold sample — and to treat an absent baseline as "notify now". The flap this
appears to reinvite is already prevented by `clearAt`: a resolve only registers five points
below the line, so a re-raise above it is a real event rather than an oscillation. That
argument is now a test rather than a paragraph.

**3. The two screens disagreed at exactly 85.000%.** `hostHealth` is strictly greater,
`evaluate` is greater-or-equal. Feeding the constant straight in would fire an alert for a
host the Fleet Monitor's own attention list does not show and whose disk bar is not red —
breaking the invariant that constant's docstring exists to assert. Worse, the planned
`isDiskCritical` extraction would have been **dead code**: called from the row builder and
never from the alert path, which is the first failure pattern the pre-release review named.
Both paths now go through the one predicate.

**4. The drift test could not fail.** Deriving both sides of an assertion from
`ALERT_KINDS` produces a test that passes for any future kind, including one that is never
plumbed through the renderer — the second pattern that review named, reproduced exactly.
Tests now assert literal strings and payload contents, and each must be shown to fail
against the bug it catches before it counts.

Smaller findings folded in: the webhook sanitiser rejects an unknown kind and writes no
`lastError`, so the Settings pane reports a healthy webhook while dropping every message;
`resolved` is ungated while `raised` is throttled, so an oscillating host would send
resolutions for alerts the endpoint never received; switching alerts off never clears an
active chip, which for a chronic disk means one that survives until restart; and the new
baseline map needs purging in `onServerForgotten` beside the existing one, or a re-added
server inherits a suppression it never earned.

Two honest limits, documented rather than fixed: alert state is in-memory, so a chronically
full disk re-announces once per app launch; and `fleetSamplingEnabled` defaults to off, so
without background checking these alerts still only fire while someone is looking at that
server. The copy reuses `alertCoverage`'s existing language rather than claiming otherwise.

Revised estimate: 2–3 days.

### Wave 1 outcome — both items shipped

| Item | Commit | Estimate | Actual |
|---|---|---|---|
| 19a disk alert | `7f4e1e2` | "half a day" | ~2 days |
| 21a itemised disk view | `425e031` | 3–5 days | ~1 day |

Suite went 2215 → 2235 passing, 51 tests added, typecheck and lint clean, verified
independently of the agents that wrote them.

**Three defects fixed that had nothing to do with disk.** The webhook sanitiser was
discarding unknown alert kinds and writing no error, so the Settings pane reported a
healthy webhook while dropping every message. Two ternaries mapped store kinds onto webhook
kinds by asking whether the kind was `cpu` and calling everything else `memory`, so a disk
alert would have arrived labelled memory. And `resolved` fired on every transition while
`raised` was throttled, so an oscillating host sent all-clears for alarms the endpoint
never received. None were visible from the disk feature; all three were on the path it
happened to walk.

**The estimate that was wrong in the other direction.** 21a came in under its 3–5 days,
because the research pass established that the compose-label grouping and `system df`
parsing already existed. The roadmap's own leverage table had it right and the wave log's
first draft did not.

**Where a brief was wrong and the implementer said so.** The 21a brief asserted that the
recorded fixture proved a two-or-more-spaces split could not parse `docker system df -v`.
It did not — every in-cell space in the recording happens to be single, and mutating the
parser to the naive split passed all 113 tests. Rather than accept the claim, the
implementer constructed the row that does prove it and labelled in the test comment which
parts were recorded and which were written to make the point. An instruction that sounds
authoritative is still a claim, and this one was false.

**Two honest reports worth keeping.** One agent shipped a guard it had determined was
unreachable-false, and said so rather than presenting it as working. Another dropped a test
it had written because the test passed with or without the fix. Both are the right
instinct; both went to the adversarial pass rather than being quietly resolved.

### The CI bump, verified rather than assumed

Moving the workflows from Node 20 to 24 was a prerequisite for the store — `node:sqlite`
does not exist before 22.5 — but it was a config change made blind, since this machine
runs 22.23.1 and nothing in the repository exercises a Node 24 toolchain.

Checked properly against Node 26.7.0, which is a stronger test than 24 and was already on
the machine: `node:sqlite` exports the same surface, the full suite passes (2235 passed,
31 skipped), and `npm run build` completes clean through electron-vite and the esbuild CLI
bundle. The only output is the pre-existing set of dynamic-versus-static import warnings,
which are unchanged from Node 22.

That closes the risk. A version bump in a workflow file is invisible until a release fails,
and this one gated the whole of wave 2.

### The gap neither wave was looking for: the renderer cannot be tested

Two of the eight fixes in the itemised-disk review shipped without an automated test, and
not because anyone chose to skip them. `vitest.config.ts` runs `environment: 'node'` and
there is no jsdom, no happy-dom and no testing-library anywhere in the dependency tree. **No
React component in this application can be rendered in a test.**

That is why the cross-server leak — a read left in flight when the operator changes server,
rendering one host's image and container names under another host's name — is covered only
by having been read carefully. Same for the dead-end error state. Both are real defects that
were found by a human-style review of the code and fixed on the same basis.

It also explains a pattern visible across both waves. Every renderer defect found so far was
found by reading: the alert chip stranded above the attention list, the status bar rendering
a disk alert as "Memory", the itemise button hidden precisely when it was needed. The main
process has 2280 tests. The renderer has assertions about renderer *source text* — the panel
suites read `.tsx` files with `readFileSync` and match regexes against them, which is an
honest workaround and is not the same thing.

The two failure patterns this repository already names are "main-process work the renderer
never calls" and "tests that assert literals and pass against the bug they were written to
catch". Source-text assertions are the second pattern with better manners: they are literal
by construction, and they cannot fail for a component that renders the wrong thing.

**This belongs on the roadmap.** The stated goal is a tool stable enough to daily-drive with
good UI, and the half of the codebase the operator actually touches has no behavioural test
coverage at all. Adding jsdom plus testing-library is a day; the value is that every
subsequent UI defect becomes catchable rather than reviewable. It should land before the job
engine's job list and item C's inventory table, which are the two largest new surfaces on the
plan — writing them first and retrofitting tests afterwards is how the gap gets permanent.

## Wave 2 — the plumbing

### Item A shipped, and what the review found

`a628ac4` built it; `6021fd8` fixed what adversarial review found. Suite 2235 → 2319.

The store itself survived attack. The schema, the retention arithmetic, the two-tier stitch
between full-resolution and hourly rows, the distinction between "no units" and "cannot see
units", and the checkpoint fix were all confirmed correct — several of them better than the
commit message claimed.

**Both serious defects were outside the file.** That is the pattern worth carrying into the
next wave: a new subsystem is reviewed carefully and its seams are not.

*"Delete all data" did not delete it.* The list of files that command clears describes itself
as deliberately exhaustive and was written before this database existed. A user who typed
DELETE and read "All data deleted" kept every hostname, kernel, systemd unit and listening
port in the estate, and the app resumed appending to it. The file is chmod 0600 a few hundred
lines away, so its sensitivity was already established by the same diff.

*A wrong clock erased it.* Retention took its cutoffs from the wall clock alone and ran
seconds after launch, before NTP could correct anything. A VM restored from a snapshot, or a
machine with a dead CMOS battery, rolled everything into hourly buckets and dropped the lot in
one committed transaction — no error, no log, nothing on the next launch to say so. Two
guards now, because either alone is insufficient: refuse a pass whose clock outruns the newest
row it can see, and refuse any pass that would delete more than half the table.

### The capability test that tested the wrong runtime

It claimed to guard against an Electron bump removing an export or shipping an older SQLite,
and ran under the test runner's own Node with Electron mocked — so it would have stayed green
through exactly that regression. There is now `npm run test:capability`, which runs it under
the shipped Electron binary. It reports SQLite 3.53.1 on Node 24.18.1, against 3.51.3 under
the runner: the gap it was blind to.

### Two review findings that were wrong, and how that was established

The review said to debounce a flapping unit on its `active` state. That does not work — a unit
in a restart loop alternates between `activating` and `failed`, so `active` is precisely what
changes. Repeated changes to one fact now amortise into a single event carrying a count,
turning a hundred flaps into four rows.

It also said `LIKE` could not use the index. Measured, it uses the primary key for the host
column; what it cannot use is the key prefix. The range scan that replaced it is right, for a
different reason than the one given.

Both were caught by an implementer testing the instruction rather than following it, which is
now three times across two waves that a brief has been wrong and saying so was worth more than
compliance.
