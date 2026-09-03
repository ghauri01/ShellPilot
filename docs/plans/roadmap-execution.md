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

## Item 29 — a renderer that can be tested

The gap this closes is stated two sections up: no jsdom, no happy-dom, no testing-library,
`environment: 'node'`, and therefore **no React component in this app could be rendered in a
test**. The panel suites' `readFileSync`-plus-regex assertions were an honest workaround and
are still there; they were never able to fail for a component that renders the wrong thing.

### What was added

`jsdom`, `@testing-library/react`, `@testing-library/dom` and `@testing-library/user-event`,
as **dev** dependencies. `tests/rendererTestHarness.test.ts` is the standing guard on that:
it fails if any of the four appears in `dependencies` (which is the list electron-builder
ships into the asar) or if anything under `src/` imports one.

jsdom over happy-dom, on evidence rather than preference. happy-dom is faster and has a
smaller tree, which matters when `npm audit` is a hard CI gate — but `npm audit` reports the
same three pre-existing advisories with jsdom installed as without it, so that argument did
not apply here. What remained was fidelity: these tests exist to catch what actually renders,
testing-library is developed against jsdom, and a DOM difference that makes a real defect
invisible would defeat the entire item.

### Per-file environment, not a global flip

Renderer tests declare their environment in a docblock:

```tsx
// @vitest-environment jsdom
```

The default stays `node`. This is not a style choice between two working options —
`environmentMatchGlobs` was deprecated in Vitest 3 and **removed in Vitest 4**, which is what
this repo runs; nothing in `node_modules/vitest` responds to it any more. The docblock is
also the more honest form: the file that needs a DOM is the file that says so.

Measured cost to the main-process suite: 112 files, 2319 passing, **17.33s before and 17.83s
after**, with Vitest attributing 617ms of that to the new setup file — roughly 5ms per file
for importing a module that checks `typeof window` and returns. The full suite including the
new renderer tests runs in the same 16–18s band.

### The setup file

`tests/setup/global.ts` is the only entry in `setupFiles`. It is global because Vitest has no
per-environment setup list, so it does nothing and imports nothing until it has established
that a DOM exists; importing `@testing-library/react` unconditionally would put react-dom in
front of every sqlite test in the suite. When there is a `window`, it pulls in
`tests/setup/renderer.ts`, which does two things:

**Installs `window.shellpilot` before the test module is imported.** The preload bridge is the
renderer's entire outside world and `store/alerts.ts` reads it at module scope. The previous
way to work around that is at the top of `tests/diskAlerts.test.ts`: assign `globalThis.window`
by hand, then `await import()` the module so the assignment happened first. That works, but it
made every renderer test carry the ordering rule, and it is incompatible with a static import.
It is no longer necessary. `stubBridge({...})` replaces the bridge per test and is reset
afterwards. The default is an **empty object**, deliberately: every call site in the renderer
is written to survive a missing method (`src/renderer/src/lib/bridge.ts`), and a harness
handing out plausible defaults would let a component pass by talking to the harness.

**Snapshots and restores every zustand store.** The stores in `src/renderer/src/store` are
module singletons; a test that raises an alert or adds a server leaves it there and the suite
becomes order-dependent — passes alone, fails in CI. The harness globs that directory, so a
store added next month is reset without anyone remembering to come back here, and it also
calls any exported `reset*ForTests()` (e.g. `store/alerts.ts`'s), which owns module-level maps
a store snapshot cannot reach.

### Writing one

```tsx
// @vitest-environment jsdom
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { Thing } from '../src/renderer/src/components/.../Thing'
import { useApp } from '../src/renderer/src/store/app'

beforeEach(() => {
  stubBridge({ docker: { list: () => Promise.resolve(probe) } })
})

it('does the thing', async () => {
  const user = userEvent.setup()
  useApp.getState().setSettings({ ... })      // rolled back for you
  render(<Thing servers={[server]} />)
  await user.click(screen.getByRole('button', { name: /Read containers/ }))
  expect(await screen.findByText('web-1')).toBeTruthy()
})
```

Notes that are not obvious the first time:

- Test files are `.test.tsx`, and `vitest.config.ts` now includes that extension. The old glob
  would have silently ignored one.
- `esbuild: { jsx: 'automatic' }` is set in `vitest.config.ts`. The root `tsconfig.json` is a
  project-references stub with no `compilerOptions`, so esbuild finds no `jsx` setting to
  inherit and would otherwise emit `React.createElement` calls — which fail, because no
  component here imports React.
- There are no jest-dom matchers. `expect(el).toBeTruthy()`, `el.getAttribute('title')` and
  `document.body.textContent` cover what these tests need without a sixth dependency.
- To resolve a promise and let React render in one step, `await act(async () => { resolve(x) })`.
  That is how the stale-read test lands an answer at a controlled moment.
- `tests/` is in no tsconfig, so `npm run typecheck` does **not** type-check test files. ESLint
  does lint them. That predates this work and is worth fixing separately.

### The three tests, and the proof they can fail

Written against defects that had already shipped, so "would this have caught it" is answerable
rather than rhetorical. Each was confirmed by reverting the fix and watching the test fail.

**`tests/dockerPanel.test.tsx` — the cross-server stale read.** A `diskDetail` request still in
the air when the operator changes server used to land under the *new* server's heading: one
host's image, volume and container names presented as another host's, with the itemise button
hidden because a listing now existed. The test reads containers and disk for `alpha`, starts an
itemise whose promise is held open, switches to `bravo`, re-reads there, then resolves alpha's
answer. Reverting the generation guard in `loadDiskItems`:

```
AssertionError: expected 'Containersalphabravo Refreshdocker 24…' not to contain 'alpha-only/leaked-image'
Received: "...By itemCloseNothing on this list can be removed from here...Images (1)
alpha-only/leaked-image:v1alphaaaa111 · 3 weeks ago0 containers1.2GBrunningbravo-api..."
```

The leak is legible in the failure message itself: alpha's image, rendered directly above
bravo's container.

**`tests/dockerPanel.test.tsx` — the dead-end error state.** The itemise control used to gate on
`diskItems === null`, so a failed read — an SSH timeout, the most likely and most transient
failure — removed the only button that could retry it. The test fails the read, asserts a
"Try again" button exists and is enabled, then clicks it and asserts the listing arrives.
Reverting the gate to `diskItems === null`:

```
TestingLibraryElementError: Unable to find an accessible element with the role "button" and name `/Try again/`
```

**`tests/statusBar.test.tsx` — the mislabelled alert chip.** A different component, chosen to
show the harness generalises rather than being shaped around one file. The chip's tooltip once
built its label from a two-kind ternary; when `disk` became a third `AlertKind`, every disk
alert was labelled "Memory". Reverting `LABEL[a.kind]` to that ternary:

```
AssertionError: expected 'web-1: Memory 91%\n\nClick to open th…' to contain 'web-1: Disk 91%'
- web-1: Disk 91%
+ web-1: Memory 91%
```

That file also asserts the negative — no chip when nothing is alerting — which is what proves
the store rollback works rather than the previous test's alerts being inherited.

### What did not change

No production code. Not one line: the three defects were already fixed, and this item was only
ever about being able to prove it. No existing test was weakened, deleted or rewritten;
`tests/diskAlerts.test.ts` still stubs `globalThis.window` its own way and still passes.
Suite 2319 → 2333.

### One finding, unrelated but found here

`npm audit` exits 1 in this tree today, on three pre-existing advisories in transitive
dependencies (`@xmldom/xmldom`, `fast-uri`, `qs`), all with fixes available. CI runs bare
`npm audit` as a gate step. Adding jsdom changed nothing about that report — the diff is
byte-identical before and after — but the gate is already red for reasons that have nothing to
do with this work.

### A commit that does not build, and how it got there

`1f9bef5` does not compile. It carries a rename of `hostHealth.ts` out of the renderer
without the re-export shim or the five importer updates that make the rename survivable —
those arrived in the next commit. `git bisect` across that pair is unusable, and per-commit
CI would fail on it.

The cause is worth writing down because the mistake was invisible at the time and the
verification that should have caught it did not.

Two agents were working the same worktree on disjoint files. One of them staged a `git mv`
part-way through its task. When the other's work was committed — with explicit paths, chosen
deliberately after an earlier blanket `git add` swept in a different agent's work-in-progress
— the **already-staged rename came with it**, because naming paths on `git commit` does not
unstage anything else. The index had a change nobody in this conversation had put there.

Typecheck and the test suite were run first, and both passed, which is exactly why this was
missed: the shim existed in the working tree as an **untracked file**. Every check ran against
a tree that was correct and committed a tree that was not. Verifying the working tree says
nothing about what is staged.

Two things follow, and the second matters more.

**Never commit from a shared worktree without inspecting the index**, not just the working
tree — `git status --short` shows staged renames in the left column and it was on screen and
read past. Better: agents editing one worktree concurrently should not stage anything, and a
file move should be its own serialised step.

**A green check on the working tree is not a green check on the commit.** The only honest
verification of a commit is against what that commit contains — `git stash -u` then build, or
build the committed tree in a scratch clone. Everything else measures a different artifact
from the one being recorded.

Not rewritten. Another agent was mid-task on this branch when the finding landed, and
rewriting history under a live worker risks destroying real work to fix a bisect boundary.
The tip is green; the record of the mistake is more useful than a tidy history.

**Audited rather than assumed.** "Probably only that one" is not a safe inference about a
failure mode that was invisible to every check being run, so every commit on this branch was
built from a scratch clone at that commit — the method described above, applied. Twenty-five
of twenty-six compile clean on both the node and web configurations; `1f9bef5` is the only
one that does not, and nothing was hiding behind it. The damage is one bisect boundary rather
than a stretch of history.

The audit is cheap enough to keep: clone at the commit, symlink `node_modules`, run the two
typechecks. About twenty seconds each, and it is the only check that measures the artifact
being recorded rather than the one on disk.

### Three git hazards from concurrent agents, all the same shape

Running several agents in one worktree produced three separate incidents, and they are worth
naming together because they look unrelated and are not. Each is a **shared mutable resource
that git offers no isolation for**, touched by a process that believed it was working alone.

**One — `git add -A` swept another agent's work-in-progress into an unrelated commit.** The
commit message described a roadmap edit and the commit contained someone's half-finished
feature. Fixed by switching to explicit paths.

**Two — explicit paths were not enough.** A commit naming its own files still carried another
agent's *staged* rename, because naming paths on `git commit` does not unstage anything else.
That shipped the only non-building commit on this branch. Fixed by inspecting the index, not
just the working tree, before committing.

**Three — a bare `git stash` swept two agents' uncommitted work into a shared stack.** The
stash stack is shared across every worktree of a repository, which the environment
documentation says plainly and which nothing enforces. `git stash pop` then failed, because
one of the files had been rewritten by its owner in the meantime.

The third was reported immediately and accurately by the agent that caused it, which is why
nothing was lost: the stash was intact, and the affected file could be recovered with
`git show 'stash@{0}:path'` and merged deliberately rather than restored wholesale.

**What actually prevents this.** One writer per file is necessary and was already in place —
all three incidents happened between agents whose *files* did not overlap. The state they
collided on was not the files:

- **Nothing is staged until commit time.** A staged change is visible to every other process
  in the worktree and will join whichever commit happens next.
- **No history-rewriting or state-shifting command, ever** — `stash`, `checkout --`,
  `reset --hard`. Setting work aside means copying to a scratch directory.
- **Verify the commit, not the tree.** A scratch clone at the commit is the only check that
  measures what was recorded.

All three are now stated in every implementation brief rather than assumed. The lesson that
generalises past git: when several workers share a resource, the dangerous operations are not
the ones that write to their own files, but the ones that touch state they think is private
and is not.

### Queued: two blockers in the detached engine

Found by adversarial review of B2/B3/17. Both need `src/shared/jobs.ts` and
`src/main/services/jobDetached.ts`, which another agent holds while it unifies the sudo
prefix. Written down rather than held in conversation, because a queued blocker that exists
only in a chat message is a blocker that gets lost.

**Reboot verification never runs.** `classifyJobPoll` checks `rc !== null` first and
unconditionally, so a declared reboot only reaches the verification path when the wrapper
was killed before it could record an exit status. But `systemctl reboot` and `shutdown -r
now` both return 0 *immediately*, and the wrapper's next instruction writes `rc` — microseconds
later, while systemd is still stopping units. The marker directory deliberately survives the
reboot, so the first poll after the host returns lands in the finished branch, reaps, and
reports success.

`verifyReboot` is therefore unreachable in production. A host that was told to reboot, came
back with failed units, or never rebooted at all because something swallowed the request,
reports `ok` and the wave rolls on — which is the failure item 17 exists to prevent, in the
one code path it was written for. A test pins the behaviour as intended without confronting
what it implies.

The fix is that a *declared* reboot must not accept `rc` as its answer; it falls through to
the same verification the killed-wrapper case already uses.

**A race deletes the exit status of jobs that succeeded.** The poll reads `rc`, then checks
`kill -0`. Those are two adjacent instructions in the wrapper, and the polling shell can be
descheduled between them — so a wrapper that writes `rc` and exits inside that window is
observed as "no exit status, not alive". That classifies as `orphaned`, which reaps the
directory, **deleting the `rc` that was in fact written**, and records the OOM-killer
explanation for a job that exited zero.

The rc-before-output ordering is correct and must stay; the fix is a second read after the
liveness check, or one confirming poll before any reap.

The pattern in both is the same, and it is worth naming: **the happy path was never
exercised end to end.** Every state the engine can reach was tested, and the two defects live
in the ordinary sequence — a reboot that works, and a job that finishes — which the fake host
could produce but was never asked to.

### The key-change gate: what has to happen on a real host before it lifts

All five blockers are fixed and each was proved to fail first. The gate stays off anyway,
because the residual cannot be closed from a laptop, and the implementer said so rather than
declaring victory.

**The residual, precisely.** The watchdog now proves it armed before the file is moved, and
the launcher is chosen on the host: `systemd-run --user --scope` first, then `setsid`, then
`nohup`, and a refusal to write at all if none of them works. `systemd-run` is first for a
reason worth keeping — it escapes the **logind session scope** that `KillUserProcesses=yes`
kills, whereas `setsid` escapes the terminal and not the cgroup. That distinction is the
difference between a fix and a fix-shaped comment.

What it still cannot promise: a transient systemd scope lives under `user@.service`, and a
user manager with no lingering and no other session can be stopped with everything inside it.
The arming proof catches a watchdog that never started; it cannot catch one killed afterwards.
If that happens the change is live and unprotected, and the leftover backup blocks further
changes on that host until a person looks — the refusal names the file and the remedy, but
nobody has watched it happen.

**Five things to try on a real estate, in order of what they would teach:**

1. **A RHEL 9 host with `KillUserProcesses=yes` and no lingering.** The one case that decides
   whether this protocol is sound. Stage a revoke, let the session end, and see whether the
   file comes back.
2. **`ExposeAuthInfo yes` with `AuthenticationMethods publickey,publickey`** — both factors
   should appear on separate lines and both should be protected from removal.
3. **An `AuthorizedKeysFile` drop-in the connecting account cannot read** — the write gate
   should close on `partial` on a real host, not only on a synthesised status line.
4. **`StrictModes` under `umask 002`** — what mode the replaced file actually has as sshd
   sees it.
5. **`systemd-run --user --scope --quiet --collect true` on Debian, Ubuntu and Alpine** — the
   probe should degrade to `setsid` rather than hang.

**Two decisions inside the fixes worth remembering.** Overlapping changes are refused rather
than resolved with a lock: killing the first change's watchdog while that change is still
unconfirmed is "silently make it permanent", which is the same failure pointing the other
way, and with one backup per host there is no safe overlap. And a session that authenticated
with a password rather than a key is still refused, even though the host has *proved* no key
holds it open — being wrong there costs a lockout, and being conservative costs nothing on a
configuration nobody runs.

`AccessJobSpec` and the `'access'` job kind were deleted rather than wired. Nothing ever
created one, and the job engine cannot supply the fresh, unpooled session this protocol
depends on — so the serialisation it needed is asserted where it actually lives.
