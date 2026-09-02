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

- [ ] Research: durable store options (running)
- [ ] Research: host facts
- [ ] Research: job engine — blocked on the store decision
