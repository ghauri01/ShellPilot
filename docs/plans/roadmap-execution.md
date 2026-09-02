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
- [ ] Research: disk alert path
- [ ] Research: docker housekeeping
- [ ] Adversarial review of both plans
- [ ] Implementation
- [ ] Adversarial review of the diff
- [ ] Green gate

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
