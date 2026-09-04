# Fleet panel UX audit

The twenty fleet-operations panels under `src/renderer/src/components/monitor/`
(plus the Docker panel they sit beside) were built over four releases by four
separate passes. Each pass was internally consistent and none of them agreed
with the others. This is the inventory that came before the fix.

`AlertsPanel.tsx` is excluded throughout — it was being redesigned separately
while this audit was written.

---

## 1. Primary actions

Every panel has exactly one thing a first-time user is supposed to press. In
almost none of them was that thing the most prominent control on screen.

| Panel | Primary action | Class before | Visually primary? |
| --- | --- | --- | --- |
| InventoryPanel | Check now | `btn` | No |
| AccessPanel | Check now | `btn` | No |
| PosturePanel | Check now | `btn` | No |
| DriftPanel | Check now | `btn` | No |
| PatchPanel | Check now | `btn` | No — and it sat *third* in the row, after two `btn ghost sm` buttons |
| CapacityPanel | Refresh | `btn` | No |
| CronPanel | Read schedules / Refresh | `btn` | No |
| ChangeLogPanel | Refresh | `btn ghost sm` | No — the panel's only action was styled as its least important |
| DockerPanel | Read containers / Refresh | `btn` | No — **the case the complaint names** |
| BroadcastPanel | Run | `btn primary` | Yes |
| LogTailPanel | Tail | `btn primary` | Yes |
| RulesPanel | New rule | `btn` | No |
| FleetMonitor | New group | `btn ghost` | No |
| FleetHealth | Open Monitoring settings | `btn sm ghost` | No |
| FleetSearch | (the search field itself) | — | n/a, field is the affordance |
| ServerMonitorCard | — | — | display only |
| FleetWatcher | — | — | headless, renders `null` |
| MonitorSidebar | — | — | 745 B of layout |

**2 of 15 panels with an action made it primary.** Eleven read-the-estate
panels all used the same neutral `btn`, so on first open the eye had nothing to
land on — which is exactly the Docker complaint, generalised.

`btn primary` was in fact reserved, by accident, for the two *dangerous* actions
in the whole feature area: running an arbitrary command on every selected host
(Broadcast) and opening a live stream (LogTail). The one visual signal meaning
"press this" was pointed at the two buttons a new user should press last.

---

## 2. Type scale actually in use

`tokens.css` declares six sizes (`--fs-xs` 11 → `--fs-2xl` 22). Inside a panel
body, only the bottom four were reachable, and none of them was larger than
body text:

| Size | Where | Count |
| --- | --- | --- |
| 13px (`--fs-md`, body default) | everything unstyled, `.btn`, `.s-desc`\* | — |
| 12px | inline `style={{ fontSize: 12 }}` | 35 occurrences |
| 11px | inline `style={{ fontSize: 11 }}` | 45 occurrences |
| 10px | `.chip`, inline | 8 occurrences |

Distinct weights: `<b>` (bold 700) for panel titles, `550` on `.btn`, `600` on
`.chip`, default `400` everywhere else.

Three findings:

1. **The panel title is the same size as the body.** Every panel names itself
   with `<b className="grow">Inventory</b>` — a 13px bold inline element. It is
   not a heading, it is not larger than the paragraph beneath it, and it is not
   in the accessibility tree as a heading either. `.content-header h1` (18px)
   exists but only FleetMonitor, the container, uses it.

2. **\*`.s-desc` is unstyled inside these panels.** This is the single largest
   cause of the complaint. `global.css` only ever defines it as a descendant:

   ```css
   .setting-row .s-desc { font-size: var(--fs-sm); color: var(--text-muted); }
   ```

   There are 60+ uses of `className="s-desc"` in the monitor panels and none of
   them is inside a `.setting-row`. Every one of them renders at **13px in
   full-strength `--text`** — identical to the interactive content around it.
   The paragraph the user is supposed to skim and the row they are supposed to
   act on are the same size and the same colour. Verbatim from the complaint:
   "most panels open with a paragraph of prose in the same size and colour as
   the interactive content".

3. **`.warn`, `.danger` and `.ok` as bare classes do not exist.** `global.css`
   defines `.chip.warn`, `.bar.warn`, `.log-line.warn .lvl`, `.backup-banner.warn`
   and `.setting-row .s-desc.warn` — every one of them compound. There is no
   rule for `.warn` on its own. So all ~35 uses of `<span className="warn">` in
   these panels render in ordinary body colour:

   - PosturePanel: `{n} could not be read`, `{n} with a weak sshd setting`,
     `{n} with an EXPIRED certificate` — 11 sites, none coloured.
   - InventoryPanel: `{n} hosts could not be counted`, `stale package cache`.
   - CronPanel: `{n} lines not understood`. DriftPanel: `{n} differ`.
     AccessPanel: `unchecked-hosts`, `incomplete-hosts`. PatchPanel: reboot owed.
   - RulesPanel: `<div className="row danger">`, the panel's error banner.

   The word "EXPIRED" is capitalised in the source specifically to shout, which
   is what you do when the colour you asked for is not arriving.

4. **`.s-desc.warn` and `.s-desc.danger` are silently inert.** Those modifiers
   are also `.setting-row`-scoped. So `<div className="s-desc danger">` in
   InventoryPanel ("the facts probe failed"), LogTailPanel, DockerPanel,
   BroadcastPanel and CapacityPanel renders in ordinary body text with no
   colour at all. A failure and an explanation were indistinguishable.

   *This is presentational, not a logic bug — the text is correct and present.
   Nothing was hidden, only levelled.*

The 11px/12px inline sizes are used for two different jobs — count roll-ups and
footnotes — with no rule for which gets which, so the same information
(a coverage caveat) is 11px in InventoryPanel and 13px in DriftPanel.

---

## 3. Colour roles, and where one colour means two things

Available tokens: `--accent`, `--ok`, `--warn`, `--danger`, `--info`, plus
`--text` / `--text-muted` / `--text-faint`.

| Token | Meanings it is carrying |
| --- | --- |
| `--accent` (cyan) | (a) primary action fill, (b) focus ring, (c) text selection, (d) **selected/active** — `.seg-btn.active`, `.bc-panel .chip.on`, (e) **drag-and-drop target** — `.card-slot`, `.mg-head.dragover` |
| `--warn` (amber) | (a) **watch** — a real degraded state (`{n} hosts awaiting a reboot`), (b) **unknown** — a measurement that could not be taken (`{n} hosts could not be counted`, `could not be read`, `did not answer`) |
| `--danger` (red) | (a) **alarm** — a failing host, (b) **destructive action** — `.btn.danger` Stop / Revoke, (c) **error message** — `s-desc danger` |
| `--info` (blue) | **defined and never used in any of these panels** (0 references) |
| `--text-faint` | (a) decorative header icons, (b) "no rules" empty text, (c) retention footnotes |

The `--warn` collision is the consequential one. This feature area is *built*
around the distinction between "bad" and "not known", and says so at length in
its own comments — PosturePanel: *"a security roll-up drawn over only the hosts
that answered is the exact shape of reassuring fiction this panel exists to
avoid"*; InventoryPanel: *"Treat those hosts as unknown, never as zero"*. The
code separates the two counts meticulously and then paints them the same amber.
There were **four status meanings and only three colours**.

`--accent` meaning both "press this" and "this is currently selected" is why
adding `primary` to a read button is safe but adding it to a *toggle* would not
be — the toggles already own that colour.

Accessibility: colour was frequently the only signal. `<span className="warn">`
around a count adds no icon, no text marker, and no non-colour cue. `.chip.ok`
/ `.chip.warn` / `.chip.danger` differ only in hue and background tint.

---

## 4. Empty states

`components/common/EmptyState.tsx` exists and is used by seven screens.
**Zero monitor sub-panels use it.**

| Panel | Empty state | Quality |
| --- | --- | --- |
| InventoryPanel | Yes | Good prose, no visual separation, no button — tells you to "Press **Check now**" in text while the actual button is unstyled |
| AccessPanel | Yes | Same |
| PosturePanel | Yes | Same |
| DriftPanel | Yes | Same |
| PatchPanel | Yes | Same |
| CronPanel | Yes | Describes the mechanism, never says what to press |
| DockerPanel | Yes | Describes the mechanism, never says what to press |
| CapacityPanel | Yes | Four separate one-line states, all flat |
| ChangeLogPanel | Yes (`changelog-empty`) | Flat |
| LogTailPanel | Yes | Good — the best of them |
| FleetSearch | Yes | Distinguishes "nothing sampled" from "nothing matched" |
| FleetHealth | Yes (`NotYetChecked`) | Good, and has an action button |
| **RulesPanel** | **Barely** — `<div className="faint">No rules. Nothing runs on its own.</div>` | 12px grey text, no next step |
| **BroadcastPanel** | **No** — `No server in this workspace is online.` in `.faint`, and with servers online the panel is just an empty chip row | No guidance |
| FleetMonitor | Yes, real `EmptyState` | Good |

So: the *information* is nearly always there. What is missing is that an empty
state looks exactly like a populated one minus the rows — same size, same
colour, no frame, and the button it names is not the button that stands out.

---

## 5. The same concept under different names

| Concept | Names in use |
| --- | --- |
| Fetch the data now | **Check now** (Inventory, Access, Posture, Drift, Patch) · **Refresh** (Capacity, ChangeLog, Cron-when-loaded, Docker-when-loaded) · **Read schedules** (Cron) · **Read containers** (Docker) · **Tail** (LogTail) · **Run** (Broadcast) |
| The scheduled background collection | **background checking** (8 files) · **background sweep** (5 files) · **fleet sampler** (Capacity, Patch) · **sampling** (5 files) |
| A machine | **host** (Inventory, Access, Posture, Drift, Patch, Cron) · **server** (FleetMonitor, Broadcast, Docker, Capacity) — often both in one panel: FleetHealth says "0 of 10 **servers** reporting" above a list of **host** rows |
| Turning a panel on | **Choose modules** (FleetMonitor) · **Modules** (ChangeLog) · **Open Monitoring settings** (FleetHealth) |
| A gap in coverage | **could not be counted** · **could not answer** · **could not be checked** · **did not answer** · **never collected** · **not measured** |

These are content changes, not presentation, so this pass **did not rename
anything** — every existing label and sentence is preserved verbatim. Recorded
here as the follow-up.

---

## 6. Bugs found, not fixed

Per the brief, logic problems are reported rather than repaired.

1. **`.bc-panel .chip.on { color: #fff }`** (`global.css:2723`) hard-codes white
   instead of `var(--accent-text)`. In the light theme `--accent-text` is
   `#ffffff` so it happens to agree; in dark it should be `#0b1013`. Selected
   host chips in BroadcastPanel therefore render white-on-cyan in dark mode,
   which is a contrast regression against the token system's own intent. Left
   alone — it is an existing rule and the brief forbids modifying those.

2. **`CapacityPanel` renders `No servers to chart.` before checking `loading`**,
   so a workspace mid-load briefly asserts an absence. Cosmetic ordering, no
   data lost.

Neither was touched.

---

## 7. The system that was added

All of it appended to the end of `global.css` in one block. No existing rule was
modified or removed, and no dependency was added.

### Type scale — four sizes, five roles

| Role | Class | Size / weight |
| --- | --- | --- |
| Page title | `.ui-page-title` | 18px / 650 |
| Section heading | `.ui-section-title` | 15px / 600 |
| Body | `.ui-body` (default) | 13px / 400 |
| Explanatory | `.ui-note`, `.panel-note` | 12px, `--text-muted`, 78ch measure |
| Label | `.ui-label` | 12px / 600, uppercase, 0.06em |

The label role separates itself by weight, caps and tracking rather than by a
fifth size — the panels already had 10/11/12/13 doing that, and a scale with a
step every pixel is not a scale. The explanatory role is **two** steps down from
body, smaller *and* quieter, because one step was not enough to stop the eye.

### Colour roles

Action roles (`--role-primary*`, `--role-secondary*`, `--role-destructive*`) are
named separately from `--accent` even where they resolve to it, so that changing
what a pressed button looks like does not also move the focus ring.

Four status roles, up from three colours: `--state-ok`, `--state-watch`,
`--state-alarm`, `--state-unknown`. Unknown is a **slate, not a hue** — an
absence should read as an absence rather than as a third kind of problem, and it
is the only one of the four that is achromatic, so it stays distinguishable
without colour vision. All four are defined on `:root` and redefined under
`:root[data-theme='light']`, the same mechanism `tokens.css` already uses.

Non-colour signalling: `.state-dot` gives each state a distinct shape — filled
disc, filled triangle, filled square, hollow ring — and every status text site
already carries a sentence saying what is wrong. `.panel-note.is-*` adds a
2px left rule in `currentColor`, so a finding is separable from surrounding
prose by its edge as well as its hue.

### Patterns

- `.panel-head` — a three-column grid: icon, title, actions right-aligned, with
  the one-line purpose spanning under the title. A grid rather than a flex row
  because the old row had nowhere to put a sentence, which is exactly why the
  sentence became a full-width paragraph below it.
- `.panel-stats` — the count roll-up six panels carry, at 12px instead of an
  inline 11px that put the numbers below the prose they sit above.
- `.panel-empty` — dashed frame, title, body, action row.
- `.panel-subtitle` — sub-group heading within a panel (one host's cron block).
- `.btn.primary:focus-visible` — the global focus ring is `--accent`, which on
  an accent-filled button was accent-on-accent. Offset ring plus a
  panel-coloured halo, in both themes.
- `@media (prefers-reduced-motion: reduce)` — the refresh spinner is slowed
  rather than removed; it is the only signal a sweep started.

### The bare status classes

`.warn`, `.ok` and `.danger` were given rules. This is the smallest possible fix
for the largest finding: 42 call sites across 13 components were marked as
warnings by their authors and drawn in ordinary body text. Every compound form
that already existed is specificity (0,2,0) or higher and still wins —
`.chip.warn`, `.bar.warn`, `.log-line.warn .lvl`, `.backup-banner.warn`,
`.setting-row .s-desc.warn`, and `.alerts .warn`, which owns its own scoped
block.

Where a panel needed the watch/unknown distinction the audit found, the call
site was moved to the explicit `.state-watch` / `.state-unknown` role instead,
so the two are no longer the same colour.

| | Components with inert status colour | Call sites |
| --- | --- | --- |
| Before | 13 | 42 |
| After | 0 | 0 |
