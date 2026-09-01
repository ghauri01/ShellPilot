# Local Terminal + Tab/Pane Multiplexing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add local shell sessions (macOS/Windows/Linux) to ShellPilot as first-class tabs and panes, alongside the existing SSH sessions, without exposing a local shell over MCP.

**Architecture:** A new main-process service `localPty.ts` mirrors `ssh.ts`'s data plane exactly — per-session IPC channels, a per-tick output coalescer, a `disposeAll` on `before-quit` — but drives an in-process `@lydell/node-pty` instead of an `ssh2` `ClientChannel`. The renderer's `useRealSession` hook is refactored to be transport-agnostic, and `Tab` becomes a discriminated union (`kind: 'ssh' | 'local'`) rather than a `Server` row with a synthesized pseudo-server. Panes become a per-tab array of session descriptors instead of the hard-coded 2-way split.

**Tech Stack:** Electron 43, TypeScript 5.7, React 19, Zustand 5, xterm.js 5.5, `@lydell/node-pty@1.2.0-beta.15` (Node-API, prebuilt), vitest 4, electron-builder 26.

---

## ⚠️ Review findings — read before starting

Three adversarial reviews (correctness, packaging/CI, security) ran against the first draft of this
plan. Everything below **supersedes** the phase text where they conflict. Items marked BLOCKING must
be resolved before the phase they name is started.

### Answered open questions — close these, do not re-investigate

- **Q1 — `handleFlowControl` exists.** Verified against the installed package:
  `@lydell/node-pty-<platform>-<arch>/lib/terminal.js:33-35, 76-82` implements `handleFlowControl` /
  `flowControlPause` / `flowControlResume` exactly as the backpressure design assumes, and the match
  is `data === this._flowControlPause` — an exact string comparison, which confirms the reasoning for
  rejecting `\x13`/`\x11` as tokens. The Q1 fallback is not needed.
  **Note the path**: this file is in the *sibling* package, not in `@lydell/node-pty`, which is 5
  files with no `lib/` at all. Anyone re-verifying Q1 or Q3 by path must read Q2's sibling-package
  structure first — confusing the two is the same mistake finding #14 is about. Glob
  `node_modules/@lydell/node-pty-*/lib/` rather than hardcoding an arch.
- **Q2 — prebuilds live in SIBLING packages.** `@lydell/node-pty` is a 13.5 KB, 5-file meta package
  with no prebuilds; `index.js` resolves `@lydell/node-pty-${process.platform}-${process.arch}` at
  runtime. Both `asarUnpack` patterns are correct and disjoint (verified against minimatch with
  electron-builder's own `{dot:true}` config). The sibling pattern is the load-bearing one.
- **Q3 — CLOSED. The bundled ConPTY is optional; the exclusion is safe.** Verified on a real Windows
  machine (`windows-latest`, CI run 33494240165): the `conpty/` directory was deleted from the
  installed package and `cmd.exe` then spawned and echoed through ConPTY with `conpty.dll` and
  `OpenConsole.exe` absent — the exact condition the shipped build creates, since `localPty.ts`
  asks for `useConptyDll: false`.

  Structure, also confirmed: `prebuilds/win32-x64/conpty/` holds only `conpty.dll` and
  `OpenConsole.exe`; `conpty.node` and `conpty_console_list.node` sit one level up as files, so the
  `conpty/**` negation cannot reach the bindings.

  There is now a permanent guard — a `windows-latest` step in `ci.yml` that removes the directory
  and respawns on every push and PR. It **fails when the directory is absent** rather than passing
  for having found nothing to do, which is the failure mode that let the broken exclusion pattern
  ship in the first place (see the correction to finding #9 below).
- **Q6 — closed.** `ALLOWED_TOOLS` matches all 15 `registerTool` calls in `mcpServer.ts` exactly, and
  `(^|_)exec($|_)` correctly does not match `execute_command` (`execu` is not the token `exec`).

### Phase 0 Step 6 — RUN, on macOS arm64, and it passes

The check this plan calls the most important one has now actually been performed against a real
`electron-builder --dir` pack (ad-hoc signed, `hardenedRuntime: true`, real entitlements):

```
loaded: function
exit={"exitCode":0,"signal":0}
PACKAGED_PTY_OK
PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:...
```

- **`pty.node` loads in the packaged, signed, hardened-runtime main process.** R1 is closed for
  macOS: the failure mode recorded at `electron-builder.yml:124-129` for `cpu-features` does not
  apply, because that module is NAN/V8 and this one is Node-API.
- **`spawn-helper` execs**, and electron-builder re-signs it `flags=0x10002(adhoc,runtime)` — npm
  ships it `linker-signed` — with mode 755 preserved.
- **`/opt/homebrew/bin` is first on `PATH`**, so the macOS login-shell requirement works end to end.
- `extraResources` with a missing `from` is confirmed a **warning**, not an error: the pack logged
  `file source doesn't exist … resources/bin/darwin-arm64` and continued. The CI `pack` job will not
  fail for absent engines.

**NEWLY VERIFIED FOOTGUN — the `app.asar.unpacked.unpacked` double-rewrite is real.**
`unixTerminal.js:33` is `helperPath.replace('app.asar', 'app.asar.unpacked')` — a **first-occurrence
string** replace. So resolving node-pty through a path that already contains `app.asar.unpacked`
produces `app.asar.unpacked.unpacked` and every spawn dies with
`posix_spawn failed: No such file or directory`. The earlier research flagged this as unconfirmed
(third-party trackers only); it is now confirmed by direct observation.

`localPty.ts` is safe because `await import('@lydell/node-pty')` resolves through normal Node
resolution, i.e. via `app.asar`. **Never require node-pty by an explicit
`app.asar.unpacked/...` path**, in product code, in a test, or in a diagnostic script.

**Since shipped in 0.8.0, and no longer open:**

- **Windows and Linux PTY** — both spawn and echo on their own CI runners, so the binding loads and
  a shell starts on all three platforms, not only macOS.
- **Q3** — closed, see above.
- **The AppImage `noexec /tmp` case (finding #19) is void**, and for a reason worth recording: the
  Linux sibling package ships `prebuilds/linux-x64/pty.node` and nothing else. There is no
  `spawn-helper` on Linux at all — it is a macOS-only workaround for the hardened-runtime `fork()`
  penalty. `pty.node` is `dlopen`'d, which `noexec` does not block. The pack verifier originally
  demanded `spawn-helper` on every non-Windows platform and failed the first 0.8.0 Linux build for
  a file that is not supposed to exist.

Still unverified: nobody has **opened the app** on Windows or Linux and used a local terminal. The
PTY layer is proven on all three; the UI around it — shell discovery populating the picker, panes,
the tabs — is proven only on macOS.

### BLOCKING — correctness

1. **Phases 1 and 2 are ordered backwards.** `localPty.ts` imports `findShell` / `sanitisedEnv` from
   `shellDiscovery.ts`, which Phase 2 creates. Phase 1 cannot typecheck or run its own test. **Swap
   the phases**, or move `findShell` + `sanitisedEnv` into Phase 1 and leave only per-OS discovery
   in Phase 2.
2. **Phase 4 breaks every SSH terminal until Phase 6.** The new `TerminalView` falls through to
   `EmptyState` when given no `transport`, but Phase 4 does not modify `WorkspacePanel.tsx`, whose
   three call sites (`:74`, `:77`, `:81`) all still pass `server={server}`. Phase 4 has no
   kill-switch. **Phase 4 must include `WorkspacePanel.tsx`** and construct
   `sshTransport(server, setServerStatus)` at all three sites in the same commit. Also update
   `RealTerminal`'s dead-session overlay (`:494`, `{server.username}@{server.host}:{server.port}`)
   and its `PasteConfirm` prop (`:511`) to use `transport.subtitle` / `transport.title`.
3. **The flow window deadlocks on non-ASCII output.** `onSent` receives
   `Buffer.byteLength(payload, 'utf8')` (bytes) while `onAck` receives `d.length` (UTF-16 code
   units). Every multi-byte character accrues a deficit that `Math.max(0, …)` cannot repay; past
   `FLOW_HIGH_WATER` the pty pauses permanently. Triggers on `htop`, `vim` with a Unicode
   statusline, `fzf`, `git log` with non-Latin names, Powerlevel10k. **Fixed inline below** —
   `onSent` now takes `payload.length`. Add a test that pushes a multi-byte payload through the real
   `coalescer`→`onSent` path and asserts the window returns to zero.
4. **`localClose` during an in-flight `localConnect` orphans a live shell.** `ssh.ts:565` registers a
   placeholder before awaiting and re-checks at `:572-577`; `localPty` registers only after two
   awaits and never re-checks. Guaranteed under React StrictMode in dev. **Fixed inline below.**
5. **Phase 8's flag flip reaches nobody who ran a Phase 3–7 build.** `save()` (`persist.ts:127-143`)
   writes `settings` wholesale and `replaceAll` (`app.ts:1040`) merges saved-over-default, so a
   persisted `false` permanently wins. `app.ts:67-71` documents this exact trap for `shortcuts`.
   Gate on `settings.localTerminalEnabled ?? true` and persist the key only when the user toggles it.
6. **`localTerminalEnabled` and `ELECTRON_DISABLE_LOCAL_TERMINAL` are referenced but never created.**
   Both appear in the phase preamble, Phase 3's rollback, Phase 6 Steps 3/6 and the rollback table.
   Add the `AppSettings` field and the `loadPty()` env check in the phase that first claims them.
7. **The narrowing table is wrong in three rows and missing six sites.** Under a discriminated union
   `t.serverId` on a `LocalTab` is a *compile error*, not `undefined` — so `app.ts:734-735`,
   `ConnectionTree.tsx:141` and `app.ts:680` are NOT "already correct". Missing entirely:
   `app.ts:495` (`openServer`), `app.ts:534` (`duplicateTab` lookup), `app.ts:163`+`:552-554`
   (`openTab` — `Omit` does not distribute over unions), `app.ts:588-589` (`setTabView` spread), and
   `useHotkeys.ts:55-58` (`open-files` on a local tab blanks the pane). **Regenerate the table from
   `grep -n '\.serverId\|activeTab()\|servers\.find' src/renderer` and delete the "safe as written"
   column — nothing touching `.serverId` is safe under a union.**
8. **The pane re-key leaks state and has a second consumer.** `dropTabs` (`:249-270`) deletes
   `tabSession[tabId]`/`tabCwd[tabId]`, which match nothing after the re-key to paneId — one stranded
   entry per pane per closed tab, forever. And `SftpView` is not the only reader: `app.ts:544`+`:548`
   in `duplicateTab` are tabId-keyed, so duplicate-tab silently stops inheriting the remote directory
   (contradicting its own comment at `:527-529`). Add both to the manual matrix.
9. **Four call sites need a renderer-side shell list that nothing creates.** `PaneGrid`'s
   `transportFor`, `openLocalById`, the hotkey runner's undefined `defaultShellId`, and the palette
   each need `LocalShell[]`; the plan's cache lives in main. Add an unpersisted `localShells` store
   slice with a `refreshLocalShells()` action in **Phase 5**, so Phase 6's consumers share one source.
10. **The Linux dash exclusion does not work.** `basename('/bin/sh')` is `'sh'`, not in
    `NON_INTERACTIVE`, and `/bin/sh` is a *symlink* to dash on Debian/Ubuntu. `discoverLinux` then
    deliberately pushes `/bin/sh` three lines after claiming it was rejected. Use `realpathSync`
    before `basename`, or add `'sh'` to the set and fall back to `/bin/bash`.
11. **Shell ids collide.** `darwin-${basename(path)}` gives `/opt/homebrew/bin/zsh` and `/bin/zsh`
    the same id (the alt-loop dedupe compares `path`, not id), making the second unselectable.
    Derive the id from the full path. Also, macOS labels "(default)" based on the shell *being zsh*
    rather than *being default* — use `discoverLinux`'s `isDefault ? … : …` form on all platforms.
12. **Phase 6 has zero automated tests** and is the highest-risk phase (re-keys `tabSession`/
    `tabCwd`, replaces `tabSplit`, changes `dropTabs`, no kill-switch). `useApp` is testable under
    the existing node environment. Add `tests/localPanes.test.ts` (~120 LOC) covering `splitPane`
    past `MAX_PANES`, `closePane` state cleanup, `dropTabs`, `duplicateTab` pane+cwd copy, and the
    `toggleSplit` shim truth table for {1 pane, N panes, same dir, other dir, at cap}.
13. **LOC estimate is ~35 % light against its own arithmetic.** The tables sum to ~1,130 new +
    ~497 modified + 670 tests ≈ **2,300**, not 1,700. With findings 7/9/12 added, budget
    **~2,400–2,600**.

### BLOCKING — packaging

14. **The macOS x64 DMG will ship the arm64 prebuild.** Siblings are `os`/`cpu`-gated so `npm ci`
    installs exactly one; `electron-builder.yml:139-141` builds both arches from one arm64 runner
    with one `npm ci`, and electron-builder packs the same `node_modules` into both bundles. Intel
    Macs get `MODULE_NOT_FOUND`. **Every check in this plan passes anyway** — `--dir` packs host arch
    only, the verifier's `pty.node` assertion is arch-agnostic, and the release step's
    `find … | head -n1` inspects one `.app`.

    **RESOLVED — and the arch-matrix half of the suggested fix was itself wrong.** Implementation
    established three things this finding could not have known:
    - **`latest-mac.yml` is written per electron-builder invocation.** electron-builder publishes
      directly (GH_TOKEN is set on the build step — that is how updater metadata reaches the release,
      since `upload-artifact` does not list `latest*.yml`). Two mac jobs means two `latest-mac.yml`
      uploads to one release, each listing only its own dmg, so the losing architecture is handed the
      other's download on every auto-update check. Worse than the bug being fixed, and slower to notice.
    - **`npm ci --os=darwin --cpu=x64` breaks the build, not just the pack.** The os/cpu-gated set in
      this tree is `@esbuild/darwin-arm64`, `@rollup/rollup-darwin-arm64`, `fsevents` and the node-pty
      sibling. A target-arch install swaps esbuild and rollup for binaries the runner cannot execute,
      so the matrix would also require splitting `npm run build` from `electron-builder` and
      reinstalling between them.
    - **`electron-builder --mac --x64` would not have worked anyway.** `computeArchToTargetNamesMap`
      (`targetFactory.js:11`) honours CLI arch flags only when the config target has no `arch` key;
      with `arch: [x64, arm64]` present, `--x64` is ignored and both arches build. The `dmg:x64` form
      does override.

    **What shipped:** a release step force-installing both `@lydell/node-pty-darwin-{x64,arm64}` at
    the version resolved for the meta package, scoped to those two names (`--os`/`--cpu` would apply
    to the whole reify and hit esbuild/rollup), hard-failing if either `pty.node` is missing. Cost
    ~1 MB of unused prebuild per dmg. The verifier asserts the target arch and the signature step
    loops over every `.app`.
15. **The new release guard passes when it finds nothing.** The `-d` test on `…/@lydell` succeeds as
    soon as the meta package is copied; if the sibling pattern is ever dropped, `find` matches zero
    files, the `while` body never runs, and the release ships a binding-less app green. Count the
    matches and fail on zero. *(The subshell concern is unfounded — `set -euo pipefail` is inherited
    and the `while` is the last pipeline element, so codesign failures do fail the step.)*
16. **`'!**/prebuilds/**/*.pdb'` is a no-op.** `appFileCopier.js:128-132` already strips `.pdb` from
    node_modules unless `includePdb: true`. Delete the pattern and its test; if you want a guard,
    assert `cfg.includePdb !== true`.
17. **The `extendInfo` rationale is factually wrong.** macOS does **not** terminate for the
    Files-and-Folders class — that behaviour belongs to Camera/Contacts/Photos etc. Terminal.app
    declares none of the three keys; 4 of 102 apps in `/Applications` declare
    `NSDownloadsFolderUsageDescription`. A denial is `EPERM`, not a signal. **Keep `extendInfo`**
    (better prompt copy is worth it) but rewrite the comment and R4, and replace Step 8's
    unfailable check. The real ad-hoc-specific cost the plan missed: with `identity: '-'` TCC keys
    the grant to the `cdhash`, which changes every build, so **every release re-prompts**.
18. **The `pack` job does not sign on pull requests.** `isSignAllowed()` returns false when
    `GITHUB_BASE_REF` is set, so the PR-packed `.app` is unsigned while the `main`-packed one is
    signed — one job, two configurations. And the verifier's codesign assertion is a tautology: the
    shipped prebuilds arrive from npm already `adhoc, linker-signed`, so `codesign --verify --strict`
    passes regardless. Drop that assertion or set `CSC_FOR_PULL_REQUEST=true`; remove the "macOS
    codesign" cell from the Testing-strategy table either way.
19. **AppImage `noexec` is the missing half of Q4.** `pty.node` is `dlopen`ed and survives `noexec`;
    `spawn-helper` is `posix_spawn`ed and does not. On a host with `noexec` `/tmp` every local spawn
    fails with `EACCES` in the AppImage build only — invisible to `--dir` packs and to the mode-bit
    check. Test with `mount -o remount,noexec /tmp`; if it fails, copy `spawn-helper` to
    `app.getPath('userData')` at 0700 on first use.
20. **On Windows the verifier is mostly vacuous.** It checks `pty.node` and `spawn-helper`, neither
    of which exists there. Assert `conpty.node` and `conpty_console_list.node` exist and `conpty/`
    does not. Note also `windowsPtyAgent.js:221` forks `conpty_console_list_agent` from inside
    `app.asar` — a second exec surface nothing tests.

### BLOCKING — security

21. **The static import guard does not work.** Its regex matches only `from '...'` and
    `require('...')` — it misses `await import('./localPty')`, **the exact idiom `localPty.ts`
    itself uses**, and misses `.js` specifiers, which are `src/cli/`'s own convention. Replace the
    regex with `ts.preProcessFile(src, true, true).importedFiles` (TypeScript is already a
    devDependency).
22. **The guard's file list is hand-picked, not an import closure.** `mcpServer.ts` really imports 17
    modules; the plan guards 5. Unguarded but directly reachable: `ssh.ts`, `sftp.ts`, `db.ts`,
    `tunnel.ts`, `metrics.ts`, `credentialResolver.ts`, `serverResolver.ts`, `approvals.ts`,
    `auditLog.ts`, `secretRedaction.ts`, `policyStore.ts`, `cliPairing.ts`, `vpn/managerApi.ts`.
    The likely breach is one this plan creates: it copies `ssh.ts`'s coalescer byte-for-byte, the
    first review comment will be "don't duplicate this", and hoisting it to a shared module puts
    `localPty` in `mcpServer`'s graph while `mcpServer.ts`'s own text never changes. **Compute the
    transitive closure from `mcpServer.ts` and `src/cli/index.ts`** (~30 LOC).
23. **`localTerminalEnabled` is renderer-side only; the IPC handlers register unconditionally.** So
    **Phases 3–7 all ship a live local-shell IPC surface with the feature nominally off** — a
    compromised renderer just calls `window.shellpilot.local.connect()`. Gate in main: read
    `settings.localTerminalEnabled` in the existing `data:save` handler (`main/index.ts:704`) and
    no-op every `local:*` handler when false, or do not register them at all.
24. **`local:connect` validates nothing.** `cols`/`rows` go unclamped into `forkpty`'s `winsize` /
    ConPTY's `COORD` in a beta native addon (while `localResize` *does* clamp). `cwd` accepts any
    string — on Windows a UNC path (`\\attacker\share`) is an NTLM-hash-leak primitive. `sessionId`
    is unvalidated and builds IPC channel names. `zod` is already a runtime dependency: validate
    `sessionId` as `/^[A-Za-z0-9._-]{1,128}$/`, `cols`/`rows` as int 1–1000, `cwd` as absolute +
    existing + non-UNC on win32.
25. **`findShell`'s silent fallback makes `shellId` non-enforcing.** Any unknown or attacker-chosen
    id spawns the default shell and reports `ready`. The bound is real (always a discovered absolute
    path), but the paired error message can only fire when the machine has zero shells. Return
    exact-match-or-null; let the UI pick the default explicitly.
26. **The local terminal writes zero audit entries.** `recordAudit` is called only from the MCP path,
    in an app whose `docs/AI-SECURITY.md` threat-model table sells an append-only audit log. Record
    one entry per session open/close — shell label, pid, resolved path, exit code; no keystrokes, no
    output.
27. **`sanitisedEnv()` is an incomplete denylist and is untested.** Missing `NODE_REPL_EXTERNAL_MODULE`
    (same class as `NODE_OPTIONS`, not covered by it) and the rest of the `ELECTRON_*` family. Use a
    prefix strip plus an explicit `NODE_*` list. It is also the only pure export in its module with
    no test — and it cannot be tested until `tests/mocks/electron.ts` gains `getVersion`.
    *Verified good news:* ShellPilot puts no credentials, vault material or MCP token into its own
    `process.env` (the only writes are `ELECTRON_RENDERER_URL`, dev only). Add a test asserting that
    stays true.
28. **The pin is not a pin.** `npm i @lydell/node-pty@1.2.0-beta.15` writes `^1.2.0-beta.15`, which
    matches every later beta and all of 1.x. Use an exact string. Also add a Phase 0 step confirming
    `npm i --ignore-scripts` installs cleanly. *(Verified: the package has no install scripts, no
    `bin`, no `engines`, MIT, and `npm audit` reports 0 vulnerabilities.)*
29. **`AiCapability` guard passes vacuously.** `?? ''` turns "regex didn't match" into "union is
    clean", and the lazy `[\s\S]*?` stops at the first blank line — so a member added under a doc
    comment falls outside the capture. Import `AI_CAPABILITIES` and assert over it at runtime.
30. **`local:ack` with `NaN` permanently disables backpressure.** `Math.max(0, NaN)` is `NaN` and
    `NaN > FLOW_HIGH_WATER` is false forever. Add `Number.isFinite`. *(A huge number is harmless —
    it clamps to zero, and a renderer can already lift its own backpressure by not acking.)*
31. **No ownership binding between `sessionId` and `WebContents`.** `ssh.ts:641-643` has the
    identical hole and there is only one `BrowserWindow` today, so this is consistency rather than
    regression — but store `wc.id` beside the session now, before a popped-out terminal window makes
    `local:write` a cross-window write primitive into a shell.

### Non-blocking, but fix while you are there

- **The TDZ note is wrong.** `coalescer(cb)` never calls `cb` synchronously (only from `flush` on a
  `setTimeout`), so either order works. The prescribed order is fine; the stated reason is not.
- **`exitDisp` never disposes `dataDisp`** — a late chunk can emit `local:data:*` after
  `local:close:*`. Dispose the data listener first in the exit handler.
- **`normaliseWslPath` is tested but never called.** Wire it into WSL cwd translation or delete it.
- **`gitBashPath` misses per-user installs** — add `HKCU\SOFTWARE\GitForWindows`.
- **ESM→CJS interop.** Use `const m = await import(...); ptyModule = (m.default ?? m) as NodePty` and
  an explicit `typeof ptyModule.spawn !== 'function'` check, so a lexer-shape failure is
  distinguishable from a native-binding failure. *(Verified working on Node 22 today — the namespace
  exposes `spawn` directly — but the `as unknown as` cast would hide a regression.)*
- **`LocalCloseInfo` does not mirror `SshCloseInfo`** (`signal` is `number` vs `string`), and Phase 4
  defines two close-reason functions, contradicting the type's own comment.
- **Phase 7 test counts are wrong** — 8 tests, not 7, and `hardenedRuntime` already passes
  (`electron-builder.yml:130`) and is already asserted in `tests/releaseWorkflow.test.ts:143-147`.
- **Scope the conpty negation** — but note the correction below; the pattern as written here is
  wrong. Use `prebuilds/*/conpty/**`, not `prebuilds/**/conpty/**`:
  `'!**/node_modules/@lydell/node-pty-*/prebuilds/*/conpty/**'` —
  `prebuilds/` is a `prebuildify` convention, not a node-pty invention.
- **`localDisposeAll()` on the `quitAndInstall` path**, not only `before-quit`: Windows NSIS
  self-replace fails if a lingering grandchild holds a handle under the install directory.
- **Citation drift:** `tabSession`/`tabCwd` are at `app.ts:116-117` (not `:117-118`);
  `CommandPalette.tsx:55-69` (not `:54-68`); `SftpView.tsx:147-148` and `:151-164`;
  `electron-builder.yml:14-23` (not `:14-24`); `openServer` at `:492`. The pseudo-Server section
  says "eleven surfaces" then lists ten. Everything else checked out.
- **`bridgeHas` needs the `as Record<string, unknown> | undefined` cast** (see `app.ts:330`).
- **`tests/` is type-checked by nothing** — no tsconfig covers it, so the TDD sequence is not
  compiler-verified.
- **Phase 2 Step 5's manual check cannot work** — `shellDiscovery.ts` imports `electron` at top
  level, which under plain Node/tsx resolves to a path string.

---

## Decisions already taken (do not re-litigate)

| Decision | Verdict | Why |
|---|---|---|
| cmux (manaflow-ai) | **Rejected** | macOS-only Swift/AppKit, GPL-3.0 at repo root, `cmux-tui` has no published Windows binary, all SDKs are `0.0.0-bootstrap` placeholders. |
| libghostty-vt | **Rejected for v1** | Verified: zero pty/spawn/exec symbols across 30 headers, zero PTY functions in 189 WASM exports. It solves VT parsing, which xterm.js already does. |
| `@lydell/node-pty@1.2.0-beta.15` | **Chosen** | Node-API (38 `napi_` symbols, 0 V8 symbols) ⇒ no electron-rebuild / node-gyp / MSVC / CI toolchain. Prebuilds cover all four shipped slots (darwin-x64, darwin-arm64, win32-x64, linux-x64). Per-platform footprint 0.10–1.57 MB. |
| `node-pty@1.1.0` | **Rejected** | No Linux prebuild; ships `winpty-agent.exe` (AV false-positive history vs. our hard-fail Defender/ClamAV release gates); `spawn-helper` at mode 644. |
| Detach/reattach across app restart | **Out of scope for v1** | Needs a daemon. Migration note only (see *Non-goals*). |
| Local terminal over MCP | **Never** — not behind a capability, not behind ASK | See Phase 8. |

---

## File structure

**New files**

| Path | Responsibility | Est. LOC |
|---|---|---|
| `src/shared/local.ts` | Types shared by main / preload / renderer: `LocalShell`, `LocalConnectConfig`, `LocalStatus`, `LocalCloseInfo`. | ~70 |
| `src/main/services/localPty.ts` | The PTY data plane. Spawn, write, resize, close, coalescer, flow control, teardown. Mirrors `ssh.ts:563-755`. | ~230 |
| `src/main/services/shellDiscovery.ts` | Per-OS enumeration of usable shells; returns `LocalShell[]`. Pure-ish, testable off-platform. | ~270 |
| `src/renderer/src/hooks/useTerminalSession.ts` | Transport-agnostic session hook extracted from `TerminalView.tsx:206-378`. | ~200 |
| `src/renderer/src/lib/transport.ts` | `TerminalTransport` interface + the two implementations (`sshTransport`, `localTransport`). | ~110 |
| `src/renderer/src/components/terminal/LocalShellMenu.tsx` | Shell picker (the `+`-button dropdown and the palette entries). | ~130 |
| `src/renderer/src/components/panel/PaneGrid.tsx` | N-pane layout for a tab, replacing the hard-coded 2-pane block at `WorkspacePanel.tsx:71-79`. | ~120 |
| `tests/shellDiscovery.test.ts` | Per-OS discovery, WSL UTF-16LE parsing, `wslpath` `\r` trim, dash exclusion. | ~180 |
| `tests/localPtyFlowControl.test.ts` | Coalescer + backpressure, against a fake pty. | ~110 |
| `tests/localPtySmoke.test.ts` | Real `@lydell/node-pty` spawn under plain Node. Runs on every PR (ubuntu). | ~60 |
| `tests/localTerminalNotExposed.test.ts` | The MCP regression gate (Phase 8). | ~120 |
| `tests/localPackaging.test.ts` | `electron-builder.yml` shape assertions. | ~110 |
| `scripts/verify-local-pty-pack.mjs` | Post-`--dir` pack smoke check, used by the new CI job. | ~90 |

**Modified files**

| Path | Change | Est. LOC touched |
|---|---|---|
| `src/preload/index.ts:128` | Add a `local` namespace mirroring `ssh` (`:89-128`). | +50 |
| `src/main/index.ts:419`, `:844` | Register `local:*` handlers; add `localDisposeAll()` to `before-quit`. | +30 |
| `src/renderer/src/types.ts:161-169` | `Tab` → discriminated union. | +25 / -4 |
| `src/renderer/src/store/app.ts` | `openLocal`, kind-aware `sessionTitle`, `panes` slice, split → pane actions. | +130 / -45 |
| `src/renderer/src/components/panel/WorkspacePanel.tsx` | `TabPane` kind switch; viewbar gating; pane grid; `+` menu. | +90 / -55 |
| `src/renderer/src/components/terminal/TerminalView.tsx` | Consume `useTerminalSession`; accept a transport, not a `Server`. | +40 / -150 |
| `src/renderer/src/hooks/useHotkeys.ts:29-34`, `:74-79` | `new-terminal` and `splitActive` become kind-aware. | +20 / -8 |
| `src/renderer/src/lib/shortcuts.ts:50-57` | New `new-local-terminal` command. | +8 |
| `src/renderer/src/components/palette/CommandPalette.tsx:54-68` | Local-shell entries in the palette. | +20 |
| `electron-builder.yml:14-24`, `:52-56`, `:88-141` | `files` negations, `asarUnpack`, `mac.extendInfo`. | +30 |
| `.github/workflows/ci.yml:48` | New `pack` matrix job. | +45 |
| `.github/workflows/release.yml` (signature loop) | Extend the per-binary `codesign --verify` loop to the unpacked node-pty dir. | +8 |
| `package.json:dependencies` | `@lydell/node-pty` | +1 |

**LOC sanity-check against the prior ~830 new / ~290 modified estimate.** Summing the table: **~1 020 new production LOC + ~230 modified**, plus **~670 LOC of tests** which the prior figure did not appear to count. The prior estimate is light by roughly 20–25 %, concentrated in two places it under-counted: (a) `shellDiscovery.ts`, where Windows alone (cmd + PS 5.1 + pwsh 7 + Git Bash registry + MSYS2 + WSL enumeration) is ~140 LOC before tests; (b) the pane refactor, which the prior estimate treated as "reuse the existing split" but which cannot be, because the existing split hard-codes two panes and gives the second no `tabId` (`WorkspacePanel.tsx:71-79`). Budget **~1 700 LOC total**.

---

## Phase plan

Each phase is independently shippable: everything is behind `settings.localTerminalEnabled` (default `false`) until Phase 8 flips it, so `main` stays releasable after every phase.

---

### Phase 0 — Spike and de-risk (no product code)

**Purpose:** answer, on real hardware, the five questions that would each invalidate a later phase. Nothing here is merged as product code; the output is a written answer per question appended to this document under *Open questions*.

**Files:**
- Scratch only. Nothing under `src/` is modified.

- [ ] **Step 1: Install the dependency in a throwaway branch**

```bash
git switch -c spike/node-pty
npm i @lydell/node-pty@1.2.0-beta.15
ls node_modules/@lydell/
```
Expected: the meta package plus exactly one platform package for this machine (e.g. `node-pty-darwin-arm64`).

- [ ] **Step 2: Confirm Node-API, not V8**

```bash
# macOS
nm -gU node_modules/@lydell/node-pty-*/pty.node | grep -c napi_
nm -gU node_modules/@lydell/node-pty-*/pty.node | grep -c '_ZN2v8'
# Linux
nm -D --defined-only node_modules/@lydell/node-pty-*/pty.node | grep -c napi_
```
Expected: a non-zero `napi_` count and `0` for the V8 count. This is the property that makes the plain-Node smoke test in Phase 1 meaningful.

- [ ] **Step 3: Confirm `spawn-helper` exists and is executable (darwin/linux)**

```bash
find node_modules/@lydell -name 'spawn-helper' -exec stat -f '%p %N' {} \;   # macOS
file $(find node_modules/@lydell -name 'spawn-helper' | head -1)
```
Expected on **macOS**: mode `755` (not `644` — that is why `node-pty@1.1.0` was rejected) and
`Mach-O executable`. Record the exact relative path; Phase 7 asserts on it.

**ANSWERED, and the platform list here was wrong.** `spawn-helper` is **macOS-only**. It exists to
avoid `fork()` in a hardened-runtime process, where Big Sur and later charge roughly 300 ms per
spawn (microsoft/node-pty#476) — a macOS problem with a macOS fix. The Linux sibling ships
`prebuilds/linux-x64/pty.node` and nothing else, and forks directly. Do not look for it there: the
pack verifier demanded it on every non-Windows platform and failed the first 0.8.0 Linux build over
a file that is not supposed to exist.

- [ ] **Step 4: Answer the flow-control question**

```bash
node -e "console.log(Object.keys(require('@lydell/node-pty')))"
grep -rn "handleFlowControl\|flowControlPause\|flowControlResume" node_modules/@lydell/node-pty/lib/ | head
```
Expected: `handleFlowControl`, `flowControlPause`, `flowControlResume` appear in the option handling. **If they do not**, Phase 1 falls back to the alternative recorded in *Open questions* Q1 and this must be written down before Phase 1 starts.

- [ ] **Step 5: Answer the ConPTY-DLL question (Windows machine required)**

```powershell
Get-ChildItem -Recurse node_modules\@lydell | Where-Object { $_.Name -match 'conpty|OpenConsole|winpty|\.pdb$' }
node -e "const p=require('@lydell/node-pty');const t=p.spawn(process.env.ComSpec,[],{cols:80,rows:24});t.onData(d=>process.stdout.write(d));setTimeout(()=>t.kill(),2000)"
```
Then **rename the `conpty` directory away** and re-run the spawn. Expected: it still works, using the system ConPTY in `conhost.exe`.

**ANSWERED: it works.** Confirmed on `windows-latest` (CI run 33494240165) — `conpty/` deleted,
`cmd.exe` spawned and echoed through ConPTY. The exclusion is safe, and this step no longer needs
doing by hand: it is a permanent job in `ci.yml` (`Verify ConPTY works without the bundled
redistributable (Q3)`) that runs on every push and PR and fails if the directory is missing rather
than passing for having found nothing to remove.

Note the pattern that ships is `prebuilds/*/conpty/**`, not `prebuilds/**/conpty/**` — the latter
matches nothing (see R3b).

- [ ] **Step 6: Load the module inside a packaged Electron main process, on all three platforms**

Build a minimal harness (a 20-line `main.js` that `require`s the module, spawns `/bin/sh -c 'echo OK'` or `cmd /c echo OK`, and `console.error`s the bytes), run `npx electron-builder --dir`, and launch the packed binary from a terminal so stderr is visible. On macOS run it **with `hardenedRuntime: true` and `build/entitlements.mac.plist`**, because that is the only configuration that ships.

Expected on all three: `OK` on stderr. This is the single most important check in the plan — CI never launches Electron (see *Testing strategy*), so this is the only place the "Node-API loads under Electron 43 with the hardened runtime on" claim is ever tested before a release.

- [ ] **Step 7: Record answers and discard the branch**

```bash
git switch - && git branch -D spike/node-pty
```

**Done when:** every question in *Open questions* Q1–Q5 has a written yes/no answer with the command output that produced it, appended to this document. No code is merged.

**Rollback:** delete the branch. Nothing shipped.

---

### Phase 1 — Main-process PTY service

**Files:**
- Create: `src/shared/local.ts`
- Create: `src/main/services/localPty.ts`
- Create: `tests/localPtyFlowControl.test.ts`
- Create: `tests/localPtySmoke.test.ts`
- Modify: `package.json` (dependencies)

- [ ] **Step 1: Add the dependency**

```bash
npm i @lydell/node-pty@1.2.0-beta.15
npm audit
```
Expected: `npm audit` clean (the `check` job in `.github/workflows/ci.yml:23` runs it and will fail the PR otherwise).

- [ ] **Step 2: Write the shared types**

Create `src/shared/local.ts`:

```ts
// Shared local-terminal types used by main, preload and renderer. Deliberately
// a sibling of src/shared/ssh.ts rather than an extension of it: a local shell
// has no host, no port, no username and no auth, and modelling it as an SshHop
// with those fields blanked is how a local session ends up in a code path that
// tries to dial it.

export type LocalShellKind = 'posix' | 'cmd' | 'powershell' | 'pwsh' | 'gitbash' | 'msys2' | 'wsl'

export interface LocalShell {
  // Stable across restarts and across machines of the same OS, because it is
  // persisted on the tab: 'darwin-zsh', 'win32-pwsh', 'wsl:Ubuntu-24.04'.
  id: string
  label: string
  kind: LocalShellKind
  // Absolute. Never a bare name resolved from PATH — same reasoning as
  // src/main/services/vpn/binaries.ts: on Windows the PATH search is the
  // vulnerability.
  path: string
  args: string[]
  // Merged over the sanitised parent environment, never replacing it.
  env?: Record<string, string>
  // True for the one shell the OS considers the user's own.
  isDefault?: boolean
}

export interface LocalConnectConfig {
  sessionId: string
  shellId: string
  // Absent means the user's home directory.
  cwd?: string
  cols: number
  rows: number
}

export type LocalStatusPhase = 'spawning' | 'ready' | 'error'

export interface LocalStatus {
  sessionId: string
  phase: LocalStatusPhase
  message?: string
  pid?: number
  shellLabel?: string
}

// Why the shell ended. Mirrors SshCloseInfo (src/shared/ssh.ts:26-31) so the
// renderer's close-reason rendering is one function, not two.
export interface LocalCloseInfo {
  exitCode?: number
  signal?: number
}
```

- [ ] **Step 3: Write the failing flow-control test**

Create `tests/localPtyFlowControl.test.ts`:

```ts
import { describe, it, expect } from 'vitest'
import { coalescer, FLOW_HIGH_WATER, FLOW_LOW_WATER, flowWindow } from '../src/main/services/localPty'

describe('output coalescer', () => {
  it('batches everything that arrives in one tick into a single send', async () => {
    const sent: string[] = []
    const c = coalescer((payload) => sent.push(payload))
    c.push(Buffer.from('a'))
    c.push(Buffer.from('b'))
    c.push(Buffer.from('c'))
    expect(sent).toEqual([])
    await new Promise((r) => setTimeout(r, 5))
    expect(sent).toEqual(['abc'])
  })

  it('flushes what is pending when the session closes', () => {
    const sent: string[] = []
    const c = coalescer((payload) => sent.push(payload))
    c.push(Buffer.from('tail'))
    c.dispose()
    expect(sent).toEqual(['tail'])
  })
})

describe('backpressure window', () => {
  it('pauses above the high-water mark and resumes below the low-water mark', () => {
    const events: string[] = []
    const w = { pause: () => events.push('pause'), resume: () => events.push('resume') }
    const { onSent, onAck } = flowWindow(w)
    onSent(FLOW_HIGH_WATER + 1)
    expect(events).toEqual(['pause'])
    onAck(FLOW_HIGH_WATER + 1 - FLOW_LOW_WATER + 1)
    expect(events).toEqual(['pause', 'resume'])
  })
})
```

- [ ] **Step 4: Run it and watch it fail**

```bash
npx vitest run tests/localPtyFlowControl.test.ts
```
Expected: FAIL — `Cannot find module '../src/main/services/localPty'`.

- [ ] **Step 5: Write the service**

Create `src/main/services/localPty.ts`:

```ts
import { homedir } from 'node:os'
import type { WebContents } from 'electron'
import type { LocalCloseInfo, LocalConnectConfig, LocalStatus, LocalStatusPhase } from '../../shared/local'
import { findShell, sanitisedEnv } from './shellDiscovery'

// node-pty is loaded lazily, on the first connect, and never at module scope.
// A machine where the native binding will not load (an unsupported libc, a
// hardened-runtime failure we did not predict) must still get an app that
// starts and does everything else — the local terminal is the feature that
// fails, not ShellPilot.
type Pty = {
  pid: number
  write(data: string): void
  resize(cols: number, rows: number): void
  kill(signal?: string): void
  pause(): void
  resume(): void
  onData(cb: (d: string) => void): { dispose(): void }
  onExit(cb: (e: { exitCode: number; signal?: number }) => void): { dispose(): void }
}
type NodePty = { spawn(file: string, args: string[], opts: Record<string, unknown>): Pty }
let ptyModule: NodePty | null = null
let ptyLoadError: string | null = null

async function loadPty(): Promise<NodePty> {
  if (ptyModule) return ptyModule
  if (ptyLoadError) throw new Error(ptyLoadError)
  try {
    ptyModule = (await import('@lydell/node-pty')) as unknown as NodePty
    return ptyModule
  } catch (err) {
    ptyLoadError =
      `The local terminal is unavailable on this machine: the pseudo-terminal ` +
      `binding failed to load (${err instanceof Error ? err.message : String(err)}). ` +
      `SSH sessions are unaffected.`
    throw new Error(ptyLoadError)
  }
}

// The pause/resume tokens node-pty intercepts. NOT '\x13'/'\x11'.
//
// With handleFlowControl on, node-pty compares each written chunk against
// these strings and, on a match, pauses/resumes its read loop instead of
// forwarding the bytes. A renderer keystroke arrives as its own write with
// data exactly '\x13' when the user presses Ctrl+S — so binding the token to
// XOFF would silently swallow Ctrl+S in vim, in emacs, and in every program
// that binds it. An OSC sequence nobody can type has no such collision.
const FLOW_PAUSE = '\u001b]777;shellpilot-pause\u0007'
const FLOW_RESUME = '\u001b]777;shellpilot-resume\u0007'

// Bytes in flight to the renderer before we stop reading, and the level we
// wait to fall back to before reading again. 512 KB is roughly a screenful of
// `yes` at 60 Hz; below ~64 KB the resume happens often enough that a fast
// `cat` of a large file never stalls visibly.
export const FLOW_HIGH_WATER = 512 * 1024
export const FLOW_LOW_WATER = 64 * 1024

export function flowWindow(w: { pause: () => void; resume: () => void }): {
  onSent: (bytes: number) => void
  onAck: (bytes: number) => void
} {
  let outstanding = 0
  let paused = false
  return {
    onSent: (bytes) => {
      outstanding += bytes
      if (!paused && outstanding > FLOW_HIGH_WATER) {
        paused = true
        w.pause()
      }
    },
    onAck: (bytes) => {
      outstanding = Math.max(0, outstanding - bytes)
      if (paused && outstanding < FLOW_LOW_WATER) {
        paused = false
        w.resume()
      }
    }
  }
}

// Byte-for-byte the same shape as the SSH coalescer at
// src/main/services/ssh.ts:602-617, and for the same reason: `cat` on a large
// file arrives as hundreds of small chunks, and one IPC message each floods
// the renderer and stalls input. A single keystroke echo still goes out
// immediately — the timer only batches what arrives inside one tick.
export function coalescer(send: (payload: string) => void): {
  push: (d: Buffer | string) => void
  dispose: () => void
} {
  let pending: string[] = []
  let flushTimer: ReturnType<typeof setTimeout> | null = null
  const flush = (): void => {
    flushTimer = null
    if (pending.length === 0) return
    const payload = pending.length === 1 ? pending[0] : pending.join('')
    pending = []
    send(payload)
  }
  return {
    push: (d) => {
      pending.push(typeof d === 'string' ? d : d.toString('utf8'))
      if (!flushTimer) flushTimer = setTimeout(flush, 0)
    },
    dispose: () => {
      if (flushTimer) clearTimeout(flushTimer)
      flush()
    }
  }
}

interface Session {
  // null while a connect is in flight — the id is claimed before the first
  // await so a concurrent close is observable. See localConnect.
  pty: Pty | null
  disposers: (() => void)[]
  ack: (bytes: number) => void
}
const sessions = new Map<string, Session>()

function send(wc: WebContents, channel: string, ...args: unknown[]): void {
  if (!wc.isDestroyed()) wc.send(channel, ...args)
}
function status(wc: WebContents, sessionId: string, phase: LocalStatusPhase, extra: Partial<LocalStatus> = {}): void {
  send(wc, `local:status:${sessionId}`, { sessionId, phase, ...extra } satisfies LocalStatus)
}

export async function localConnect(wc: WebContents, cfg: LocalConnectConfig): Promise<void> {
  const { sessionId } = cfg
  status(wc, sessionId, 'spawning')
  // Claim the id before the first await, so a localClose() arriving mid-connect
  // has something to delete and the re-check after spawn() can see that it did.
  sessions.set(sessionId, { pty: null, ack: () => {}, disposers: [] })
  try {
    const shell = await findShell(cfg.shellId)
    if (!shell) throw new Error(`No shell is configured under the id "${cfg.shellId}".`)
    const pty = (await loadPty()).spawn(shell.path, shell.args, {
      name: 'xterm-256color',
      cols: cfg.cols,
      rows: cfg.rows,
      cwd: cfg.cwd ?? homedir(),
      env: { ...sanitisedEnv(), ...(shell.env ?? {}) },
      useConpty: true,
      // See Phase 0 Q3. The bundled redistributable ConPTY is deliberately not
      // shipped; the one in conhost.exe is used instead.
      useConptyDll: false,
      handleFlowControl: true,
      flowControlPause: FLOW_PAUSE,
      flowControlResume: FLOW_RESUME
    })

    // The window is declared first only because the coalescer's callback reads
    // it. (An earlier draft claimed this ordering avoided a TDZ error — it does
    // not: coalescer(cb) never invokes cb synchronously, it only fires from
    // flush() on a setTimeout. Either order works.)
    const window_ = flowWindow({
      pause: () => pty.write(FLOW_PAUSE),
      resume: () => pty.write(FLOW_RESUME)
    })
    const out = coalescer((payload) => {
      // UTF-16 code units, NOT Buffer.byteLength.
      //
      // The renderer acks with `d.length` on the string it received, so both
      // sides of the window must count the same unit. Counting bytes here and
      // code units there accrues a permanent deficit on every multi-byte
      // character — onAck's Math.max(0, …) clamps over-acks but cannot repay an
      // under-ack — and once `outstanding` passes FLOW_HIGH_WATER the pty is
      // paused forever. That freezes the session mid-output on htop, on vim
      // with a Unicode statusline, on fzf, on any Powerlevel10k prompt.
      window_.onSent(payload.length)
      send(wc, `local:data:${sessionId}`, payload)
    })

    const dataDisp = pty.onData((d) => out.push(d))
    const exitDisp = pty.onExit((e) => {
      const exit: LocalCloseInfo = { exitCode: e.exitCode, signal: e.signal }
      // Detach the data listener BEFORE flushing: a chunk arriving after
      // out.dispose() would re-arm the flush timer and emit local:data:* after
      // local:close:*, into a terminal the renderer has already marked dead.
      dataDisp.dispose()
      out.dispose()
      send(wc, `local:close:${sessionId}`, exit)
      sessions.delete(sessionId)
    })

    // Re-check the placeholder. localClose() may have run during either await
    // above — ordinary on a fast open-then-close, and guaranteed in dev under
    // React StrictMode, where the session effect mounts, cleans up and remounts
    // while the first (slow, native) loadPty() is still resolving. ssh.ts:565
    // and :572-577 do exactly this; dropping it orphans a live shell that
    // nothing but localDisposeAll() at quit will ever reap.
    if (!sessions.has(sessionId)) {
      dataDisp.dispose()
      exitDisp.dispose()
      out.dispose()
      try {
        pty.kill()
      } catch {
        /* already gone */
      }
      return
    }

    sessions.set(sessionId, {
      pty,
      ack: window_.onAck,
      disposers: [() => dataDisp.dispose(), () => exitDisp.dispose(), () => out.dispose()]
    })
    status(wc, sessionId, 'ready', { pid: pty.pid, shellLabel: shell.label })
  } catch (err) {
    status(wc, sessionId, 'error', { message: err instanceof Error ? err.message : String(err) })
  }
}

export function localWrite(sessionId: string, data: string): void {
  // A renderer that could write the sentinel could stall its own session for
  // good, so the tokens are refused on the way in. Nothing legitimate sends
  // them: they exist only for this module's own pause()/resume().
  if (data === FLOW_PAUSE || data === FLOW_RESUME) return
  // `?.pty?.` — pty is null while a connect is still in flight.
  sessions.get(sessionId)?.pty?.write(data)
}

export function localAck(sessionId: string, bytes: number): void {
  // Reject non-finite values. Math.max(0, NaN) is NaN, and NaN > FLOW_HIGH_WATER
  // is false forever — so a single ack(undefined) from a buggy or hostile
  // renderer permanently disables the pause path and restores the unbounded
  // memory growth the flow window exists to prevent. An over-large number is
  // harmless: it clamps to zero, and a renderer can already lift its own
  // backpressure by simply never acking.
  if (!Number.isFinite(bytes)) return
  sessions.get(sessionId)?.ack(bytes)
}

export function localResize(sessionId: string, cols: number, rows: number): void {
  try {
    sessions.get(sessionId)?.pty?.resize(Math.max(1, cols), Math.max(1, rows))
  } catch {
    /* a pty that exited between the resize and this call is not an error */
  }
}

export function localClose(sessionId: string): void {
  const s = sessions.get(sessionId)
  if (!s) return
  // Deleting the entry is what an in-flight localConnect observes when it
  // re-checks after spawn(); it then kills the pty it just created and returns.
  sessions.delete(sessionId)
  for (const d of s.disposers) d()
  try {
    s.pty?.kill()
  } catch {
    /* already gone */
  }
}

export function localDisposeAll(): void {
  for (const id of [...sessions.keys()]) localClose(id)
}
```

- [ ] **Step 6: Run the flow-control test**

```bash
npx vitest run tests/localPtyFlowControl.test.ts
```
Expected: PASS, 3 tests.

- [ ] **Step 7: Write the real-PTY smoke test**

Create `tests/localPtySmoke.test.ts`:

```ts
import { describe, it, expect } from 'vitest'

// This runs under plain Node, not Electron, and that is the point. The binding
// is Node-API, so the exact same prebuilt .node loads in Node 20 and in
// Electron 43 — which is what makes a CI job that never launches Electron
// worth anything at all. node-pty@1.1.0 is NAN/V8 and could not be tested this
// way; see the plan's decision table.
describe('@lydell/node-pty spawns a real shell', () => {
  it.skipIf(process.platform === 'win32')('echoes back through a pty', async () => {
    const pty = await import('@lydell/node-pty')
    const term = pty.spawn('/bin/sh', ['-c', 'echo SHELLPILOT_PTY_OK'], {
      name: 'xterm-256color',
      cols: 80,
      rows: 24,
      cwd: process.cwd(),
      env: { ...process.env, TERM: 'xterm-256color' } as Record<string, string>
    })
    const seen = await new Promise<string>((resolve) => {
      let buf = ''
      term.onData((d) => {
        buf += d
        if (buf.includes('SHELLPILOT_PTY_OK')) resolve(buf)
      })
      setTimeout(() => resolve(buf), 8000)
    })
    term.kill()
    expect(seen).toContain('SHELLPILOT_PTY_OK')
  })

  it.skipIf(process.platform !== 'win32')('echoes back through ConPTY', async () => {
    const pty = await import('@lydell/node-pty')
    const term = pty.spawn(process.env.ComSpec ?? 'cmd.exe', ['/c', 'echo SHELLPILOT_PTY_OK'], {
      name: 'xterm-256color',
      cols: 80,
      rows: 24,
      cwd: process.cwd(),
      env: process.env as Record<string, string>
    })
    const seen = await new Promise<string>((resolve) => {
      let buf = ''
      term.onData((d) => {
        buf += d
        if (buf.includes('SHELLPILOT_PTY_OK')) resolve(buf)
      })
      setTimeout(() => resolve(buf), 8000)
    })
    term.kill()
    expect(seen).toContain('SHELLPILOT_PTY_OK')
  })
})
```

- [ ] **Step 8: Run the whole suite**

```bash
npm run typecheck && npm run test
```
Expected: PASS. The smoke test proves the module loads and `spawn-helper` execs on the ubuntu runner on every PR.

- [ ] **Step 9: Commit**

```bash
git add package.json package-lock.json src/shared/local.ts src/main/services/localPty.ts tests/localPtyFlowControl.test.ts tests/localPtySmoke.test.ts
git commit -m "feat(local): main-process PTY service with coalescing and backpressure"
```

**Done when:** `npm run test` passes on ubuntu including a real PTY spawn; `localPty.ts` is importable but not yet reachable from any IPC channel; the app builds and behaves identically to before.

**Rollback:** revert the commit. Nothing outside `localPty.ts` referenced it.

---

### Phase 2 — Shell discovery

Deliberately before IPC, so Phase 3 has something real to expose.

**Files:**
- Create: `src/main/services/shellDiscovery.ts`
- Create: `tests/shellDiscovery.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `tests/shellDiscovery.test.ts`:

```ts
import { describe, it, expect } from 'vitest'
import { parseWslDistros, parseDsclShell, normaliseWslPath, isInteractiveShell } from '../src/main/services/shellDiscovery'

describe('WSL distro enumeration', () => {
  it('decodes `wsl -l -q` output as UTF-16LE with a BOM', () => {
    // wsl.exe writes UTF-16LE. Read as utf8 the names come back as
    // "U\0b\0u\0n\0t\0u\0" — visibly wrong in a dropdown, and unusable as a
    // -d argument. This is the single most common WSL integration bug.
    const buf = Buffer.from('\ufeffUbuntu-24.04\r\nDebian\r\n', 'utf16le')
    expect(parseWslDistros(buf)).toEqual(['Ubuntu-24.04', 'Debian'])
  })

  it('drops blank lines and trailing whitespace', () => {
    const buf = Buffer.from('Ubuntu \r\n\r\n  \r\nDebian\r\n', 'utf16le')
    expect(parseWslDistros(buf)).toEqual(['Ubuntu', 'Debian'])
  })

  it('returns nothing when WSL reports no distributions', () => {
    expect(parseWslDistros(Buffer.from('', 'utf16le'))).toEqual([])
  })
})

describe('wslpath output', () => {
  it('trims the carriage return wslpath leaves behind', () => {
    // `wslpath -a -u 'C:\Users\me'` returns "/mnt/c/Users/me\r". Passing that
    // straight to `cd` fails with "No such file or directory" and the shell
    // silently starts in $HOME instead.
    expect(normaliseWslPath('/mnt/c/Users/me\r\n')).toBe('/mnt/c/Users/me')
    expect(normaliseWslPath('/mnt/c/Users/me\r')).toBe('/mnt/c/Users/me')
    expect(normaliseWslPath('/mnt/c/Users/me')).toBe('/mnt/c/Users/me')
  })
})

describe('dscl fallback on macOS', () => {
  it('reads the shell out of a dscl record', () => {
    expect(parseDsclShell('UserShell: /bin/zsh\n')).toBe('/bin/zsh')
  })
  it('returns null for a record with no UserShell', () => {
    expect(parseDsclShell('No such key: UserShell\n')).toBeNull()
  })
})

describe('interactive shell suitability', () => {
  it('rejects dash, which has no line editing or history', () => {
    // /bin/sh is dash on Debian and Ubuntu. Offering it as "your shell" gets
    // reported as a broken terminal: arrow keys print ^[[A and there is no
    // history at all.
    expect(isInteractiveShell('/bin/dash')).toBe(false)
    expect(isInteractiveShell('/usr/bin/dash')).toBe(false)
  })
  it('rejects nologin and false', () => {
    expect(isInteractiveShell('/usr/sbin/nologin')).toBe(false)
    expect(isInteractiveShell('/bin/false')).toBe(false)
  })
  it('accepts the real interactive shells', () => {
    for (const s of ['/bin/zsh', '/bin/bash', '/usr/bin/fish', '/opt/homebrew/bin/nu']) {
      expect(isInteractiveShell(s)).toBe(true)
    }
  })
})
```

- [ ] **Step 2: Run and watch it fail**

```bash
npx vitest run tests/shellDiscovery.test.ts
```
Expected: FAIL — module not found.

- [ ] **Step 3: Write the discovery module**

Create `src/main/services/shellDiscovery.ts`. The pure helpers first (they are what the tests above drive):

```ts
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { existsSync } from 'node:fs'
import { basename, join } from 'node:path'
import { homedir, userInfo } from 'node:os'
import { app } from 'electron'
import type { LocalShell } from '../../shared/local'

const run = promisify(execFile)

// `wsl.exe -l -q` writes UTF-16LE, with a BOM. Decoding it as UTF-8 yields
// names interleaved with NULs, which are useless as a `-d` argument.
export function parseWslDistros(buf: Buffer): string[] {
  return buf
    .toString('utf16le')
    .replace(/^\ufeff/, '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
}

// wslpath's output carries the CR of a Windows line ending. `cd $'…\r'` fails.
export function normaliseWslPath(out: string): string {
  return out.replace(/[\r\n]+$/, '')
}

export function parseDsclShell(out: string): string | null {
  return /^UserShell:\s*(\S+)\s*$/m.exec(out)?.[1] ?? null
}

// Shells that must never be offered as an interactive session.
const NON_INTERACTIVE = new Set(['dash', 'nologin', 'false', 'sync', 'git-shell'])
export function isInteractiveShell(path: string): boolean {
  return path.length > 0 && !NON_INTERACTIVE.has(basename(path).replace(/\.exe$/i, ''))
}
```

Then the environment. This is where the macOS PATH problem is solved:

```ts
// The environment every local shell starts from.
//
// Two jobs. First, strip what Electron put there for its own child processes:
// ELECTRON_RUN_AS_NODE turns any Electron binary the user runs into a bare
// Node, and NODE_OPTIONS is inherited into every node the user starts. Second,
// declare what a terminal is, so programs stop guessing.
export function sanitisedEnv(): Record<string, string> {
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue
    if (k === 'ELECTRON_RUN_AS_NODE' || k === 'NODE_OPTIONS' || k === 'ELECTRON_NO_ATTACH_CONSOLE') continue
    env[k] = v
  }
  env.TERM = 'xterm-256color'
  env.COLORTERM = 'truecolor'
  env.TERM_PROGRAM = 'ShellPilot'
  env.TERM_PROGRAM_VERSION = app.getVersion()
  // An AppImage started from a desktop launcher can have no locale at all,
  // which makes every UTF-8 box-drawing character in the shell prompt render
  // as mojibake. Set a default; never override one the user has.
  if (!env.LANG && !env.LC_ALL) env.LANG = 'en_US.UTF-8'
  return env
}
```

macOS:

```ts
// macOS. A login shell is mandatory, not a preference.
//
// A GUI Electron app is launched by launchd, and launchd's PATH is the minimal
// /usr/bin:/bin:/usr/sbin:/sbin. Everything a developer actually uses —
// /opt/homebrew/bin, /usr/local/bin, whatever /etc/paths.d contributes — is
// assembled by path_helper, which runs from /etc/zprofile and /etc/profile.
// Those are read by a LOGIN shell only. Without -l the user gets a terminal
// where `brew`, `node`, `git` from Xcode-alternatives and their whole toolchain
// are simply not found, and it looks like ShellPilot broke their machine.
// Terminal.app and iTerm2 both start login shells for exactly this reason.
async function discoverDarwin(): Promise<LocalShell[]> {
  const shells: LocalShell[] = []
  const candidates: string[] = []

  const fromEnv = process.env.SHELL
  if (fromEnv && isInteractiveShell(fromEnv) && existsSync(fromEnv)) candidates.push(fromEnv)

  // $SHELL is absent when the app was launched from Finder rather than from a
  // terminal, which is the normal case. Directory Services knows the answer.
  if (candidates.length === 0) {
    try {
      const { stdout } = await run('/usr/bin/dscl', ['.', '-read', `/Users/${userInfo().username}`, 'UserShell'], {
        timeout: 4000
      })
      const shell = parseDsclShell(stdout)
      if (shell && isInteractiveShell(shell) && existsSync(shell)) candidates.push(shell)
    } catch {
      /* fall through to the hard default */
    }
  }

  if (candidates.length === 0) candidates.push('/bin/zsh')

  for (const path of candidates) {
    const name = basename(path)
    shells.push({
      id: `darwin-${name}`,
      label: name === 'zsh' ? 'zsh (default)' : name,
      kind: 'posix',
      path,
      args: ['-l'],
      isDefault: shells.length === 0
    })
  }

  // Offer the other system shell too, so a zsh user can still reach bash.
  for (const alt of ['/bin/bash', '/bin/zsh']) {
    if (!shells.some((s) => s.path === alt) && existsSync(alt)) {
      shells.push({ id: `darwin-${basename(alt)}`, label: basename(alt), kind: 'posix', path: alt, args: ['-l'] })
    }
  }
  return shells
}
```

Linux:

```ts
// Linux. $SHELL first, then the passwd entry, then bash, then sh.
//
// -i rather than -l for bash, and this asymmetry with macOS is deliberate: a
// bash LOGIN shell reads ~/.bash_profile and deliberately does NOT read
// ~/.bashrc, which is where essentially every Linux user's aliases, prompt and
// completion live. A Linux desktop session already inherits ~/.profile through
// the display manager, so there is no PATH problem to solve here — the macOS
// launchd problem simply does not exist. zsh and fish read their rc file in
// both modes, so they get -l.
async function discoverLinux(): Promise<LocalShell[]> {
  const shells: LocalShell[] = []
  const seen = new Set<string>()
  const push = (path: string, isDefault = false): void => {
    if (seen.has(path) || !existsSync(path) || !isInteractiveShell(path)) return
    seen.add(path)
    const name = basename(path)
    shells.push({
      id: `linux-${name}`,
      label: isDefault ? `${name} (default)` : name,
      kind: 'posix',
      path,
      args: name === 'bash' ? ['-i'] : ['-l'],
      isDefault
    })
  }

  const preferred = process.env.SHELL || userInfo().shell || ''
  // /bin/sh is dash on Debian and Ubuntu; isInteractiveShell rejects it and
  // this falls through to bash, which is what the user actually wants.
  push(preferred, true)
  if (shells.length === 0) push('/bin/bash', true)
  if (shells.length === 0) push('/bin/sh', true)
  for (const alt of ['/bin/bash', '/usr/bin/zsh', '/usr/bin/fish']) push(alt)
  return shells
}
```

Windows — the longest of the three:

```ts
// Windows. Absolute paths only, never a PATH search: the same rule
// src/main/services/vpn/binaries.ts enforces for engine binaries, for the same
// reason. A writable directory earlier on PATH than System32 is a local
// privilege escalation, and "pwsh" is a name an attacker can plant.
async function discoverWin32(): Promise<LocalShell[]> {
  const shells: LocalShell[] = []
  const sysRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const pf = process.env.ProgramFiles ?? 'C:\\Program Files'
  const localAppData = process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local')

  const cmd = process.env.ComSpec ?? join(sysRoot, 'System32', 'cmd.exe')
  if (existsSync(cmd)) {
    shells.push({ id: 'win32-cmd', label: 'Command Prompt', kind: 'cmd', path: cmd, args: [], isDefault: false })
  }

  const ps51 = join(sysRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  if (existsSync(ps51)) {
    shells.push({
      id: 'win32-powershell',
      label: 'Windows PowerShell',
      kind: 'powershell',
      path: ps51,
      // -NoLogo suppresses the banner; -ExecutionPolicy is deliberately NOT
      // set — changing a machine's script policy from a terminal launcher is
      // not ours to do.
      args: ['-NoLogo']
    })
  }

  for (const pwsh of [join(pf, 'PowerShell', '7', 'pwsh.exe'), join(localAppData, 'Microsoft', 'WindowsApps', 'pwsh.exe')]) {
    if (existsSync(pwsh)) {
      shells.push({ id: 'win32-pwsh', label: 'PowerShell 7', kind: 'pwsh', path: pwsh, args: ['-NoLogo'], isDefault: true })
      break
    }
  }
  if (!shells.some((s) => s.isDefault)) {
    const fallback = shells.find((s) => s.id === 'win32-powershell') ?? shells[0]
    if (fallback) fallback.isDefault = true
  }

  const git = await gitBashPath()
  if (git) {
    shells.push({
      id: 'win32-gitbash',
      label: 'Git Bash',
      kind: 'gitbash',
      path: git,
      // --login runs /etc/profile, which is what puts Git's own bin on PATH.
      // -i is what makes it read ~/.bashrc.
      args: ['--login', '-i']
    })
  }

  for (const root of ['C:\\msys64', 'C:\\msys32']) {
    const bash = join(root, 'usr', 'bin', 'bash.exe')
    if (!existsSync(bash)) continue
    shells.push({
      id: 'win32-msys2',
      label: 'MSYS2 UCRT64',
      kind: 'msys2',
      path: bash,
      args: ['-l', '-i'],
      // MSYSTEM selects the toolchain (UCRT64 / MINGW64 / MSYS); without it
      // the shell starts in MSYS mode and the mingw compilers are not on PATH.
      // CHERE_INVOKING keeps the shell in the directory it was started in —
      // without it /etc/profile cds to $HOME and the tab's cwd is discarded.
      env: { MSYSTEM: 'UCRT64', CHERE_INVOKING: '1' }
    })
    break
  }

  for (const distro of await wslDistros()) {
    shells.push({
      id: `wsl:${distro}`,
      label: `WSL · ${distro}`,
      kind: 'wsl',
      path: join(sysRoot, 'System32', 'wsl.exe'),
      args: ['-d', distro]
    })
  }
  return shells
}

// HKLM\SOFTWARE\GitForWindows\InstallPath is what Git for Windows writes on
// install; the WOW6432Node mirror covers a 32-bit Git on a 64-bit machine.
// `reg query` rather than a registry npm package: no new native dependency for
// one lookup, and reg.exe is in System32 on every Windows since 2000.
async function gitBashPath(): Promise<string | null> {
  const keys = ['HKLM\\SOFTWARE\\GitForWindows', 'HKLM\\SOFTWARE\\WOW6432Node\\GitForWindows']
  for (const key of keys) {
    try {
      const { stdout } = await run(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'reg.exe'), ['query', key, '/v', 'InstallPath'], { timeout: 4000 })
      const install = /InstallPath\s+REG_SZ\s+(.+?)\s*$/m.exec(stdout)?.[1]
      if (!install) continue
      const bash = join(install, 'bin', 'bash.exe')
      if (existsSync(bash)) return bash
    } catch {
      /* key absent: Git is not installed this way */
    }
  }
  return null
}

async function wslDistros(): Promise<string[]> {
  try {
    const { stdout } = await run(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'wsl.exe'), ['-l', '-q'], {
      timeout: 6000,
      // Buffer, not a string: the output is UTF-16LE and a utf8 decode here
      // destroys it before parseWslDistros can see it.
      encoding: 'buffer'
    })
    return parseWslDistros(stdout as unknown as Buffer)
  } catch {
    return []
  }
}
```

And the cached public surface:

```ts
// Discovery shells out (dscl, reg, wsl) and the answer does not change while
// the app runs, so it is computed once. `refresh` exists for the case that
// does change it: the user installing WSL or Git while ShellPilot is open.
let cache: Promise<LocalShell[]> | null = null

export function listShells(refresh = false): Promise<LocalShell[]> {
  if (refresh) cache = null
  if (!cache) {
    cache =
      process.platform === 'darwin'
        ? discoverDarwin()
        : process.platform === 'win32'
          ? discoverWin32()
          : discoverLinux()
    cache = cache.catch(() => [])
  }
  return cache
}

export async function findShell(id: string): Promise<LocalShell | null> {
  const shells = await listShells()
  return shells.find((s) => s.id === id) ?? shells.find((s) => s.isDefault) ?? shells[0] ?? null
}
```

- [ ] **Step 4: Run the tests**

```bash
npx vitest run tests/shellDiscovery.test.ts
```
Expected: PASS, 9 tests.

- [ ] **Step 5: Manually verify on this machine**

```bash
npx tsx -e "import('./src/main/services/shellDiscovery.ts').then(m=>m.listShells()).then(console.log)"
```
(If `tsx` is not available, add a temporary `console.log` behind the `local:shells` handler in Phase 3 instead and check the dev console.) Expected on macOS: at least `zsh (default)` with `args: ['-l']`.

- [ ] **Step 6: Commit**

```bash
git add src/main/services/shellDiscovery.ts tests/shellDiscovery.test.ts
git commit -m "feat(local): per-OS shell discovery with WSL, Git Bash and MSYS2"
```

**Done when:** `listShells()` returns a sensible list on each of the three platforms, verified by hand; the pure parsers are covered by tests that run on ubuntu.

**Rollback:** revert. `localPty.ts` imports it, so revert both together, or stub `findShell` to return `/bin/sh`.

---

### Phase 3 — IPC and preload

**Files:**
- Modify: `src/preload/index.ts:128` (after the `ssh` namespace, `:89-128`)
- Modify: `src/main/index.ts:419` (after the `ssh` handlers, `:411-419`) and `:844`

- [ ] **Step 1: Add the preload namespace**

In `src/preload/index.ts`, after the `ssh` block closes at line 128, insert:

```ts
  // Mirrors `ssh` above, channel for channel. The two are separate namespaces
  // rather than one with a `kind` because they take different configs, and a
  // union that the renderer has to narrow at every call site is how a local
  // session ends up in a code path that expects a host.
  local: {
    shells: (refresh?: boolean): Promise<LocalShell[]> => ipcRenderer.invoke('local:shells', refresh),
    connect: (cfg: LocalConnectConfig): Promise<void> => ipcRenderer.invoke('local:connect', cfg),
    write: (id: string, data: string): void => ipcRenderer.send('local:write', id, data),
    // Tells main how many bytes the terminal has actually parsed, which is
    // what lets it stop reading the pty when the renderer falls behind.
    ack: (id: string, bytes: number): void => ipcRenderer.send('local:ack', id, bytes),
    resize: (id: string, cols: number, rows: number): void =>
      ipcRenderer.send('local:resize', id, cols, rows),
    close: (id: string): void => ipcRenderer.send('local:close', id),
    onData: (id: string, cb: (data: string) => void): (() => void) => {
      const ch = `local:data:${id}`
      const h = (_e: IpcRendererEvent, d: string): void => cb(d)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    },
    onStatus: (id: string, cb: (s: LocalStatus) => void): (() => void) => {
      const ch = `local:status:${id}`
      const h = (_e: IpcRendererEvent, s: LocalStatus): void => cb(s)
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    },
    onClose: (id: string, cb: (info: LocalCloseInfo) => void): (() => void) => {
      const ch = `local:close:${id}`
      const h = (_e: IpcRendererEvent, info: LocalCloseInfo): void => cb(info ?? {})
      ipcRenderer.on(ch, h)
      return () => ipcRenderer.removeListener(ch, h)
    }
  },
```

And add to the type imports at the top of the file:

```ts
import type { LocalCloseInfo, LocalConnectConfig, LocalShell, LocalStatus } from '../shared/local'
```

- [ ] **Step 2: Register the main handlers**

In `src/main/index.ts`, immediately after line 419 (`ipcMain.on('ssh:close', …)`), insert:

```ts
// ---- Local terminal ----
//
// Deliberately NOT reachable from the MCP bridge or the CLI. There is no
// capability for it, no ASK path, and no tool. tests/localTerminalNotExposed
// .test.ts is what keeps that true.
ipcMain.handle('local:shells', (_e, refresh?: boolean) => listShells(refresh === true))
ipcMain.handle('local:connect', (e, cfg: LocalConnectConfig) => localConnect(e.sender, cfg))
ipcMain.on('local:write', (_e, id: string, data: string) => localWrite(id, data))
ipcMain.on('local:ack', (_e, id: string, bytes: number) => localAck(id, bytes))
ipcMain.on('local:resize', (_e, id: string, cols: number, rows: number) => localResize(id, cols, rows))
ipcMain.on('local:close', (_e, id: string) => localClose(id))
```

Add the imports beside the `./services/ssh` import block at `src/main/index.ts:8-18`:

```ts
import { localConnect, localWrite, localAck, localResize, localClose, localDisposeAll } from './services/localPty'
import { listShells } from './services/shellDiscovery'
import type { LocalConnectConfig } from '../shared/local'
```

- [ ] **Step 3: Add teardown**

In `src/main/index.ts`, in the `before-quit` handler, add `localDisposeAll()` immediately after `sshDisposeAll()` at line 844:

```ts
  sshDisposeAll()
  localDisposeAll()
  sftpDisposeAll()
```

The ordering comment at `:822-825` ("every consumer dies before the transport it was riding") still holds: a local pty rides nothing, so it goes with the other consumers.

- [ ] **Step 4: Typecheck**

```bash
npm run typecheck
```
Expected: PASS. `tsconfig.node.json:17` covers both `src/main/**` and `src/preload/**`, so a mismatch between the handler signature and the preload call is caught here.

- [ ] **Step 5: Manual smoke through the dev console**

```bash
npm run dev
```
In the renderer devtools console:

```js
await window.shellpilot.local.shells()
const id = 'smoke-1'
window.shellpilot.local.onData(id, d => console.log(JSON.stringify(d)))
await window.shellpilot.local.connect({ sessionId: id, shellId: (await window.shellpilot.local.shells())[0].id, cols: 80, rows: 24 })
window.shellpilot.local.write(id, 'echo hello\r')
```
Expected: a shell prompt then `hello` in the console. On macOS, also run `window.shellpilot.local.write(id, 'echo $PATH\r')` and confirm `/opt/homebrew/bin` (or `/usr/local/bin`) is present — that is the login-shell requirement paying off.

- [ ] **Step 6: Commit**

```bash
git add src/preload/index.ts src/main/index.ts
git commit -m "feat(local): local:* IPC channels and preload namespace"
```

**Done when:** a local shell can be driven end-to-end from the devtools console; nothing in the UI has changed.

**Rollback:** revert. The channels simply stop existing; `bridgeHas` guards in the renderer are not yet needed because nothing in the renderer calls them.

---

### Phase 4 — Transport-agnostic renderer hook

**Files:**
- Create: `src/renderer/src/lib/transport.ts`
- Create: `src/renderer/src/hooks/useTerminalSession.ts`
- Modify: `src/renderer/src/components/terminal/TerminalView.tsx:206-378`, `:466-539`

The existing `useRealSession` (`TerminalView.tsx:206-378`) already has the two properties this phase needs and must preserve: the xterm instance outlives the session (two separate effects, `:243-282` and `:286-357`), and reconnect is a `generation` bump (`:238`, `:372-375`) that re-runs the same code path as the first connect. Keep both. What changes is that both effects key on a `transportKey` string rather than `server.id`.

- [ ] **Step 1: Define the transport**

Create `src/renderer/src/lib/transport.ts`:

```ts
import type { SshCloseInfo } from '../../../shared/ssh'
import type { LocalCloseInfo, LocalShell } from '../../../shared/local'
import type { Server } from '../types'
import { sshHopsFor } from './ssh'
import { withVaultUnlock } from './withVaultUnlock'

// Everything a terminal needs to run a session, with no knowledge of whether
// the bytes come from a socket or a pty. `useTerminalSession` talks only to
// this; TerminalView chooses which implementation to hand it.
export interface TerminalTransport {
  // Identity of the thing being connected to. Both effects in
  // useTerminalSession key on this, so it must be stable for the life of a
  // pane and different for different targets.
  key: string
  // Shown in the connecting banner and the dead-session overlay.
  title: string
  subtitle: string
  connect(sessionId: string, cols: number, rows: number): Promise<void>
  write(sessionId: string, data: string): void
  resize(sessionId: string, cols: number, rows: number): void
  close(sessionId: string): void
  // Called once per chunk after xterm has parsed it. SSH ignores it; local
  // uses it to drive backpressure.
  ack?(sessionId: string, bytes: number): void
  onData(sessionId: string, cb: (d: string) => void): () => void
  // A single normalised status callback so the hook does not switch on kind.
  onStatus(sessionId: string, cb: (s: { phase: 'progress' | 'ready' | 'error'; line?: string; message?: string }) => void): () => void
  onClose(sessionId: string, cb: (reason: string) => void): () => void
  // Only SSH has one; local sessions do not touch Server.status.
  onLifecycle?(phase: 'connecting' | 'online' | 'offline'): void
}

function sshCloseReason(info: SshCloseInfo): string {
  if (info.signal) {
    return info.signal === 'HUP' ? 'closed by server (SIGHUP — often an idle timeout)' : `signal ${info.signal}`
  }
  if (info.code === 0) return 'shell exited'
  if (typeof info.code === 'number') return `shell exited with ${info.code}`
  return ''
}

function localCloseReason(info: LocalCloseInfo): string {
  if (info.signal) return `killed by signal ${info.signal}`
  if (info.exitCode === 0) return 'shell exited'
  if (typeof info.exitCode === 'number') return `shell exited with ${info.exitCode}`
  return ''
}

export function sshTransport(server: Server, setServerStatus: (id: string, s: Server['status']) => void): TerminalTransport {
  const api = () => window.shellpilot?.ssh
  return {
    key: `ssh:${server.id}`,
    title: server.name,
    subtitle: `${server.username}@${server.host}:${server.port}`,
    connect: (sessionId, cols, rows) =>
      withVaultUnlock(`Connecting to ${server.name}`, () =>
        Promise.resolve(
          api()?.connect({
            sessionId,
            serverId: server.id,
            host: server.host,
            port: server.port,
            username: server.username,
            auth: server.auth === 'password' || server.auth === 'agent' ? server.auth : 'key',
            cols,
            rows,
            hops: sshHopsFor(server)
          })
        )
      ),
    write: (id, d) => api()?.write(id, d),
    resize: (id, c, r) => api()?.resize(id, c, r),
    close: (id) => api()?.close(id),
    onData: (id, cb) => api()?.onData(id, cb) ?? (() => {}),
    onStatus: (id, cb) =>
      api()?.onStatus(id, (s) => {
        if (s.phase === 'hop') cb({ phase: 'progress', line: `\x1b[90m↪ hop ${(s.hopIndex ?? 0) + 1}/${s.hopCount}\x1b[0m` })
        else if (s.phase === 'ready') cb({ phase: 'ready' })
        else if (s.phase === 'error') cb({ phase: 'error', message: s.message ?? 'unknown error' })
      }) ?? (() => {}),
    onClose: (id, cb) => api()?.onClose(id, (info) => cb(sshCloseReason(info))) ?? (() => {}),
    onLifecycle: (phase) => {
      if (phase === 'connecting') setServerStatus(server.id, 'connecting')
      else setServerStatus(server.id, phase === 'online' ? 'online' : 'offline')
    }
  }
}

export function localTransport(shell: LocalShell, cwd?: string): TerminalTransport {
  const api = () => window.shellpilot?.local
  return {
    key: `local:${shell.id}`,
    title: shell.label,
    subtitle: shell.path,
    connect: (sessionId, cols, rows) =>
      Promise.resolve(api()?.connect({ sessionId, shellId: shell.id, cwd, cols, rows })),
    write: (id, d) => api()?.write(id, d),
    ack: (id, bytes) => api()?.ack(id, bytes),
    resize: (id, c, r) => api()?.resize(id, c, r),
    close: (id) => api()?.close(id),
    onData: (id, cb) => api()?.onData(id, cb) ?? (() => {}),
    onStatus: (id, cb) =>
      api()?.onStatus(id, (s) => {
        if (s.phase === 'ready') cb({ phase: 'ready' })
        else if (s.phase === 'error') cb({ phase: 'error', message: s.message ?? 'unknown error' })
      }) ?? (() => {}),
    onClose: (id, cb) => api()?.onClose(id, (info) => cb(localCloseReason(info))) ?? (() => {})
  }
}
```

- [ ] **Step 2: Extract the hook**

Create `src/renderer/src/hooks/useTerminalSession.ts` by moving `TerminalView.tsx:206-378` wholesale and applying exactly four changes:

1. The parameter `server: Server` becomes `transport: TerminalTransport`.
2. Both `useEffect` dependency arrays change from `[server.id]` / `[server.id, generation]` to `[transport.key]` / `[transport.key, generation]`. The eslint-disable comments at `:281` and `:356` stay for the same reason.
3. `bridge?.ssh.*` calls become `transport.*`; `setServerStatus(server.id, …)` becomes `transport.onLifecycle?.(…)`.
4. The `onData` handler gains the ack, which is the whole point of Phase 1's flow window:

```ts
    const offData = transport.onData(sessionId, (d) => {
      // xterm calls back once the chunk has been parsed into the buffer. Main
      // stops reading the pty when too many bytes are outstanding, so this is
      // what unblocks it — without the callback the window never reopens and a
      // large `cat` stalls forever after the first 512 KB.
      term.write(d, () => transport.ack?.(sessionId, d.length))
    })
```

The session id keeps the same shape but keys on the transport rather than the server: `` const sessionId = `sess-${transport.key}-${Math.random().toString(36).slice(2)}` ``.

The OSC 7 handler at `:258-262` stays as it is — a local zsh with `add-zsh-hook` or a bash with `PROMPT_COMMAND` emits OSC 7 exactly like a remote one does, so `tabCwd` works for local tabs for free.

- [ ] **Step 3: Reduce TerminalView to a chooser**

`TerminalView.tsx` keeps `createTerm`, `safeFit`, `observeSize`, `setupTerminalUX`, `themeFromCss`, `parseOsc7` and the demo shell unchanged. `RealTerminal` (`:466-531`) changes signature from `{ server, tabId }` to `{ transport, tabId }`, and `TerminalView` (`:533-539`) becomes:

```tsx
export function TerminalView({
  transport,
  server,
  tabId
}: {
  transport?: TerminalTransport
  // Only for the demo path, which is still keyed on a Server.
  server?: Server
  tabId?: string
}): React.JSX.Element {
  if (transport) return <RealTerminal transport={transport} tabId={tabId} />
  if (server && server.demo !== false) return <DemoTerminal server={server} />
  return <EmptyState icon={<TerminalIcon size={26} />} title="Session unavailable" message="This session has no transport." />
}
```

- [ ] **Step 4: Typecheck and run the app**

```bash
npm run typecheck:web && npm run dev
```
Expected: existing SSH sessions behave exactly as before — connect, reconnect after a drop, scrollback survives, Ctrl+wheel zoom, split still works. This phase must be a pure refactor with zero behavioural change for SSH.

- [ ] **Step 5: Commit**

```bash
git add src/renderer/src/lib/transport.ts src/renderer/src/hooks/useTerminalSession.ts src/renderer/src/components/terminal/TerminalView.tsx
git commit -m "refactor(terminal): make the session hook transport-agnostic"
```

**Done when:** `TerminalView` no longer imports `sshHopsFor` or `window.shellpilot.ssh`, and every existing SSH behaviour is unchanged by manual test.

**Rollback:** revert. This is the one phase with no feature flag, because it ships no feature — if SSH regresses, revert immediately.

---

### Phase 5 — The tab-model refactor

**This is the hardest constraint in the plan, so the decision and its justification come first.**

#### Decision: discriminated union on `Tab`. Not a synthesized pseudo-`Server`.

`src/renderer/src/types.ts:166` types `Tab.serverId` as `UUID | null`, but every consumer assumes non-null. The tempting fix is to mint a fake `Server` row (`{ id: 'local-1', host: 'localhost', username: <user>, demo: false, … }`) and push it into `state.servers`, so every existing consumer keeps working untouched. **That is the trap.** `servers` is not a private list belonging to the tab system; it is the app's central entity table, and it is read by eleven surfaces plus main. Concretely, a pseudo-`Server` leaks into:

1. **The sidebar tree.** `store/app.ts:400` `workspaceServers()` → `ConnectionTree.tsx:32,141` renders a `ServerRow` for it. A "Local" row with a status dot that never goes green, a right-click menu offering *Edit server*, *Open monitor* and *Route editor*, and a `Route` icon it can never have.
2. **The command palette.** `CommandPalette.tsx:54-68` iterates `workspaceServers()` and lists every one with `sub: ${s.username}@${s.host}` — so "Local · you@localhost", opening which calls `store.openServer(s.id)`, which dials SSH to `localhost:22`.
3. **The monitor wall.** `store/app.ts:952-999` `syncMonitorLayout()` files *every* server in the workspace into a group; `FleetMonitor.tsx:327` then renders a `ServerMonitorCard`, whose `useServerMetrics` (`hooks/useServerMetrics.ts:76`) calls `metrics:sample` → `main/index.ts:443` → `metricsSample` → `acquire()`. That is a real SSH dial to a host that does not accept one, retried on a timer, forever.
4. **SFTP and the docked monitor strip.** `WorkspacePanel.tsx:85,90,95` mount `MonitorStrip`, `MonitorView` and `SftpView` for any tab with a server. `SftpView.tsx:152-160` builds an `SshConnectConfig` from it and calls `sftp:connect`.
5. **The MCP data cache — the fatal one.** `servers` is a **persisted** key (`store/persist.ts:16`), and `main/index.ts:704` `data:save` feeds `refreshMcpDataCache` (`src/main/services/mcpDataCache.ts`). A pseudo-`Server` written to disk becomes an MCP-visible server the moment it is created. `list_servers` (`mcpServer.ts:485`) would return it, and `execute_command` would accept it as a target. **The local terminal would be exposed over MCP without anyone adding a tool** — which is precisely the outcome the brief forbids.
6. **The policy assignment server list.** `main/index.ts:730` `aiPolicy:listServers` → `AiAccessGroups.tsx:314` — the fake server appears in the per-server access-group override table, and a user can grant it Full Access.
7. **The tunnel editor.** `TunnelManager.tsx:322,382` — a `<select>` of `useWorkspaceServers()` for which SSH server carries a tunnel.
8. **The database editor.** `AddDatabaseModal.tsx:23,225` — the same `<select>` for `sshServerId`.
9. **The route-hop editor.** `RouteHops.tsx:17,114` — "reuse a saved server's credentials for this hop".
10. **Backup.** `persist.ts` writes `servers` into the blob `backup:export` encrypts, so the fake row travels into every backup and restores on another machine where its `id` means nothing.

Suppressing it in all ten places means adding a `demo`-style discriminator to `Server` anyway — at which point the union is the honest version of the same thing, with the type checker enforcing the ten exclusions instead of ten hand-written filters that drift.

**Cost of the union:** `serverId` moves off the base type, so every site that reads `tab.serverId` must narrow. There are nine, enumerated below, and seven of them already tolerate the absence.

#### Every `tab.serverId` / `servers.find` site, and what happens to it

| Site | Current behaviour | Under the union |
|---|---|---|
| `WorkspacePanel.tsx:125` | `servers.find(s => s.id === active.serverId)` gates the viewbar at `:205` | Narrow: `active?.kind === 'ssh' ? servers.find(...) : undefined`. The Terminal/Monitor/Files segment (`:207-217`) renders only for `kind === 'ssh'`; a local tab gets the split controls only. |
| `WorkspacePanel.tsx:128` (`addTab`) | `if (active?.serverId) newSession(...)` else add-server modal | Three-way: ssh → `newSession`, local → `openLocal(active.shellId)`, none → the shell menu. |
| `WorkspacePanel.tsx:165` | tab-bar status dot from `servers.find` | `kind === 'ssh'` only; local tabs show a terminal glyph. |
| `WorkspacePanel.tsx:269` → `TabPane` `:56-58` | `"Session unavailable — This server no longer exists."` when the lookup misses | Becomes reachable **only** for `kind === 'ssh'` with a deleted server, which is exactly the case the message describes. Local tabs never take this branch. |
| `store/app.ts:493` `openServer` | bails when the server is gone | Unchanged; only ever called with a real id. |
| `store/app.ts:515` `newSession` | bails when the server is gone | Unchanged. |
| `store/app.ts:534-540` `duplicateTab` | falls back to `src.title.replace(/ \(\d+\)$/, '')` when the server is missing | **Already correct for local tabs.** Only the constructed object needs to spread `src`'s kind-specific fields. |
| `store/app.ts:679-680` `deleteWorkspace` | `!t.serverId \|\| !doomedServers.has(t.serverId)` | **Already tolerates the absence.** Local tabs survive a workspace delete only if they belong to another workspace — add `t.workspaceId !== id` to the same filter. |
| `store/app.ts:734-735` `deleteServer` | `t.serverId !== id` | **Already correct** — `undefined !== id`, so local tabs are kept. |
| `store/app.ts:285-288` `sessionTitle` | counts `t.serverId === serverId` | Must become kind-aware, or `undefined === null` silently never matches and every local tab is titled identically. |
| `hooks/useHotkeys.ts:30-33` `new-terminal` | `serverId` → `newSession`, else add-server modal | Kind-aware, as `addTab` above. |
| `hooks/useHotkeys.ts:74-79` `splitActive` | `if (!tab?.serverId) return false` — **blocks Ctrl+\ on a local tab** | `if (!tab) return false`. |
| `ConnectionTree.tsx:141` | `activeTab?.serverId === s.id` | **Safe as written** — `undefined` never equals a UUID. |
| `CommandPalette.tsx:83` | reads `.id` and `.title` only | **Safe as written.** |

- [ ] **Step 1: Write the failing store test**

Create `tests/localTabModel.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest'
import { useApp } from '../src/renderer/src/store/app'

const reset = (): void =>
  useApp.setState({ tabs: [], activeTabId: null, tabSession: {}, tabCwd: {}, panes: {} })

describe('local tabs', () => {
  beforeEach(reset)

  it('opens a local tab with no serverId at all', () => {
    useApp.getState().openLocal({ id: 'darwin-zsh', label: 'zsh', kind: 'posix', path: '/bin/zsh', args: ['-l'] })
    const [tab] = useApp.getState().tabs
    expect(tab.kind).toBe('local')
    expect('serverId' in tab).toBe(false)
    expect(tab.title).toBe('zsh')
  })

  it('numbers repeat local sessions per shell, not per server', () => {
    const shell = { id: 'darwin-zsh', label: 'zsh', kind: 'posix' as const, path: '/bin/zsh', args: ['-l'] }
    const open = useApp.getState().openLocal
    open(shell); open(shell); open(shell)
    expect(useApp.getState().tabs.map((t) => t.title)).toEqual(['zsh', 'zsh (2)', 'zsh (3)'])
  })

  it('never writes a synthesized server into the servers list', () => {
    // The whole reason for the discriminated union: `servers` is persisted and
    // fed to the MCP data cache, so anything added here becomes an
    // MCP-addressable server.
    useApp.getState().openLocal({ id: 'darwin-zsh', label: 'zsh', kind: 'posix', path: '/bin/zsh', args: ['-l'] })
    expect(useApp.getState().servers).toEqual([])
  })

  it('keeps local tabs when the server they sit beside is deleted', () => {
    useApp.setState({ servers: [{ id: 's1', workspaceId: 'ws-default', name: 'box' } as never] })
    useApp.getState().openServer('s1')
    useApp.getState().openLocal({ id: 'darwin-zsh', label: 'zsh', kind: 'posix', path: '/bin/zsh', args: ['-l'] })
    useApp.getState().deleteServer('s1')
    expect(useApp.getState().tabs.map((t) => t.kind)).toEqual(['local'])
  })
})
```

- [ ] **Step 2: Run and watch it fail**

```bash
npx vitest run tests/localTabModel.test.ts
```
Expected: FAIL — `openLocal is not a function`.

> **Note:** the store is renderer code and imports `zustand` and `./lib/bridge`. `vitest.config.ts:5` sets `environment: 'node'` and `include: ['tests/**/*.test.ts']`. `store/app.ts` touches `window.shellpilot` only inside `releaseVpnSecrets` (`:330`), guarded by `bridgeHas`, so it imports cleanly under node. If it does not, add `environmentMatchGlobs` for this one file rather than switching the whole suite to jsdom.

- [ ] **Step 3: Change the type**

In `src/renderer/src/types.ts`, replace lines 161-169 with:

```ts
interface TabBase {
  id: UUID
  // Tabs belong to the workspace they were opened in, so switching workspaces
  // does not show another workspace's sessions.
  workspaceId: UUID
  title: string
  view: PanelView
}

// A tab backed by a saved server. `serverId` is non-null here on purpose: it
// was typed `UUID | null` while every consumer assumed non-null, which is how
// "Session unavailable" became reachable for reasons other than a deleted
// server.
export interface SshTab extends TabBase {
  kind: 'ssh'
  serverId: UUID
}

// A tab backed by a shell on this machine. It has no server, and deliberately
// does not synthesize one: `servers` is persisted and mirrored into the MCP
// data cache, so a fake row there would make the local terminal an
// MCP-addressable target without anyone registering a tool.
export interface LocalTab extends TabBase {
  kind: 'local'
  // A LocalShell.id from src/shared/local.ts.
  shellId: string
  // Where the shell was started, when the user asked for somewhere specific.
  cwd?: string
  // Only 'terminal' is meaningful; Monitor and Files are SSH-only views.
  view: 'terminal'
}

export type Tab = SshTab | LocalTab
```

- [ ] **Step 4: Update the store**

In `src/renderer/src/store/app.ts`:

Replace `sessionTitle` (`:284-288`):

```ts
// Repeat sessions are numbered "name", "name (2)", "name (3)". Counting is
// per-target, and the target is a server for an SSH tab and a shell for a local
// one — comparing `t.serverId === serverId` across both would compare
// `undefined === null`, never match, and title every local tab identically.
function sessionTitle(tabs: Tab[], match: (t: Tab) => boolean, name: string): string {
  const count = tabs.filter(match).length
  return count ? `${name} (${count + 1})` : name
}
```

Update the three call sites: `openServer` does not use it; `newSession` (`:521`) passes `(t) => t.kind === 'ssh' && t.serverId === serverId`; `duplicateTab` (`:540`) passes a matcher built from `src`'s own kind.

Add `kind: 'ssh'` to the two `Tab` literals at `:503-509` and `:517-523`, and to `duplicateTab`'s at `:536-542` (which must spread the kind-specific fields from `src`).

Add the action:

```ts
  // Always a new tab. Unlike openServer there is no "focus the existing one"
  // path: a second local shell is a second shell, never the same one.
  openLocal: (shell: LocalShell, cwd?: string) => {
    const tab: LocalTab = {
      id: uid('tab'),
      kind: 'local',
      workspaceId: get().activeId(),
      shellId: shell.id,
      cwd,
      title: sessionTitle(get().tabs, (t) => t.kind === 'local' && t.shellId === shell.id, shell.label),
      view: 'terminal'
    }
    set((s) => ({ tabs: [...s.tabs, tab], activeTabId: tab.id }))
  },
```

Declare it in the `AppState` interface beside `newSession` (`:162`):

```ts
  openLocal: (shell: LocalShell, cwd?: string) => void
```

Fix `deleteWorkspace` (`:679-680`) so local tabs in the doomed workspace go too:

```ts
        tabs: s.tabs.filter(
          (t) => t.workspaceId !== id && (t.kind !== 'ssh' || !doomedServers.has(t.serverId))
        ),
```

- [ ] **Step 5: Fix every narrowing site**

Work through the fourteen rows in the table above. `npm run typecheck:web` is the checklist — the union makes the compiler point at each one. Do **not** add `as SshTab` casts anywhere; if a site needs one, the narrowing is in the wrong place.

`hooks/useHotkeys.ts:29-34`:

```ts
  'new-terminal': (s) => {
    const tab = s.activeTab()
    if (tab?.kind === 'ssh') s.newSession(tab.serverId)
    else if (tab?.kind === 'local') s.openLocalById(tab.shellId, tab.cwd)
    else s.setModal('add-server')
    return true
  },
```

`hooks/useHotkeys.ts:74-79`:

```ts
// Splitting applies to any terminal tab, local or remote. It used to require a
// serverId, which silently made Ctrl+\ a no-op in a local tab.
function splitActive(s: Store, dir: 'h' | 'v'): boolean {
  const tab = s.activeTab()
  if (!tab) return false
  s.toggleSplit(tab.id, dir)
  return true
}
```

(`openLocalById(shellId, cwd)` is a thin wrapper that resolves the shell from the cached list; add it beside `openLocal`.)

- [ ] **Step 6: Handle old saves**

`Tab` is **not** in the persisted set — `store/persist.ts:8-20` lists `workspaces / monitorGroups / activeWorkspaceId / folders / servers / vpns / tunnels / databases / settings`, and tabs are absent. **No migration is needed.** Confirm this by grepping before assuming it:

```bash
grep -n "tabs" src/renderer/src/store/persist.ts
```
Expected: no match. If a later change adds tabs to the blob, `replaceAll` (`:1003`) must default `kind` to `'ssh'` for any tab that has a `serverId` and drop any that has neither.

- [ ] **Step 7: Run the tests**

```bash
npm run typecheck && npx vitest run tests/localTabModel.test.ts
```
Expected: PASS, 4 tests, and a clean typecheck with no casts added.

- [ ] **Step 8: Commit**

```bash
git add src/renderer/src/types.ts src/renderer/src/store/app.ts src/renderer/src/hooks/useHotkeys.ts src/renderer/src/components/panel/WorkspacePanel.tsx tests/localTabModel.test.ts
git commit -m "refactor(tabs): discriminated union on Tab for local vs ssh sessions"
```

**Done when:** `openLocal` creates a working local tab; `state.servers` is provably untouched by it; SSH tabs are unchanged; typecheck is clean with zero new casts.

**Rollback:** revert. The union is one type and one action; nothing persisted changed, so a revert cannot strand user data.

---

### Phase 6 — Panes and UI

`WorkspacePanel.tsx:71-79` hard-codes exactly two panes and gives the second no `tabId`, so its OSC-7 cwd and its session id go nowhere. Replace it with a per-tab array.

**Files:**
- Create: `src/renderer/src/components/panel/PaneGrid.tsx`
- Create: `src/renderer/src/components/terminal/LocalShellMenu.tsx`
- Modify: `src/renderer/src/store/app.ts` (`tabSplit` → `panes`)
- Modify: `src/renderer/src/components/panel/WorkspacePanel.tsx:38-100`, `:127-130`, `:161-244`
- Modify: `src/renderer/src/lib/shortcuts.ts:50-57`
- Modify: `src/renderer/src/components/palette/CommandPalette.tsx:54-68`

- [ ] **Step 1: Replace `tabSplit` with `panes` in the store**

`tabSplit: Record<string, TabSplit>` (`app.ts:121`) becomes:

```ts
// A pane is one terminal inside a tab. Each has its own transport, so a tab
// can hold a remote shell beside a local one — which is the whole point of
// splitting rather than opening a second tab.
export type PaneTarget =
  | { kind: 'ssh'; serverId: string }
  | { kind: 'local'; shellId: string; cwd?: string }

export interface Pane {
  id: string
  target: PaneTarget
}

export interface TabPanes {
  // A flat, ordered list laid out along one axis. Not a tree: tmux's nested
  // splits are a much larger surface and nothing in the brief needs them.
  // 'v' lays panes left-to-right, 'h' top-to-bottom, matching the existing
  // toggleSplit(dir) contract at store/app.ts:603-606.
  direction: 'h' | 'v'
  panes: Pane[]
  activePaneId: string
}

panes: Record<string, TabPanes>
```

Actions:

```ts
  // Adds a pane to a tab, defaulting to the same target the active pane has.
  // Capped at MAX_PANES: past four the terminals are too narrow to be useful
  // and every one of them holds a live process.
  splitPane: (tabId: string, dir: 'h' | 'v', target?: PaneTarget) => void
  closePane: (tabId: string, paneId: string) => void
  setActivePane: (tabId: string, paneId: string) => void
```

`toggleSplit` (`:603-606`) is kept as a shim so `useHotkeys.ts` and the two viewbar buttons need no change of contract: with one pane it splits, with the tab already split in that direction it collapses back to the first pane. Add `MAX_PANES = 4`.

`dropTabs` (`:249-270`) must delete `panes[id]` alongside `tabSession`, `tabCwd` and `tabSplit`.

- [ ] **Step 2: Write the pane grid**

`PaneGrid.tsx` renders `TabPanes` as the existing `.splits` / `.split-pane` CSS (`WorkspacePanel.tsx:72-79`), generalised to N children with `flex: 1` each, a click-to-focus border on the active pane, and — critically — **every** pane gets a `tabId`, not just the first:

```tsx
{tp.panes.map((p) => (
  <div
    key={p.id}
    className={clsx('split-pane', p.id === tp.activePaneId && 'active')}
    onMouseDown={() => setActivePane(tab.id, p.id)}
  >
    <TerminalView transport={transportFor(p.target)} tabId={tab.id} paneId={p.id} />
  </div>
))}
```

`tabSession` and `tabCwd` are keyed by `tabId` today (`app.ts:117-118`). With N panes they must key on `paneId`; `SftpView.tsx:147-149` reads `s.tabSession[tabId]` / `s.tabCwd[tabId]` and must read the **active** pane's entry instead. Add a selector `activePaneSession(tabId)` so `SftpView` has one thing to call and the keying change is invisible to it.

- [ ] **Step 3: Write the shell menu**

`LocalShellMenu.tsx` is a dropdown anchored to the `+` button (`WorkspacePanel.tsx:191-193`), listing `await window.shellpilot.local.shells()` with the default first. Fetched once on mount into component state; a *Rescan* entry at the bottom calls `shells(true)`. Guard the whole component with `bridgeHas(window.shellpilot?.local, 'shells')` (the pattern at `store/app.ts:330`) so a renderer running against an older preload degrades to the current behaviour instead of throwing.

The `+` button becomes a split button: click = the current tab's kind (as `addTab` at `:127-130`), the caret = the menu.

- [ ] **Step 4: Add the shortcut**

`src/renderer/src/lib/shortcuts.ts`, after line 51:

```ts
  {
    id: 'new-local-terminal',
    name: 'New Local Terminal',
    group: 'Tabs',
    scope: 'app',
    keys: 'Ctrl+Shift+T',
    hint: 'Opens a shell on this machine, not on a server.'
  },
```

with a `RUNNERS` entry in `useHotkeys.ts` calling `openLocalById(defaultShellId)`.

- [ ] **Step 5: Add the palette entries**

`CommandPalette.tsx`, after the `workspaceServers()` loop (`:54-68`), add one entry per discovered shell under a `Local Shells` group, `run: () => store.openLocal(shell)`. Fetch the list in the same `useMemo` the commands are built in, from a `useState` populated by a `useEffect` — the palette must not await inside `useMemo`.

- [ ] **Step 6: Gate the SSH-only views**

`TabPane` (`WorkspacePanel.tsx:38-100`) switches on `tab.kind`. For `'local'` it renders only the terminal pane grid — **no** `MonitorStrip` (`:85`), **no** `MonitorView` (`:90`), **no** `SftpView` (`:95`). All three take a non-optional `server: Server` and would need a fake one, which is the trap this plan already rejected. The viewbar (`:205-244`) shows the three-view segment only for `kind === 'ssh'`; local tabs get the split controls and the `server-meta` slot shows the shell path instead of `user@host:port`.

- [ ] **Step 7: Manual test matrix**

```bash
npm run dev
```
Verify, in order:
1. `+` → menu lists this machine's shells; the default is marked.
2. Open a local tab; `echo $PATH` (macOS) contains Homebrew.
3. `Ctrl+\` splits it; both panes are live and independent; typing in one does not echo in the other.
4. Split a *remote* tab; both panes still work (the regression risk of the `tabSession` re-keying).
5. Split a local tab, then change the second pane's target to an SSH server: local beside remote in one tab.
6. Close a pane; the remaining pane refits.
7. `exit` in a local pane → the dead-session overlay with a working *Reconnect*.
8. Open ten local tabs, `yes` in each, switch tabs — the UI stays responsive (this is the coalescer and the flow window under load).
9. Quit the app with local shells running → `localDisposeAll` reaps them. Confirm with `ps` / Task Manager that no orphan shell survives.

- [ ] **Step 8: Commit**

```bash
git add src/renderer/src/components/panel/PaneGrid.tsx src/renderer/src/components/terminal/LocalShellMenu.tsx src/renderer/src/components/panel/WorkspacePanel.tsx src/renderer/src/store/app.ts src/renderer/src/lib/shortcuts.ts src/renderer/src/components/palette/CommandPalette.tsx src/renderer/src/components/panel/SftpView.tsx
git commit -m "feat(local): local terminal tabs, shell picker and N-pane splits"
```

**Done when:** the nine-step matrix passes on the implementer's platform; the other two are checked in Phase 7's `--dir` packs and by a reviewer with that OS.

**Rollback:** the `localTerminalEnabled` setting hides the `+` menu, the palette group and the shortcut. The pane refactor is not flagged and cannot be — if it regresses SSH splits, revert the phase.

---

### Phase 7 — Packaging and CI

**Files:**
- Modify: `electron-builder.yml:14-24`, `:52-56`, `:88-141`
- Modify: `.github/workflows/ci.yml:48`
- Modify: `.github/workflows/release.yml` (the macOS signature-verification step)
- Create: `scripts/verify-local-pty-pack.mjs`
- Create: `tests/localPackaging.test.ts`

- [ ] **Step 1: Write the failing packaging test**

Create `tests/localPackaging.test.ts`, in the style of `tests/releaseWorkflow.test.ts` (a plain YAML parse asserting on shape, which is the only thing about packaging that can be checked on every PR):

```ts
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { load } from 'js-yaml'

interface Builder {
  files: string[]
  asarUnpack: string[]
  mac: { extendInfo?: Record<string, string>; hardenedRuntime?: boolean }
}
const cfg = load(readFileSync('electron-builder.yml', 'utf8')) as Builder

describe('node-pty is unpacked as a whole package directory', () => {
  it('names the package dir, never a *.node glob', () => {
    // node-pty ships `spawn-helper`, a Mach-O/ELF EXECUTABLE that is
    // fork/exec'd on every spawn. A '**/*.node' pattern leaves it inside the
    // asar, where it has no path on disk to exec and posix_spawn fails with
    // ENOENT. Unpacking the directory also preserves the +x bit, which asar's
    // own runtime extraction does not.
    const unpacked = cfg.asarUnpack.join('\n')
    expect(unpacked).toContain('@lydell/node-pty')
    expect(cfg.asarUnpack.some((p) => p.includes('node-pty') && p.endsWith('*.node'))).toBe(false)
  })

  it('covers the per-platform prebuild packages too', () => {
    // @lydell/node-pty resolves the binding out of a sibling optional
    // dependency (@lydell/node-pty-darwin-arm64 and friends), so unpacking
    // only the meta package leaves the actual .node inside the archive.
    expect(cfg.asarUnpack.some((p) => /@lydell\/node-pty-/.test(p) || /@lydell\/\*\*/.test(p))).toBe(true)
  })
})

describe('the installers carry no debug or redistributable-ConPTY payload', () => {
  it('excludes prebuild .pdb files', () => {
    // Several MB of Windows debug symbols, and a .pdb inside an installer is a
    // standard heuristic hit for the AV engines the release gates on.
    expect(cfg.files).toContain('!**/prebuilds/**/*.pdb')
  })
  it('excludes the bundled conpty redistributable', () => {
    // NOTE — this drafted assertion is what actually shipped broken. It compares
    // the pattern's TEXT, so it passed against a pattern that matched no file,
    // and conpty.dll and OpenConsole.exe went into the first 0.8.0 Windows
    // installer. Run the glob instead, through the same matcher electron-builder
    // uses, against real paths from the published tarball. See R3b.
    //
    // The shipped version of this test is in tests/localPackaging.test.ts.
    const rule = cfg.files.find((p) => p.includes('conpty'))!
    const excludes = (path: string): boolean => minimatch(path, rule.slice(1), { dot: true })
    const WIN = 'node_modules/@lydell/node-pty-win32-x64/prebuilds/win32-x64/'

    expect(excludes(`${WIN}conpty/conpty.dll`)).toBe(true)
    expect(excludes(`${WIN}conpty/OpenConsole.exe`)).toBe(true)
    // The bindings one level up are what the app loads; they must survive.
    expect(excludes(`${WIN}conpty.node`)).toBe(false)
    expect(excludes(`${WIN}conpty_console_list.node`)).toBe(false)
  })
})

describe('macOS file-access usage descriptions', () => {
  // Without these keys, the FIRST time any process under the app bundle
  // touches ~/Documents, ~/Desktop or ~/Downloads, macOS terminates it — it
  // does not prompt, because there is no string to put in the prompt. A local
  // shell touches all three on day one: `ls ~/Downloads` is the second thing
  // anyone types.
  it.each(['NSDocumentsFolderUsageDescription', 'NSDesktopFolderUsageDescription', 'NSDownloadsFolderUsageDescription'])(
    '%s is present and non-empty',
    (key) => {
      expect(cfg.mac.extendInfo?.[key]).toBeTruthy()
      expect((cfg.mac.extendInfo?.[key] ?? '').length).toBeGreaterThan(20)
    }
  )

  it('still runs hardened', () => {
    // Regression guard: adding extendInfo must not disturb the block that
    // enables the hardened runtime (electron-builder.yml:130).
    expect(cfg.mac.hardenedRuntime).toBe(true)
  })
})
```

- [ ] **Step 2: Run and watch it fail**

```bash
npx vitest run tests/localPackaging.test.ts
```
Expected: FAIL on all seven assertions.

- [ ] **Step 3: Apply the `electron-builder.yml` deltas**

Under `files:` (currently `:14-24`), after the `'!resources/bin/**'` line:

```yaml
  # node-pty's Windows prebuilds carry debug symbols and a redistributable
  # ConPTY the app does not use (localPty.ts sets useConptyDll: false, so the
  # one in conhost.exe is used instead). Neither is needed at runtime, both are
  # megabytes, and shipping unsigned Microsoft binaries through an installer is
  # precisely what the Defender and ClamAV hard-fail gates in the release
  # workflow are there to catch.
  - '!**/prebuilds/**/*.pdb'
  # `prebuilds/*/conpty/**`, NOT `prebuilds/**/conpty/**`. With a leading `**/`
  # already in the pattern, a second `**/` in the middle makes minimatch match
  # nothing at all, and the redistributable ships. That segment is one
  # platform-arch directory, so a single `*` is also the accurate shape. See R3b.
  - '!**/node_modules/@lydell/node-pty-*/prebuilds/*/conpty/**'
```

Note the `.pdb` line above is a **no-op** and did not ship: electron-builder already strips `.pdb`
from node_modules unless `includePdb: true` (`appFileCopier.js:128-132`). See finding #16.

Under `asarUnpack:` (currently `:52-56`), after `'**/node_modules/ssh2/**'`:

```yaml
  # The whole package directory, deliberately not a '*.node' glob.
  #
  # node-pty is not only a loadable binding: on macOS and Linux it ships
  # `spawn-helper`, a Mach-O/ELF *executable* that it fork/execs for every
  # session. A glob that matches only .node files leaves that helper inside
  # the archive, where it has no path on disk to hand to posix_spawn and every
  # spawn fails with ENOENT. Unpacking the directory at build time is also what
  # preserves its +x bit — asar's runtime extraction does not.
  #
  # The second pattern covers the per-platform prebuild packages: @lydell/
  # node-pty resolves its binding out of an optional sibling dependency
  # (@lydell/node-pty-darwin-arm64 and friends), so unpacking only the meta
  # package leaves the actual pty.node behind.
  - '**/node_modules/@lydell/node-pty/**'
  - '**/node_modules/@lydell/node-pty-*/**'
```

Under `mac:`, after `entitlementsInherit` (`:132`) and before the `target:` block (`:139`):

```yaml
  # macOS TCC prompt copy.
  #
  # On macOS 10.15+ the first access to ~/Documents, ~/Desktop or ~/Downloads by
  # any process inside this bundle raises a consent prompt, and these strings are
  # its body text. They are OPTIONAL for the Files-and-Folders class: without
  # them the system supplies generic copy, and a denial surfaces as EPERM
  # ("Operation not permitted"), not a crash. (Termination on a missing usage
  # description is real, but for the hardware/data classes — Camera, Contacts,
  # Photos — not this one. Terminal.app declares none of these three keys.)
  #
  # We set them because a dialog that explains why a terminal wants your
  # Downloads folder gets approved, and a generic one gets declined. The child
  # shell inherits the app bundle's TCC identity, so the strings belong here and
  # nowhere in the child's environment.
  #
  # Cost specific to this app: with `identity: '-'` there is no Team ID for TCC
  # to key the grant on, so it falls back to the ad-hoc cdhash — which changes on
  # every build. Each release therefore re-prompts. That is the same root cause
  # as the keychain-ACL note above, and another entry on the Developer ID case.
  extendInfo:
    NSDocumentsFolderUsageDescription: >-
      ShellPilot needs access to your Documents folder so that commands you run
      in a local terminal can read and write files there.
    NSDesktopFolderUsageDescription: >-
      ShellPilot needs access to your Desktop so that commands you run in a
      local terminal can read and write files there.
    NSDownloadsFolderUsageDescription: >-
      ShellPilot needs access to your Downloads folder so that commands you run
      in a local terminal can read and write files there.
    NSRemovableVolumesUsageDescription: >-
      ShellPilot needs access to removable volumes so that commands you run in a
      local terminal can read and write files on external drives.
```

- [ ] **Step 4: Run the packaging test**

```bash
npx vitest run tests/localPackaging.test.ts
```
Expected: PASS, 7 tests.

- [ ] **Step 5: Write the pack verifier**

Create `scripts/verify-local-pty-pack.mjs`, a plain Node script (no deps) taking the `release/` dir, that asserts:

1. exactly one unpacked app dir exists;
2. `…/app.asar.unpacked/node_modules/@lydell/node-pty/` exists;
3. a `pty.node` exists under `…/app.asar.unpacked/node_modules/@lydell/`;
4. on darwin/linux, `spawn-helper` exists and `(mode & 0o111) !== 0` — this is the exact defect that disqualified `node-pty@1.1.0`;
5. no `*.pdb` and no path containing `/conpty/` anywhere under the pack;
6. on darwin, `codesign --verify --strict` passes for the `.node` and for `spawn-helper`.

Each failure prints `::error::` and exits non-zero, matching the style of `scripts/verify-bin-manifest.mjs`.

- [ ] **Step 6: Add the CI pack job**

In `.github/workflows/ci.yml`, after the `check` job:

```yaml
  # CI has always been ubuntu-only and has never run electron-builder, so
  # nothing here proved that a PACKAGED app could load a native module or exec
  # a helper binary — the first time that was tested was a release tag. A
  # native dependency makes that gap load-bearing, so this job packs (--dir,
  # no installers, no publish, no code-signing identity beyond ad-hoc) on all
  # three runners and asserts the layout the app depends on at runtime.
  #
  # It does NOT launch Electron. See docs/plans/local-terminal-plan.md,
  # "Testing strategy", for what that leaves unverified and why.
  pack:
    name: Pack ${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - run: npm ci
      - run: npm run build
      # The tunnel engines are not built here: extraResources' `from`
      # directories are simply absent, which electron-builder warns about and
      # continues past. This job is about the asar layout, not the engines —
      # scripts/verify-bin-manifest.mjs in the release workflow covers those.
      - run: npx electron-builder --dir --publish never
      - run: node scripts/verify-local-pty-pack.mjs release
      # Proves the prebuilt binding loads and spawn-helper execs under plain
      # Node on this OS. Node-API is what makes this transferable to Electron;
      # a NAN/V8 module could not be checked this way at all.
      - run: npx vitest run tests/localPtySmoke.test.ts
```

- [ ] **Step 7: Extend the release signature check**

In `.github/workflows/release.yml`, in the *Verify macOS signature covers the engines* step, after the `Resources/bin` loop, add:

```bash
          # spawn-helper and pty.node live outside the asar (asarUnpack), so
          # they are nested binaries electron-builder has to discover and sign
          # exactly like the engines under Resources/bin. --deep above covers
          # the bundle as a whole; this names them, so a config change that
          # stops unpacking them fails the release rather than shipping an app
          # whose local terminal dies on first use.
          UNPACKED="$APP/Contents/Resources/app.asar.unpacked/node_modules/@lydell"
          if [ ! -d "$UNPACKED" ]; then
            echo "::error::@lydell/node-pty is not unpacked in the packaged app"; exit 1
          fi
          find "$UNPACKED" \( -name '*.node' -o -name 'spawn-helper' \) -print0 \
            | while IFS= read -r -d '' bin; do
                echo "checking $bin"
                codesign --verify --strict "$bin"
              done
```

- [ ] **Step 8: Verify locally, then commit**

```bash
npm run build && npx electron-builder --dir --publish never
node scripts/verify-local-pty-pack.mjs release
open release/*/ShellPilot.app   # macOS: launch the packed app and open a local tab
```
Expected: the verifier passes, and the packed app opens a working local terminal.

For the `extendInfo` check, `ls ~/Downloads` "not killing the app" proves nothing — it would be true
either way (see the corrected R4). The check that can actually fail is: run `ls ~/Downloads`, confirm
the consent dialog carries **our** copy rather than generic system text, approve it, then rebuild and
relaunch and record whether the grant survived. It will not, because the ad-hoc cdhash changed — that
is the finding worth having, and it is the one only a packed build can produce.

```bash
git add electron-builder.yml .github/workflows/ci.yml .github/workflows/release.yml scripts/verify-local-pty-pack.mjs tests/localPackaging.test.ts
git commit -m "build(local): unpack node-pty, trim prebuilds, add macOS TCC strings and a pack CI job"
```

**Done when:** `--dir` packs succeed and the verifier passes on all three runners; a packed macOS build survives `ls ~/Downloads`; the release workflow's signature loop names the unpacked binaries.

**Rollback:** the YAML changes are additive and inert without the dependency; revert the whole phase together with Phase 1 if the dependency is dropped.

---

### Phase 8 — Security assertions and the flag flip

**Files:**
- Create: `tests/localTerminalNotExposed.test.ts`
- Modify: `src/renderer/src/store/app.ts` (`DEFAULT_SETTINGS`)
- Modify: `docs/AI-SECURITY.md`, `SECURITY.md`, `README.md`

- [ ] **Step 1: Write the exposure test**

Create `tests/localTerminalNotExposed.test.ts`:

```ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { refreshMcpDataCache } from '../src/main/services/mcpDataCache'
import { resetPolicyCacheForTests } from '../src/main/services/policyStore'
import { setMcpConfig, createSession, resetMcpAuthForTests } from '../src/main/services/mcpAuth'
import { startMcpServer, stopMcpServer } from '../src/main/services/mcpServer'

// The local terminal is a shell on the user's own machine with the user's own
// privileges, reached with no credential and no host key. It is not behind a
// capability and not behind ASK, because there is no setting of either that
// makes it safe to hand an agent — an agent that can run local commands can
// read the vault file, the policy store and the audit log it is supposedly
// constrained by. The three assertions below are what keep that true when
// someone later adds "just a read-only one".

const PORT = 58741
const ROOT = resolve(__dirname, '..')

// Every tool the bridge is allowed to expose. A whitelist, not a pattern
// match: a new tool has to be added here deliberately, in a diff a reviewer
// sees, which is the whole point.
//
// MUST be reconciled against the registerTool calls in mcpServer.ts before
// this test is committed — read the real names out of the file. See Q6.
const ALLOWED_TOOLS = [
  'list_workspaces', 'list_servers', 'get_server_details', 'execute_command',
  'read_file', 'write_file', 'list_files', 'get_server_metrics',
  'list_databases', 'query_database', 'list_tunnels', 'set_tunnel',
  'list_vpns', 'set_vpn', 'add_server'
]

describe('the MCP bridge exposes no local-terminal surface', () => {
  let token: string
  beforeAll(async () => {
    resetMcpAuthForTests()
    resetPolicyCacheForTests()
    refreshMcpDataCache({ workspaces: [{ id: 'ws', name: 'W' }], servers: [] })
    setMcpConfig({ enabled: true, port: PORT })
    token = (await createSession({ agentName: 't', workspaces: [{ id: 'ws', name: 'W' }], groupId: null, groupName: 'Read Only', ttlMinutes: null })).token
    await startMcpServer()
  })
  afterAll(async () => { await stopMcpServer() })

  it('registers no tool whose name mentions local, shell, pty, spawn or exec', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } }
    })
    const client = new Client({ name: 'guard', version: '1.0.0' })
    await client.connect(transport)
    const { tools } = await client.listTools()
    const names = tools.map((t) => t.name)

    const offenders = names.filter((n) => /local|shell|pty|spawn|(^|_)exec($|_)/i.test(n))
    expect(offenders, `These tool names suggest a local-execution surface: ${offenders.join(', ')}`).toEqual([])

    // And nothing outside the reviewed list at all.
    const unexpected = names.filter((n) => !ALLOWED_TOOLS.includes(n))
    expect(unexpected, `New MCP tools must be added to ALLOWED_TOOLS in this test, deliberately: ${unexpected.join(', ')}`).toEqual([])
    await client.close()
  })
})

describe('no MCP-reachable module can even import the local terminal', () => {
  // A static check on top of the runtime one. The runtime check catches a tool
  // that was registered; this catches the step before it, and it also covers
  // the CLI bridge, which is a second agent-facing surface with no listTools
  // to interrogate.
  const FORBIDDEN = /from\s+['"].*(localPty|shellDiscovery)['"]|require\(['"].*(localPty|shellDiscovery)['"]|@lydell\/node-pty/

  function walk(dir: string): string[] {
    const out: string[] = []
    for (const e of readdirSync(dir)) {
      const full = join(dir, e)
      if (statSync(full).isDirectory()) out.push(...walk(full))
      else if (/\.ts$/.test(e)) out.push(full)
    }
    return out
  }

  const guarded = [
    join(ROOT, 'src/main/services/mcpServer.ts'),
    join(ROOT, 'src/main/services/mcpDataCache.ts'),
    join(ROOT, 'src/main/services/mcpAuth.ts'),
    join(ROOT, 'src/main/services/policyEngine.ts'),
    join(ROOT, 'src/main/services/agentServerCreate.ts'),
    ...walk(join(ROOT, 'src/cli'))
  ]

  it.each(guarded)('%s does not reach the local terminal', (file) => {
    expect(FORBIDDEN.test(readFileSync(file, 'utf8'))).toBe(false)
  })
})

describe('no capability names the local terminal', () => {
  it('AiCapability gains no local-execution member', () => {
    // Adding one would be the natural next step for someone implementing
    // "let the agent run something locally". This is where that conversation
    // has to happen instead of landing in a diff.
    const src = readFileSync(join(ROOT, 'src/shared/mcp.ts'), 'utf8')
    const union = /export type AiCapability =([\s\S]*?)\n\n/.exec(src)?.[1] ?? ''
    expect(/local|shell|pty|spawn/i.test(union)).toBe(false)
  })
})
```

- [ ] **Step 2: Run it**

```bash
npx vitest run tests/localTerminalNotExposed.test.ts
```
Expected: PASS. If the `ALLOWED_TOOLS` assertion fails, correct the list from the source; do not weaken the assertion.

- [ ] **Step 3: Add a deliberate temporary violation and confirm the test catches it**

Add a one-line `import { localWrite } from './localPty'` to `src/main/services/mcpServer.ts`, re-run, confirm FAIL, then remove it. A guard nobody has seen fail is a guard nobody knows works.

- [ ] **Step 4: Flip the flag**

In `src/renderer/src/store/app.ts` `DEFAULT_SETTINGS` (`:74-88`), set `localTerminalEnabled: true`.

- [ ] **Step 5: Document it**

- `SECURITY.md`: a *Local terminal* section — runs with the user's privileges; deliberately not reachable from the AI bridge or the CLI; the guard test that enforces it.
- `docs/AI-SECURITY.md`: an explicit "what the bridge cannot do" line naming the local terminal, so the answer exists before someone asks.
- `README.md`: the feature, the shells discovered per OS, and the fact that macOS starts a **login** shell.
- `THIRD-PARTY-NOTICES.md`: `@lydell/node-pty` and its license.

- [ ] **Step 6: Full run and commit**

```bash
npm run typecheck && npm run test && npm run build
git add tests/localTerminalNotExposed.test.ts src/renderer/src/store/app.ts SECURITY.md docs/AI-SECURITY.md README.md THIRD-PARTY-NOTICES.md
git commit -m "feat(local): enable local terminals; assert they are never exposed over MCP"
```

**Done when:** the guard test passes, has been seen to fail against a deliberate violation, and the feature is on by default.

**Rollback:** set `localTerminalEnabled: false`. The IPC handlers stay registered but nothing in the UI reaches them; `ELECTRON_DISABLE_LOCAL_TERMINAL=1` additionally short-circuits `loadPty()` before the native import.

---

## Testing strategy, and what CI cannot tell us

`.github/workflows/ci.yml` runs on `ubuntu-latest` only and never invokes electron-builder. That is fine for pure-TS features and it is the reason `cpu-features` shipped for a year without loading in packaged macOS builds (`electron-builder.yml:124-129`). A native dependency makes the gap load-bearing.

| Phase | Runs in CI (ubuntu, every PR) | Runs in the new `pack` job (3 OS) | Only a human, only in Phase 0 / a release |
|---|---|---|---|
| 1 | coalescer + flow-window units; real PTY spawn under Node | — | the binding under **Electron** with hardened runtime |
| 2 | WSL UTF-16LE, `wslpath` `\r`, `dscl`, dash exclusion | — | the actual shell list on a real Windows / macOS box |
| 3 | typecheck of the handler↔preload contract | — | end-to-end IPC in a running app |
| 4 | typecheck | — | SSH reconnect, scrollback survival, zoom |
| 5 | store unit tests (`openLocal`, titles, `servers` untouched) | — | — |
| 6 | — | — | the whole nine-step pane matrix |
| 7 | `electron-builder.yml` + workflow shape (18 tests) | asar layout, `spawn-helper` +x, no `conpty/`, per-platform binding set, **bundle-level** macOS codesign | AppImage `noexec` `/tmp`; the ConPTY console-list fork; the TCC grant surviving a rebuild |
| 8 | MCP tool whitelist, static import guard, capability guard | — | — |

**What this leaves unverified, stated plainly.** No job in this repository launches Electron. So the claim "the Node-API binding loads inside the Electron 43 main process, under `hardenedRuntime: true` with `build/entitlements.mac.plist`" is established once, by hand, in Phase 0 Step 6, and thereafter only by a release build being smoke-tested. **Mitigations, in the order they buy confidence per unit of cost:**

1. The `pack` job (Phase 7) — proves the *layout* on all three OSes on every push. Cheap (~4 min), catches the entire class of "the file is in the wrong place" bugs, which is what actually breaks native modules in Electron.
2. `tests/localPtySmoke.test.ts` under plain Node on ubuntu — proves the *binding loads and `spawn-helper` execs*. This is only meaningful because the module is Node-API: the same prebuilt `.node` loads in Node 20 and Electron 43. It is the single strongest argument for the `@lydell/node-pty` choice over `node-pty@1.1.0`, and it should be called out as such in the PR description.
3. A manual release checklist item: *"Download each of the three installers, open a local terminal, run `echo $PATH` and `ls ~/Downloads`."* Add it to the release notes template. Three minutes per release, and it is the only thing that covers the residual gap.

**Deliberately not proposed:** a headless-Electron (`xvfb-run electron .`) job. It would close the gap on Linux only — the two platforms where the packaging is actually delicate (macOS hardened runtime, Windows ConPTY) cannot be covered headlessly on a GitHub runner without more scaffolding than the risk justifies. If the local terminal later grows a daemon, revisit.

---

## Backpressure

Two independent mechanisms, both required:

1. **Per-tick coalescing** (`localPty.ts` `coalescer`, copied from `ssh.ts:602-617`). Bounds the *number* of IPC messages. Without it, `cat` on a large file sends hundreds of small `local:data:*` messages per second and the renderer's event loop starves — input goes laggy and the app feels broken. A single keystroke echo still goes out on the same tick.

2. **An ack-driven flow window** (`flowWindow`, `FLOW_HIGH_WATER = 512 KB`, `FLOW_LOW_WATER = 64 KB`). Bounds the *volume in flight*. `xterm.write(data, cb)` fires the callback once the chunk is parsed into the buffer; the renderer acks the byte count over `local:ack`; main stops reading the pty past the high-water mark and resumes below the low. This is how VS Code's terminal does it and it is the only thing that keeps `yes` in ten tabs from pinning the app.

The pause and resume are driven through node-pty's `handleFlowControl`: writing a chunk exactly equal to `flowControlPause` makes node-pty pause its read loop instead of forwarding the bytes to the child. **The tokens must not be `\x13`/`\x11`.** A user pressing Ctrl+S sends `'\x13'` as its own `local:write` call, which would match the sentinel exactly and be swallowed — breaking Ctrl+S in vim, in emacs, and everywhere else it is bound. Use OSC sequences nobody can type (`\u001b]777;shellpilot-pause\u0007`). `localWrite` additionally refuses the tokens on the way in, so a compromised renderer cannot stall its own session permanently.

SSH sessions are deliberately **not** given the ack path in v1: they already have the coalescer, and the far end's own TCP window plus the ssh2 channel window provide the backpressure a local pty lacks.

---

## Rollback and kill-switches

| Phase | Kill-switch | Blast radius of a revert |
|---|---|---|
| 0 | — | none, nothing merged |
| 1 | `ELECTRON_DISABLE_LOCAL_TERMINAL=1` short-circuits `loadPty()` before the native import | one new file + one dependency |
| 2 | `listShells()` catches and returns `[]`, so discovery failure = no shells, not a crash | one new file |
| 3 | `settings.localTerminalEnabled` (default `false`) hides every caller; handlers stay but are unreachable | preload + 3 lines of `main/index.ts` |
| 4 | **none — this is a pure refactor with no feature to flag.** Revert immediately if SSH regresses. | `TerminalView` and two new lib files |
| 5 | none — a type change | `types.ts`, `app.ts`, and the fourteen narrowing sites |
| 6 | `localTerminalEnabled` hides the `+` menu, palette group and shortcut; the pane refactor is not flagged | `WorkspacePanel`, `PaneGrid`, store `panes` slice |
| 7 | YAML is additive and inert without the dependency | build config + CI |
| 8 | set `localTerminalEnabled: false` | one constant |

Phases 4 and 5 are the two with no flag, because neither ships a feature — they are refactors that must be correct on their own. Land each behind its own PR with the manual SSH regression matrix (connect, drop, reconnect, split, zoom, SFTP cwd sync) run and recorded in the PR body.

---

## Non-goals for v1

- **Detach / reattach surviving an app restart.** Needs a daemon that outlives the Electron process. The documented future path is a Go sidecar built the way `sidecar/netd` already is (`scripts/build-sidecar.sh`, `resources/bin/${platform}-${arch}`, `scripts/verify-bin-manifest.mjs`), driving `aymanbagabas/go-pty` v0.2.3 and speaking a small framed protocol over a unix socket / named pipe. The `TerminalTransport` interface (Phase 4) is the seam that migration goes through: a third implementation, `sidecarTransport`, and nothing in the renderer changes. **Do not build any of it now.**
- **A tmux-style nested pane tree.** Panes are a flat list on one axis, capped at four. Nested trees are a much larger surface (resize propagation, focus traversal, serialisation) and nothing in the brief needs them.
- **Local SFTP / a local file browser.** `SftpView` is SSH-only; a local file browser is a different feature.
- **Local host metrics on the monitor strip.** Would need a whole second metrics implementation that reads this machine instead of shelling out over SSH.
- **Shell profile management** (custom argv, per-profile env, saved working directories). Discovery only in v1.
- **Any AI/MCP access to a local shell.** Permanently, not just in v1. See Phase 8.
- **Windows on ARM, and Linux on arm64.** `@lydell/node-pty` prebuilds cover the four slots ShellPilot ships (`electron-builder.yml:63, 141, 163`) and no others. If the shipped arch list grows, this must be re-checked first.

---

## Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | The `.node` loads in dev but not in a packaged macOS build under `hardenedRuntime: true` — exactly what already happens to `cpu-features` (`electron-builder.yml:124-129`) | Low (Node-API + `disable-library-validation` in `build/entitlements.mac.plist`) | High — feature dead on macOS | Phase 0 Step 6 tests this configuration specifically, before any product code. `loadPty()` degrades to a named error instead of crashing. |
| R2 | `spawn-helper` ships non-executable or unsigned, so every spawn fails with ENOENT in the installed app | Medium — this is the defect that disqualified `node-pty@1.1.0` | High | `asarUnpack` names the whole directory; `scripts/verify-local-pty-pack.mjs` asserts the mode bit on every pack; the release signature loop names it. |
| R3 | ~~Excluding the redistributable ConPTY breaks Windows~~ | **Retired** — Q3 closed on real Windows | — | A `windows-latest` CI step deletes `conpty/` and respawns on every push, and fails if the directory is missing rather than passing vacuously. |
| R3b | The exclusion pattern matches nothing, so the redistributable ships anyway | **Happened**, in the first 0.8.0 build | Medium — two unsigned Microsoft binaries into an installer that AV-gates on | With a leading `**/` already present, a second `**/` mid-pattern makes minimatch match no path. Use `prebuilds/*/conpty/**`. The packaging test now runs the glob through electron-builder's own matcher instead of asserting the pattern's text, which is why the original slipped through. |
| R4 | macOS TCC re-prompts for folder access on **every release**, because an ad-hoc signature has no Team ID and the cdhash changes each build | **Certain** | Medium — recurring user friction, looks like the app forgot its permissions | Cannot be fixed without a Developer ID. Document it in the README. `mac.extendInfo` at least makes each prompt explain itself. *(An earlier draft claimed a missing usage description would TERMINATE the app — that is the hardware/data classes, not Files-and-Folders. Corrected; severity dropped from High.)* |
| R5 | Defender or ClamAV flags an installer once a PTY binary is inside, hard-failing the release (`release.yml`, both gates `exit 1`) | Low–Medium | High — no release can be cut | Ship no `winpty-agent.exe` (that is why `node-pty@1.1.0` was rejected), no `.pdb`, no redistributable ConPTY. If a false positive happens anyway, the fallback is a VirusTotal-corroborated allowance recorded in the release notes — **not** loosening the gate. |
| R6 | The pane refactor regresses SSH split panes, which work today | Medium — `tabSession`/`tabCwd` re-key from `tabId` to `paneId`, and `SftpView.tsx:147-149` reads both | Medium | A named `activePaneSession(tabId)` selector so `SftpView` has one call site; step 4 of the Phase 6 matrix tests remote splits explicitly. |
| R7 | The `Tab` union causes a wide, mechanical diff someone "fixes" with `as SshTab` casts, defeating the whole point | Medium | High — the pseudo-Server problem returns in a worse form | The enumerated fourteen-site table is the review checklist. Reject any PR in Phase 5 that adds a cast. |
| R8 | Someone later adds a `run_local_command` MCP tool because a user asked | Medium, over time | Critical — an agent with local exec can read the vault file, the policy store and the audit log that supposedly constrain it | `tests/localTerminalNotExposed.test.ts`: a tool **whitelist**, a static import guard over `mcpServer.ts` / `mcpDataCache.ts` / `src/cli/**`, and a capability-union guard. Plus the `SECURITY.md` paragraph, so the answer exists before the question. |
| R9 | Backpressure regression: a `yes` in a background tab pins the app | Medium without the flow window | Medium | Coalescer + ack window, unit-tested; step 8 of the Phase 6 matrix is the load test. |
| R10 | macOS login shell breaks for a user whose `~/.zprofile` is interactive (asks a question, runs `tmux`) | Low | Low–Medium | Documented in the README; the dead-session overlay's *Reconnect* already exists (`TerminalView.tsx:489-506`). A per-shell "no login shell" toggle is a v2 profile feature (non-goal). |
| R11 | `wsl.exe -l -q` hangs on a machine where WSL is installed but broken, blocking discovery | Low | Medium — the shell menu never populates | 6-second `timeout` on the `execFile`; `listShells()` catches to `[]`; the menu renders whatever it got. |
| R12 | The new `pack` CI job doubles PR latency and gets disabled | Medium | Medium — the safety net erodes | `--dir` only, no installers, no engines, no publish; ~4 min. If it still hurts, gate it to pushes to `main` plus a `packaging` PR label rather than deleting it. |

---

## Open questions

Answer these in Phase 0. Do not invent answers; a wrong guess here invalidates a later phase.

- **Q1 — Does `@lydell/node-pty@1.2.0-beta.15` expose `handleFlowControl` / `flowControlPause` / `flowControlResume`?** Upstream `node-pty` has had them since 0.10, and this is a fork, but the beta's option surface has not been read. *If not:* fall back to `pty.pause()` / `pty.resume()` on the underlying socket if exposed; if neither is available, drop the ack scheme, keep the coalescer, and add a hard per-session cap (drop-oldest above 2 MB in flight with a `[output truncated]` marker) — worse, but bounded.
- **Q2 — Exact on-disk layout of the prebuilds.** Is the binding inside `@lydell/node-pty/prebuilds/<platform>-<arch>/`, or in sibling optional packages `@lydell/node-pty-<platform>-<arch>/`? The `asarUnpack` patterns and `scripts/verify-local-pty-pack.mjs` both depend on the answer. Phase 0 Step 1 settles it; correct both patterns before Phase 7 is committed.
- **Q3 — Is the bundled `conpty` directory optional on Windows? — ANSWERED: yes.** The negation
  assumed the system ConPTY in `conhost.exe` is used and the redistributable is dead weight. Proven
  on `windows-latest` (CI run 33494240165): with `conpty/` deleted, `cmd.exe` spawns and echoes
  through ConPTY. The check is now a permanent CI step rather than a one-off, and it hard-fails if
  the directory is not there to delete. **Do not re-open this by inspection; it is settled by
  execution on the platform in question.**
- **Q4 — Does the AppImage build need anything extra?** AppImage relocates the app root at runtime; a `.node` under `app.asar.unpacked` normally resolves fine, but ShellPilot has never shipped a native module it actually loads (`cpu-features` does not load — `electron-builder.yml:124-129`), so this has never been exercised. Phase 0 Step 6 must include the AppImage, not just the `--dir` pack.
- **Q5 — Is `bash -i` without `-l` the right default on Linux?** The plan argues yes (a login bash reads `~/.bash_profile` and skips `~/.bashrc`, where Linux users keep everything, and the GUI session already inherits `~/.profile`). But a Wayland session started by a display manager that does not source `~/.profile` would leave PATH short. Test on both a GNOME/Wayland and a bare i3/X11 session before committing to it. If PATH is short, switch to `['-l', '-i']` and accept that `~/.bash_profile` then also runs.
- **Q6 — Is `execute_command` the only tool name in `ALLOWED_TOOLS` that legitimately matches an "execution" pattern?** The whitelist in `tests/localTerminalNotExposed.test.ts` must be built by reading the `registerTool` calls in `src/main/services/mcpServer.ts`, not from this document. Do that before committing Phase 8.

---

### Critical files for implementation

- `src/main/services/ssh.ts` — the data plane to mirror; the coalescer at `:602-617` and the `sshConnect`/`cleanup` lifecycle at `:563-755` are copied structurally into `localPty.ts`.
- `src/renderer/src/store/app.ts` — the `Tab` union, `openLocal`, the `tabSplit`→`panes` migration, and the `sessionTitle`/`deleteWorkspace` narrowing sites.
- `src/renderer/src/components/terminal/TerminalView.tsx` — `useRealSession` at `:206-378` becomes the transport-agnostic `useTerminalSession`; the `generation` reconnect at `:238`/`:372-375` and the xterm-outlives-session split at `:243`/`:286` must both survive.
- `src/renderer/src/components/panel/WorkspacePanel.tsx` — `TabPane`'s "Session unavailable" bail-out at `:56-58` and the hard-coded 2-pane split at `:71-79`.
- `electron-builder.yml` — `files` (`:14-24`), `asarUnpack` (`:52-56`), and the `mac` block (`:88-141`) where `extendInfo` is currently absent.
