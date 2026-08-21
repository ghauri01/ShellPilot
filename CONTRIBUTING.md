# Contributing to ShellPilot

Thanks for considering a contribution. Bug reports, documentation, translations
and code are all welcome, and you do not need to be an Electron expert to help.

## Getting set up

```bash
git clone https://github.com/ghauri01/ShellPilot.git
cd shellpilot
npm install
npm run dev
```

Requires **Node.js 20+**.

Before opening a pull request:

```bash
npm run typecheck    # must pass — main, preload and renderer
npm run build        # must succeed
```

Build installers on the platform you are targeting — a Windows installer has to
be built on Windows.

> Working in WSL? Note that `node_modules` is platform-specific. If you run
> `npm install` in Windows and then build in WSL (or vice versa) you will get
> errors about missing `@rollup/rollup-*` or `@esbuild/*` binaries. Delete
> `node_modules` and reinstall in whichever environment you are building from.

## Architecture

ShellPilot is Electron + React + TypeScript, built with electron-vite. Three
processes, three source trees:

```
src/
  main/         Node.js. Owns all I/O: SSH, SFTP, databases, crypto, files.
    services/   One module per subsystem.
  preload/      The only bridge between main and renderer. Defines the IPC API.
  renderer/     React UI. No Node access at all.
    src/
      components/   Feature-grouped UI
      store/        zustand state (app.ts) and persistence (persist.ts)
      hooks/        Shortcuts, metrics polling, click-outside
      lib/          Small shared helpers
  shared/       Types and pure functions used by more than one process
```

### Rules that keep it safe

1. **Secrets never reach the renderer.** The UI sends a `serverId`; the main
   process merges credentials from the encrypted store. Do not pass passwords
   or key material through IPC in the other direction.
2. **The renderer has no Node access.** `contextIsolation` is on,
   `nodeIntegration` is off. Everything goes through `preload/index.ts`.
3. **Never `eval` user input.** Shell and query input is parsed — see
   `main/services/relaxed-json.ts` for the pattern.
4. **Write files atomically.** Temp file plus rename, so a crash cannot
   truncate a user's data. See `main/services/vault.ts`.
5. **Build SSH hop lists with `sshHopsFor()`** in `renderer/src/lib/ssh.ts`.
   Hand-rolling that mapping is how hops end up with no credentials.

### Things worth knowing

- **Connections are pooled.** `main/services/ssh.ts` keeps one authenticated
  connection per hop, shared by terminals, SFTP and metrics. This is what makes
  two-factor auth bearable. If you add a feature that opens SSH, use
  `acquire()` / `release()` — never `openChain()` directly.
- **Every tab stays mounted.** Views hide with `display: none` rather than
  unmounting, so sessions survive switching tabs, views and workspaces. If you
  add background work (polling, timers), gate it on **visibility**, not on
  being rendered.
- **State shape changes need a migration.** `replaceAll` in `store/app.ts`
  normalises older saved data. Add a default there rather than assuming a
  field exists.

## Making a change

1. Fork, then branch from `main`: `git checkout -b fix/short-description`
2. Keep the change focused — one problem per pull request
3. Match the surrounding style; comments explain **why**, not what
4. Run `npm run typecheck` and `npm run build`
5. Describe what you changed, why, and how you tested it

### Commit messages

Conventional commits, please:

```
fix(ssh): carry key path onto jump hops
feat(vault): search across custom fields
docs(readme): document folder drag and drop
```

## Reporting bugs

A good report includes:

- ShellPilot version and how you installed it
- OS and version
- What you did, what you expected, what happened
- The exact error text, if there is one
- Whether it involves a jump host, two-factor auth or a tunnel — those paths
  have the most moving parts

Please **redact hostnames, usernames, keys and IPs** before pasting logs.

## Suggesting features

Open a discussion or an issue describing the problem you hit, not only the
solution you have in mind. The [issue tracker](https://github.com/ghauri01/ShellPilot/issues)
lists what is already planned, and the roadmap is kept there.

## Where help is most needed

- **Tests.** There is no test suite yet. The parsers in `shared/sshconfig.ts`
  and `main/services/relaxed-json.ts` and the crypto in `main/services/` are
  pure and easy to cover.
- **Replacing placeholder UI.** Several Settings controls hold local state and
  do nothing; they are tracked as issues.
- **Accessibility.** Keyboard navigation and screen-reader labels.
- **Documentation and translations.**

## Licence

By contributing you agree that your work is licensed under the
[MIT Licence](LICENSE) that covers this project.
