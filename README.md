<div align="center">

<img src="docs/images/logo.png" alt="ShellPilot logo" width="120" />

# ShellPilot

**A free, open-source SSH client, SFTP browser, database manager and secrets vault — in one desktop app.**

Your DevOps workstation, everywhere. Windows · macOS · Linux.

<a href="https://github.com/ghauri01/ShellPilot/releases/latest">
<img src="https://img.shields.io/badge/Download%20ShellPilot-22c7d6?style=for-the-badge&labelColor=0d1119" alt="Download ShellPilot" height="34" />
</a>

<a href="https://github.com/ghauri01/ShellPilot/releases/latest"><img src="https://img.shields.io/badge/Windows-0d1119?style=for-the-badge&logo=windows&logoColor=22c7d6" alt="Windows" height="26" /></a>
<a href="https://github.com/ghauri01/ShellPilot/releases/latest"><img src="https://img.shields.io/badge/macOS-0d1119?style=for-the-badge&logo=apple&logoColor=22c7d6" alt="macOS" height="26" /></a>
<a href="https://github.com/ghauri01/ShellPilot/releases/latest"><img src="https://img.shields.io/badge/Linux-0d1119?style=for-the-badge&logo=linux&logoColor=22c7d6" alt="Linux" height="26" /></a>

[![Latest release](https://img.shields.io/github/v/release/ghauri01/ShellPilot?style=flat-square&label=release&color=22c7d6&labelColor=30363d&sort=semver)](https://github.com/ghauri01/ShellPilot/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/ghauri01/ShellPilot/total?style=flat-square&label=downloads&color=22c7d6&labelColor=30363d)](https://github.com/ghauri01/ShellPilot/releases)
[![Stars](https://img.shields.io/github/stars/ghauri01/ShellPilot?style=flat-square&label=stars&color=22c7d6&labelColor=30363d)](https://github.com/ghauri01/ShellPilot/stargazers)
[![License](https://img.shields.io/badge/license-MIT-22c7d6?style=flat-square&labelColor=30363d)](LICENSE)

[Features](#features) · [Install](#install) · [Quick start](#quick-start) · [Comparison](#shellpilot-vs-mobaxterm-putty-termius-and-securecrt) · [Workspaces](#workspaces) · [Command palette](#command-palette) · [Shortcuts](#keyboard-shortcuts) · [Databases](#databases) · [Vault](#vault) · [FAQ](#faq) · [Contributing](#contributing) · [Licence](#licence)

</div>

---

ShellPilot is a **free and open-source alternative to MobaXterm, PuTTY, Termius, SecureCRT and MobaXterm Personal Edition**, built for engineers who spend the day moving between bastions, production boxes and databases. It combines an **SSH terminal**, **SFTP file browser**, **server monitoring**, **SSH tunnels**, a **multi-engine database client** and an **encrypted password vault** in a single window — with no account, no telemetry and no subscription.

![ShellPilot main window](docs/images/main-window.png)

## Why ShellPilot

Most terminal tools do one thing. A typical DevOps task needs four: open a shell through a jump host, tail a file, poke a database that is only reachable from inside the network, and look up a credential. ShellPilot puts those in one place, keeps them organised per project, and stores every secret in your operating system's keychain rather than a plaintext config file.

- **No lock-in** — connections import from your existing `~/.ssh/config`
- **No account** — nothing is uploaded, nothing phones home
- **No cost** — MIT licensed, free forever, contributions welcome

## ShellPilot vs MobaXterm, PuTTY, Termius and SecureCRT

If you are looking for a **free MobaXterm alternative**, a **modern PuTTY replacement**, or an
**open-source Termius alternative** that does not put your saved servers behind a subscription,
this is the short version:

| | **ShellPilot** | MobaXterm | PuTTY | Termius | SecureCRT |
|---|---|---|---|---|---|
| Price | **Free, MIT** | Free tier, paid Pro | Free | Free tier, paid Pro | Paid licence |
| Open source | **Yes** | No | Yes | No | No |
| Windows / macOS / Linux | **All three** | Windows only | All three | All three | All three |
| Account required | **No** | No | No | Yes for sync | No |
| Telemetry | **None** | Some | None | Yes | Some |
| Saved sessions limit | **Unlimited** | 12 on free tier | Unlimited | Limited on free tier | Unlimited |
| Chained jump hosts | **Unlimited** | Yes | Manual | Yes | Yes |
| SFTP browser | **Built in** | Built in | Separate app | Built in | Built in |
| SSH tunnels + SOCKS5 | **Yes** | Yes | Yes | Yes | Yes |
| Database client | **PostgreSQL, MySQL, SQL Server, MongoDB, Redis** | No | No | No | No |
| Encrypted secrets vault | **Yes, AES-256-GCM** | Password store | No | Cloud vault | No |
| Live server monitoring | **Yes** | Basic | No | No | No |
| Rebindable shortcuts | **Every one** | Partial | Partial | Partial | Yes |

The point of difference is the **database client and the vault**. Every other tool in that table
sends you to a second application the moment you need to query a table or look up an API key.


## Features

| | |
|---|---|
| **SSH terminal** | Full xterm terminal with GPU rendering, search, split panes, copy-on-select and configurable zoom |
| **Jump hosts / bastions** | Unlimited chained hops per server, each with its own credentials |
| **Two-factor auth** | Answers keyboard-interactive challenges; connections are shared so you enter a code once, not per session |
| **SFTP browser** | Browse, edit, upload, rename and delete files over the same connection |
| **Server monitoring** | Live CPU, memory, disk and network docked under the terminal, with resource alerts |
| **SSH tunnels** | Local forwards, remote forwards and a SOCKS5 proxy |
| **Databases** | PostgreSQL, MySQL, SQL Server, MongoDB and Redis — with an interactive shell per engine |
| **Databases over SSH** | Reach a database that is only routable from a bastion |
| **Vault** | AES-256-GCM encrypted store for URLs, logins, API keys and free-form key/value pairs |
| **Workspaces** | Isolated, optionally password-protected spaces per client or environment |
| **Encrypted backup** | One passphrase-protected file containing everything, portable across machines |
| **Host key verification** | Trust-on-first-use, with a hard stop when a key changes |
| **Rebindable shortcuts** | Every shortcut is remappable per context, with conflict detection and export/import |

## Install

Download the latest build from the [Releases](https://github.com/ghauri01/ShellPilot/releases/latest) page.

| Platform | File | Notes |
|---|---|---|
| **Windows 10/11** | [`ShellPilot-x.y.z-setup.exe`](https://github.com/ghauri01/ShellPilot/releases/latest) | Installer, desktop + Start-menu shortcut. Pick this one if unsure. |
| **Windows (portable)** | [`ShellPilot-x.y.z-portable.exe`](https://github.com/ghauri01/ShellPilot/releases/latest) | Single file, no install, keeps its data beside the `.exe` — runs from a USB stick |
| **macOS (Apple Silicon)** | [`ShellPilot-x.y.z-arm64.dmg`](https://github.com/ghauri01/ShellPilot/releases/latest) | M1 and later |
| **macOS (Intel)** | [`ShellPilot-x.y.z-x64.dmg`](https://github.com/ghauri01/ShellPilot/releases/latest) | Intel Macs |
| **Linux** | [`ShellPilot-x.y.z-x86_64.AppImage`](https://github.com/ghauri01/ShellPilot/releases/latest) | `chmod +x ShellPilot-*.AppImage` and run — works on any distribution |
| **Linux (Debian / Ubuntu)** | [`ShellPilot-x.y.z-amd64.deb`](https://github.com/ghauri01/ShellPilot/releases/latest) | `sudo apt install ./ShellPilot-*-amd64.deb` |

<details>
<summary><b>What are the other files on the release page?</b></summary>

A release carries 14 assets. Six of them are the downloads above; the rest are
build metadata that you can ignore.

| Asset | What it is | Do you need it? |
|---|---|---|
| `*.blockmap` | A map of the installer's content blocks, used to work out which parts of a file changed between two versions so an update can download only the difference. | **No** — it is only read by an updater, never by you. |
| `latest.yml`, `latest-mac.yml`, `latest-linux.yml` | The update feed for each platform: the current version number, the file names and their checksums. Published automatically by `electron-builder`. | **No.** ShellPilot does not auto-update yet — check back here for new versions. |
| **Source code** (zip / tar.gz) | A snapshot of the repository at the tagged commit, generated by GitHub. Not a build — it contains no application, just the source. | **No**, unless you intend to [build from source](#build-from-source). |

</details>

### Verifying a download

Every asset on the release page lists its SHA-256. Compare it against the file
you downloaded — the builds are unsigned, so this is the strongest integrity
check available:

```bash
sha256sum ShellPilot-x.y.z-x86_64.AppImage    # Linux
shasum -a 256 ShellPilot-x.y.z-arm64.dmg      # macOS
```

```powershell
Get-FileHash ShellPilot-x.y.z-setup.exe -Algorithm SHA256    # Windows
```

> The builds are **not code-signed**. Windows SmartScreen will warn on first run — choose *More info → Run anyway*. On macOS, run `xattr -cr /Applications/ShellPilot.app` if Gatekeeper blocks it.

### Build from source

```bash
git clone https://github.com/ghauri01/ShellPilot.git
cd ShellPilot
npm install

npm run dev          # run in development
npm run typecheck    # type check main, preload and renderer
npm run build        # bundle without packaging

npm run dist:win     # Windows installer + portable exe
npm run dist:linux   # AppImage + deb
npm run dist:mac     # dmg (must be run on macOS)
```

Requires **Node.js 20+**. Build each platform's installer on that platform.

## Quick start

### 1. Add a server

Click **+** in the Connections sidebar, or press <kbd>Ctrl</kbd>+<kbd>N</kbd>.

![Add Server dialog](docs/images/add-server.png)

Fill in the host, port and username, then pick how to authenticate:

- **Password** — stored in your OS keychain
- **Private key** — browse to the key file; the path and optional passphrase are stored in the keychain, never in plaintext
- **SSH Agent** — uses `SSH_AUTH_SOCK`, or Pageant on Windows
- **Certificate** — for certificate-based setups

> **Key files without an extension** (`id_ed25519`, or any bare filename) are fully supported — the file picker shows all files by default.

### 2. Add jump hosts, in the same dialog

Servers inside a private network are reached through a bastion. Click **Add jump host** and the hops appear right there — no second dialog, no separate step.

![Add Server with jump hosts](docs/images/add-server-jump-hosts.png)

Each hop can either:

- **Use a saved server** — the hop borrows that server's stored credentials, so a key is defined once and reused, or
- **Be a custom host** — set its own host, port, user and private key

Hops connect in order, top to bottom: `you → Hop 1 → Hop 2 → target`. Use the arrows to reorder.

### 3. Open a session

Click a server to open it. **Double-click to open an additional session** in a new tab — useful when you want one shell tailing logs and another running commands.

Sessions keep running when you switch workspaces, change views or open a database. Nothing is torn down until you close the tab.

## Workspaces

A workspace is an isolated space with its own servers, folders, databases, tunnels and colour. Use one per client, per environment, or per project — whatever keeps unrelated infrastructure apart.

Open the switcher in the title bar, or **Manage Workspaces** (<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>N</kbd>).

![Manage Workspaces](docs/images/manage-workspaces.png)

**What a workspace gives you**

- **Isolation** — the sidebar, tabs and databases only ever show the active workspace
- **Colour coding** — pick a colour so production never looks like staging
- **Fast switching** — <kbd>Ctrl</kbd>+<kbd>1</kbd> … <kbd>Ctrl</kbd>+<kbd>9</kbd> jump straight to a workspace
- **Hiding** — clutter you rarely touch can be hidden from the switcher
- **Password protection** — lock a workspace behind a password
- **Live sessions survive** — switching workspaces never disconnects a running session

**Password-protected workspaces**

Toggle **Password protect** when creating a workspace, or use the padlock on an existing one. Anything that tries to open it — the switcher, the shortcut, the manager — asks for the password first. Unlocks last for the session only; everything re-locks when the app restarts. The password is stored as a scrypt verifier, never as recoverable text.

> **Scope of this feature:** a workspace password gates access **inside the app**. It does not encrypt the workspace's servers on disk. For data that must be protected at rest, use the [Vault](#vault) or an [encrypted backup](#backup--restore).

## Organising servers with folders

Folders keep a long server list navigable, and they nest as deep as you like.

![Folder context menu](docs/images/folders-context-menu.png)

### Create a folder

![Connections toolbar](docs/images/connections-toolbar.png)

The Connections toolbar has three actions — from left to right:

| Icon | Action |
|---|---|
| 📁+ | **New folder** — creates a folder and drops straight into rename |
| ⬇ | **Import from `~/.ssh/config`** — bulk-import your existing hosts |
| ➕ | **Add server** |

There is also a small **New folder** button on the `CONNECTIONS` section header itself.

### Create a subfolder

**Right-click any folder** → **New subfolder**. The same menu has **Rename** and **Delete**.

Deleting a folder never deletes its contents — servers and subfolders move back to the top level.

### Move servers into folders

**Drag and drop.** Drag a server onto a folder to move it in; drag it onto the `CONNECTIONS` header to move it back to the root. Folders show a running count of everything inside them, including subfolders.

Databases have their own, separate folder tree with the same behaviour, so a "Staging" folder for servers does not clutter the database sidebar.

### Import from `~/.ssh/config`

Click the import icon to read your existing SSH config. ShellPilot parses `Host`, `HostName`, `User`, `Port`, `IdentityFile` and `ProxyJump`, applies `Host *` wildcard defaults the way OpenSSH does, and shows a preview so you choose what to import. `ProxyJump` entries become jump hosts automatically, carrying the referenced host's key.

## Terminal

| Action | Shortcut |
|---|---|
| Search the scrollback | <kbd>Ctrl</kbd>+<kbd>F</kbd> |
| Zoom in / out / reset | <kbd>Ctrl</kbd>+<kbd>+</kbd> / <kbd>Ctrl</kbd>+<kbd>-</kbd> / <kbd>Ctrl</kbd>+<kbd>0</kbd>, or <kbd>Ctrl</kbd>+scroll |
| Copy selection | Select (copy-on-select), or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>C</kbd> |
| Paste | Right-click, or <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>V</kbd> |
| New session for this server | Double-click the server |
| Next / previous tab | <kbd>Ctrl</kbd>+<kbd>Tab</kbd> / <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>Tab</kbd> |
| Close tab | <kbd>Ctrl</kbd>+<kbd>W</kbd> |
| Command palette | <kbd>Ctrl</kbd>+<kbd>K</kbd> |

**Open files in your own editor.** In the Files view, right-click a remote file
and choose **Open in code** to edit it in VS Code (or whatever you configure in
Settings → Editor). Saving uploads it back to the server automatically — no
download/re-upload dance. The inline editor is still there for quick edits.

**Multi-line pastes ask first.** Pasting more than one line into a remote shell
shows a preview and a confirmation, because every line runs the moment it
lands. Single-line pastes go straight through.

Control keys such as <kbd>Ctrl</kbd>+<kbd>C</kbd>, <kbd>Ctrl</kbd>+<kbd>A</kbd> and <kbd>Ctrl</kbd>+<kbd>W</kbd> pass through to the remote shell, so `vim`, `nano` and bash line editing behave normally.

**Monitoring** is docked under the terminal rather than hidden in a separate tab. Expand it for live CPU, memory, disk and network. It samples only for the tab you are looking at, and shares the terminal's SSH connection.

### Resource alerts

When a host's CPU or memory reaches **80%** (configurable) you get a native OS
notification, repeated once a minute while it lasts and cleared automatically on
recovery. A count also appears in the status bar.

**Turning alerts on or off.** Go to **Settings → Monitoring** and use the
**Resource alerts** toggle. They are **on by default**; switching them off stops
any further CPU or memory notification being raised for any server. The setting
is global — it applies to all hosts, not one at a time — and it persists across
restarts.

Under it, **Alert threshold** sets how hard a host has to be working before it
counts as high: **70%**, **80%** (default), **90%** or **95%**. The same
threshold applies to both CPU and RAM. Raise it if busy-but-healthy servers are
noisy, lower it if you want earlier warning. The threshold buttons are greyed
out while alerts are switched off.

The third toggle, **Show monitor under the terminal**, is independent: it
controls the live CPU/memory/disk/network strip docked below the session, not
whether you get alerted.

They are designed not to interrupt you:
- Notifications are handled by the operating system, so they render **outside
  the window and never cover the terminal**
- The status-bar chip sits in the layout, not floating over your output
- Nothing steals focus, and nothing must be dismissed before you carry on
- Alerts are evaluated from metrics **already being sampled**, so switching them
  on adds no extra SSH load

## Command palette

Press <kbd>Ctrl</kbd>+<kbd>K</kbd> anywhere — including with focus inside a
terminal — to search everything and jump straight to it, without reaching for
the mouse.

![Command palette](docs/images/command-palette.png)

Start typing to filter across **every** category at once, then <kbd>Enter</kbd>
to run the highlighted entry.

| Group | What it does |
|---|---|
| **Actions** | Add Server, New Workspace, Import from `~/.ssh/config`, Open Fleet Monitor, Open Connections |
| **Settings** | Jump straight into Settings |
| **Workspaces** | Switch to any visible workspace by name |
| **Servers** | Open a terminal on any server in the current workspace — matches on name *and* on `user@host` |
| **Tunnels** | Jump to a tunnel, shown with its `listen → target` |

| Key | Action |
|---|---|
| <kbd>Ctrl</kbd>+<kbd>K</kbd> | Open the palette (also <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd>) |
| <kbd>↑</kbd> / <kbd>↓</kbd> | Move through results |
| <kbd>Enter</kbd> | Run the highlighted entry |
| <kbd>Esc</kbd> | Close |

Because the search also matches the subtitle, typing part of a hostname or a
username finds the server even when you cannot remember what you named it —
`ubuntu@10.20` will find it just as well as `Production API`.

The palette works **while you are in a session**: hit <kbd>Ctrl</kbd>+<kbd>K</kbd>
mid-command, switch workspace or open another server, and the shell you left
keeps running exactly where it was.

## Keyboard shortcuts

On macOS use <kbd>Cmd</kbd> in place of <kbd>Ctrl</kbd>.

Every shortcut below is **rebindable** in Settings → Keyboard Shortcuts, and
each one is listed there with the context it applies to:

| Context | Meaning |
|---|---|
| **Everywhere** | Works with focus anywhere, terminals included |
| **Outside terminals** | Skipped while a terminal has focus, so the key reaches the remote shell |
| **In terminals** | Only fires with focus inside a terminal |

That split is why the palette and the sidebar each have two bindings. A shell
owns <kbd>Ctrl</kbd>+<kbd>K</kbd> (kill-line) and <kbd>Ctrl</kbd>+<kbd>B</kbd>
(backward-char, and the tmux prefix), so those stay out of terminals and a
Shift-qualified twin covers you there instead. The command box in the title bar
follows your focus: it shows <kbd>Ctrl</kbd>+<kbd>K</kbd> normally and
<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> once you click into a terminal —
and it shows whatever you have rebound them to.

### General

| Shortcut | Action | Context |
|---|---|---|
| <kbd>Ctrl</kbd>+<kbd>K</kbd> | Command palette — search servers, workspaces, tunnels and actions | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> | Command palette | Everywhere |
| <kbd>Ctrl</kbd>+<kbd>B</kbd> | Show / hide the sidebar | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>B</kbd> | Show / hide the sidebar | Everywhere |
| <kbd>Ctrl</kbd>+<kbd>,</kbd> | Open Settings | Outside terminals |

### Tabs and sessions

| Shortcut | Action | Context |
|---|---|---|
| <kbd>Ctrl</kbd>+<kbd>N</kbd> | Add server | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>T</kbd> | New terminal on the current server | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>D</kbd> | Duplicate the current tab | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>W</kbd> | Close the current tab | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>Tab</kbd> / <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>Tab</kbd> | Next / previous tab | Everywhere |
| <kbd>Ctrl</kbd>+<kbd>\</kbd> | Split right | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>\</kbd> | Split down | Outside terminals |
| Double-click a server | Open an additional session in a new tab | |

### Workspaces

| Shortcut | Action | Context |
|---|---|---|
| <kbd>Ctrl</kbd>+<kbd>1</kbd> … <kbd>9</kbd> | Switch to the Nth workspace | Everywhere |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>N</kbd> | Manage workspaces | Everywhere |
| <kbd>Ctrl</kbd>+<kbd>L</kbd> | Lock the current workspace (password-protected ones only) | Outside terminals |

<kbd>Ctrl</kbd>+<kbd>1</kbd>…<kbd>9</kbd> is the one binding that cannot be
reassigned — the digit is the workspace number, not a key to map. Whether it
counts hidden workspaces is a setting.

### Views

| Shortcut | Action | Context |
|---|---|---|
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>E</kbd> | Open the Files view for the current tab | Everywhere |
| <kbd>Ctrl</kbd>+<kbd>M</kbd> | Open the Fleet Monitor | Outside terminals |
| <kbd>Ctrl</kbd>+<kbd>=</kbd> / <kbd>Ctrl</kbd>+<kbd>-</kbd> / <kbd>Ctrl</kbd>+<kbd>0</kbd> | Terminal font bigger / smaller / reset | Everywhere |
| <kbd>Ctrl</kbd>+scroll | Zoom in / out | In terminals |
| <kbd>F12</kbd> | Developer tools | |

### Terminal

| Shortcut | Action | Context |
|---|---|---|
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>C</kbd> or <kbd>Ctrl</kbd>+<kbd>Insert</kbd> | Copy selection | In terminals |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>V</kbd> or <kbd>Shift</kbd>+<kbd>Insert</kbd> | Paste | In terminals |
| <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>F</kbd> or <kbd>Ctrl</kbd>+<kbd>F</kbd> | Search the scrollback | In terminals |
| <kbd>Enter</kbd> / <kbd>Shift</kbd>+<kbd>Enter</kbd> | Next / previous match while searching | |
| Right-click | Paste (PuTTY / MobaXterm style) | In terminals |
| Select text | Copies automatically | In terminals |

Text selection copies on release, and pasting more than one line asks for
confirmation first.

### Customising shortcuts

Settings → Keyboard Shortcuts.

- **Rebind** — click a shortcut and press the keys you want. The combo is
  recorded exactly as pressed.
- **Clear** — press <kbd>Backspace</kbd> while recording to leave a command with
  no key at all. <kbd>Esc</kbd> cancels without changing anything.
- **Restore one** — a ↺ button appears next to any shortcut you have changed.
- **Reset all** — the Reset button puts every shortcut back to its default.
- **Conflicts** — two commands sharing a combo are flagged, but only when their
  contexts actually overlap. A terminal binding and an outside-terminal binding
  can safely share keys, because they never see the same key press.
- **Export / Import** — writes a small `shellpilot-shortcuts.json` holding only
  the shortcuts you changed, so it stays valid across upgrades. Importing
  replaces your current overrides.

Changes take effect immediately and are saved with the rest of your settings, so
they survive a restart.

### Deliberately not bound

| Key | Why |
|---|---|
| <kbd>Ctrl</kbd>+<kbd>R</kbd> | Reserved for the shell's reverse history search. ShellPilot never reloads on it — a reload would destroy every open session. |
| <kbd>Ctrl</kbd>+<kbd>C</kbd>, <kbd>Ctrl</kbd>+<kbd>A</kbd>, <kbd>Ctrl</kbd>+<kbd>E</kbd>, <kbd>Ctrl</kbd>+<kbd>O</kbd> | Passed to the remote shell so `vim`, `nano` and bash line editing behave normally. |
| <kbd>F5</kbd> | Blocked — it would reload the window and close every terminal. |

Nothing stops you binding one of these yourself, but scoping it to
**Everywhere** will take it away from the remote shell.

## Databases

ShellPilot speaks **PostgreSQL, MySQL, SQL Server, MongoDB and Redis**. Add a connection with discrete fields or a full connection string, browse tables and collections in the sidebar, and open each database in its own tab.

Every engine gets an **interactive shell** alongside the query editor:

- **MongoDB** — `show dbs`, `use x`, `db.users.find({...}).sort({...}).limit(n)`, aggregation pipelines, `ObjectId()` / `ISODate()` helpers
- **PostgreSQL / MySQL / SQL Server** — SQL plus psql-style meta commands: `\l`, `\dt`, `\d <table>`, `\du`, `\c <database>`
- **Redis** — commands passed straight through

**Databases over SSH:** pick a bastion in the *SSH tunnel* field and ShellPilot opens a forward automatically, so you can reach a database that is only routable from inside the network.

## SSH tunnels

Create local forwards, remote forwards or a SOCKS5 proxy over any saved server. Live connection counts are shown per tunnel, and a dropped SSH connection tears the listener down rather than leaving it accepting traffic that goes nowhere.

## Vault

An encrypted store for the credentials that do not belong to a single server — cloud logins, API keys, database URLs, licence keys.

- **AES-256-GCM**, with the key derived from your master password using **scrypt**
- The master password is **never stored**; a wrong one fails the authentication tag
- Entries hold a URL, username, password, notes, tags and **any number of custom key/value fields**, each markable secret
- **Search matches every field**, so you can find an entry by hostname or username, not just its title
- Plaintext exists only in memory while unlocked, and is wiped on lock and on quit

> There is **no recovery** if the master password is lost. That is the point.

## Backup & restore

Settings → **Backup & Restore** exports everything — workspaces, servers, databases, tunnels, stored credentials, the vault, workspace passwords and trusted host keys — into a **single passphrase-encrypted file**.

Credentials on disk are sealed with your OS keychain, which is tied to that machine and user, so a copied config folder is useless elsewhere. The backup unseals them and re-encrypts everything under your passphrase, which makes it **portable to any machine**.

A red **Backup out of date** indicator appears whenever your connections change, so you know when the last export no longer reflects reality.

## Settings

![Settings](docs/images/settings-general.png)

| Section | What it covers |
|---|---|
| **General** | Workspace-level preferences |
| **Appearance** | Theme (dark / light / system) and density |
| **Terminal** | Font family, **font size** (also <kbd>Ctrl</kbd>+<kbd>+</kbd>/<kbd>-</kbd>), cursor blink, scroll behaviour |
| **Connections** | Defaults for new connections |
| **SSH** | **How long an authenticated connection is kept** after its last session closes, and a live list of shared connections with a Disconnect button |
| **Security** | Credential storage, workspace locking, and the list of **trusted SSH host keys** with a Forget button |
| **SFTP** | File transfer preferences |
| **Monitoring** | **Resource alerts** (on by default), the CPU/memory threshold, and the monitor strip |
| **Editor** | Built-in file editor |
| **Keyboard Shortcuts** | **Rebind any shortcut**, clear it, reset to defaults, export/import, and whether <kbd>Ctrl</kbd>+<kbd>1</kbd>…<kbd>9</kbd> includes hidden workspaces |
| **Backup & Restore** | Encrypted export and import |
| **Notifications** | Alerts and toasts |
| **Advanced** | Diagnostics and resets |

The **SSH → Keep authenticated connection** setting is the one to know if your servers use two-factor auth: while a connection is alive, new sessions, file browsing and monitoring all reuse it, so you are asked for a code once rather than every time.

## Security

- Credentials are stored with **Electron `safeStorage`**, backed by DPAPI on Windows, Keychain on macOS and libsecret on Linux — never in plaintext
- The vault and backups use **AES-256-GCM** with **scrypt** key derivation
- Workspace passwords are stored as **scrypt verifiers** compared in constant time
- **Host keys are verified**: unknown hosts prompt with a SHA-256 fingerprint, and a changed key is refused outright
- Shell input is **parsed, never evaluated** — no `eval` on anything you type
- The renderer runs with `contextIsolation` on and `nodeIntegration` off, behind a strict Content-Security-Policy

Found a vulnerability? Please read [SECURITY.md](SECURITY.md) — do not open a public issue.

## FAQ

### What is ShellPilot?

ShellPilot is a free, open-source, cross-platform desktop application that combines an SSH
terminal, an SFTP file browser, an SSH tunnel manager, a multi-engine database client and an
encrypted secrets vault in a single window. It runs on Windows, macOS and Linux, is released
under the MIT licence, and needs no account.

### Which file should I download?

On Windows, `ShellPilot-x.y.z-setup.exe` unless you specifically want the
portable single-file build. On macOS, `-arm64.dmg` for an M1 or later and
`-x64.dmg` for an Intel Mac. On Linux, the `.AppImage` works on any
distribution, and the `.deb` is there if you would rather install through
`apt` on Debian or Ubuntu. The `.blockmap` and `latest*.yml` files on the
release page are build metadata — you never need to download them.

### Is ShellPilot really free?

Yes. It is MIT licensed, free for personal and commercial use, with no paid tier, no
session limit and no subscription. Nobody should be charging you for it.

### Is ShellPilot a good MobaXterm alternative?

It is the closest free alternative for most workflows, and unlike MobaXterm it runs on macOS
and Linux as well as Windows. There is no 12-session cap, no Professional Edition, and the
built-in database client and vault cover work MobaXterm sends you elsewhere for. MobaXterm's
X11 server and its bundled Cygwin toolchain have no equivalent here.

### Can it replace PuTTY?

For day-to-day SSH, yes — with saved sessions, folders, tabs, a searchable scrollback and
right-click paste in the PuTTY style. It also imports the servers you already have in
`~/.ssh/config`, so there is no re-typing. Serial-port connections are not supported.

### Is it an open-source Termius alternative?

Yes. The functional difference is sync: Termius syncs your servers through its cloud on a
paid plan, while ShellPilot keeps everything local and moves it between machines with a
passphrase-encrypted backup file. Nothing is uploaded and nothing phones home.

### Does ShellPilot support jump hosts and bastions?

Yes — unlimited chained hops per server, configured in the same dialog as the server itself.
Each hop can either reuse a saved server's credentials or define its own host, port, user and
key. `ProxyJump` entries in `~/.ssh/config` are imported as jump hosts automatically.

### Which databases does it support?

PostgreSQL, MySQL, SQL Server, MongoDB and Redis — each with a table/collection browser, a
query editor and an interactive shell. Any of them can be reached through an SSH tunnel, so a
database that is only routable from inside the network still works.

### How are my passwords and SSH keys stored?

In your operating system's own credential store through Electron `safeStorage` — DPAPI on
Windows, Keychain on macOS, libsecret on Linux. Nothing is written in plaintext. The vault
and encrypted backups add AES-256-GCM with scrypt key derivation on top of that.

### Does ShellPilot send any data anywhere?

No. There is no account, no telemetry, no analytics and no update ping. Every connection it
makes is one you configured.

### Does it work offline?

Yes, entirely. The app has no online dependency beyond the servers you connect to.

### Does it support two-factor authentication?

Yes. It answers keyboard-interactive challenges, and connections are shared between sessions,
file browsing and monitoring — so you enter a code once rather than once per tab.

### Why does Windows SmartScreen or macOS Gatekeeper warn about it?

The builds are not code-signed, because a signing certificate costs money a free project does
not have. On Windows choose *More info → Run anyway*; on macOS run
`xattr -cr /Applications/ShellPilot.app`. The source is public if you would rather build it
yourself.

### What are the system requirements?

Windows 10 or later, macOS 11 or later (Apple Silicon and Intel), or a modern 64-bit Linux
distribution. Building from source needs Node.js 20 or later.

### How do I move my setup to another machine?

Settings → Backup & Restore writes a single passphrase-encrypted file containing workspaces,
servers, databases, tunnels, credentials, the vault and trusted host keys. Restore it on the
new machine with the same passphrase.

### How can I help?

Star the repository, report bugs, or open a pull request — see [Contributing](#contributing).

## Contributing

Contributions are very welcome, whether that is code, documentation, a bug report or a translation. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for the architecture overview and development workflow, and please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

Good first issues are labelled [`good first issue`](https://github.com/ghauri01/ShellPilot/labels/good%20first%20issue).

## Licence

ShellPilot is released under the **[MIT Licence](LICENSE)** — free to use, copy, modify and share, for personal and commercial work alike, with no fee and no subscription.

**This tool is not sold.** It is given to the community. If someone is charging you for ShellPilot itself, you are being overcharged — download it here for free. The MIT licence does permit others to redistribute or build commercial products on top of it; that is a deliberate part of being genuinely open source, and it is what lets companies adopt it without a legal review.

Please do keep the copyright notice, and do not imply the maintainers endorse a fork.

---

<div align="center">

**Built for the DevOps community.** If ShellPilot saves you time, a ⭐ helps others find it.

[⬇ Download ShellPilot](https://github.com/ghauri01/ShellPilot/releases/latest) · [🐞 Report a bug](https://github.com/ghauri01/ShellPilot/issues/new/choose) · [📧 Contact](mailto:aliwaqarofficial@gmail.com)

*Keywords: open source SSH client, free SSH client for Windows, free MobaXterm alternative, PuTTY alternative, Termius alternative, SecureCRT alternative, Xshell alternative, MobaXterm for Mac, SSH client for macOS, SSH client for Linux, SSH terminal manager, SSH connection manager, SFTP client, SCP file transfer, SSH tunnel manager, port forwarding tool, SOCKS5 proxy client, bastion host client, jump host SSH client, ProxyJump GUI, ssh config importer, server monitoring tool, database GUI client, PostgreSQL client, MySQL client, MongoDB client, Redis client, SQL Server client, database over SSH tunnel, password manager for developers, encrypted secrets vault, AES-256-GCM vault, DevOps tools, sysadmin tools, self-hosted, no telemetry, no subscription, Electron SSH client, cross-platform terminal, Windows macOS Linux.*

</div>
