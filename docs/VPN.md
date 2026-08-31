# VPN and reverse-proxy tunnels

ShellPilot can carry your SSH sessions, SFTP browsing and database connections
over a VPN, and can publish a local port through an frp server. Three engines
are supported: **WireGuard**, **OpenVPN** and **frp**.

The design decision that shapes everything below: **the default mode needs no
administrator rights and changes nothing about your machine's networking.**

---

## The two modes, and why the default is the unusual one

Most VPN clients do one thing — create a network interface, take over your
routing table, and send some or all of your traffic through it. That needs root
or an administrator prompt, it rewrites DNS, and if the app is killed hard it
can leave your machine's networking in a state you have to fix by hand.

ShellPilot's default for WireGuard is different:

| | Userspace (default) | System (opt-in) |
|---|---|---|
| Administrator rights | **none** | prompt on every connect |
| Network interface | none — the TCP/IP stack runs inside ShellPilot | a real `utun`/`wg`/Wintun device |
| Your routing table | untouched | modified |
| Your DNS | untouched | replaced while connected |
| What goes through it | only what you point at it | whatever the routes say — but **not** a full tunnel; see below |
| If ShellPilot is killed | nothing to clean up | routes and DNS restored on next launch |
| Available for | WireGuard, everywhere | WireGuard on Linux and Windows. macOS is refused; OpenVPN is always system-mode |

In userspace mode the tunnel appears as **local listeners**: a SOCKS5 proxy on
`127.0.0.1`, and/or specific forwarded ports. Your browser and the rest of your
system carry on exactly as before. ShellPilot's own SSH and database
connections can be pointed through the tunnel individually.

That is a deliberate trade. It means a userspace WireGuard profile with
`AllowedIPs = 0.0.0.0/0` does **not** send all your traffic through the VPN —
it only means the tunnel is willing to carry anything you hand it. The UI says
so on the profile rather than letting you assume otherwise.

Turn on system mode when you need routes on the far network that the whole
machine can see. Everything else — reaching one bastion, one database, one
internal service — is better served by the default.

### What system mode does not do yet

Three limits, stated plainly because each of them is a refusal you will meet
rather than a bug you will hit:

- **A full tunnel (`AllowedIPs = 0.0.0.0/0` or `::/0`) is refused in system
  mode.** Sending *everything* through the tunnel means the encrypted packets
  going to the VPN server also match the route that was just created, and the
  machine takes itself off the network. Doing it safely needs the peer's own
  endpoint pinned outside the tunnel — a firewall mark and a routing rule on
  Linux, a host route via the previous gateway elsewhere. That is route surgery
  on a live machine, and it has not been verified against a real kernel here, so
  ShellPilot refuses it and says why rather than shipping something plausible.
  Split routes (`10.0.0.0/8`, `192.168.0.0/16`, and so on) work normally.
  **Userspace mode is unaffected** — `0.0.0.0/0` there is harmless, because
  nothing is routed system-wide in the first place.
- **macOS system mode is blocked.** It needs a privileged helper, which needs an
  Apple Developer ID this project does not have. Userspace WireGuard works
  fully on macOS and needs no permission at all.
- **Windows system mode needs `wintun.dll`**, which ShellPilot does not bundle —
  install [WireGuard for Windows](https://www.wireguard.com/install/) and it is
  provided. See [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) for why
  it is not included. Userspace mode needs nothing.

None of these affect the default. Userspace WireGuard runs on all three
platforms with no administrator rights and no driver.

---

## WireGuard

Runs on `shellpilot-netd`, a small Go program shipped with ShellPilot that
embeds the official `wireguard-go` implementation and a userspace TCP/IP stack.
It is MIT-licensed like the rest of ShellPilot, and is built from source in
this repository (`sidecar/netd/`).

### Importing a profile

Paste or drop a standard `wg-quick` `.conf`. ShellPilot parses it, does not
keep the file, and re-derives everything it runs from the parsed model.

**`PostUp`, `PreUp`, `PostDown` and `PreDown` are rejected.** Those are
`wg-quick` shell hooks — arbitrary commands that run as root. A config using
them expects those side effects, so silently dropping them and reporting
success would be a lie about what you are connected to. The import fails and
quotes the offending line.

### Reading the status

The number that matters is the **handshake age**. WireGuard rekeys well inside
180 seconds whenever anything is flowing, so:

- handshake under 180s → **connected**
- process up but handshake older than 180s → **degraded** (amber)
- no handshake at all after 30s → **handshake timeout**

"Degraded" is the state most WireGuard UIs do not show, and it is the one worth
knowing about: the tunnel is up and is not passing traffic. Usually that means
the endpoint address is wrong, UDP is blocked, or you are behind a captive
portal you have not signed into yet.

### Known limits

- **WireGuard is UDP and cannot go through an HTTP proxy.** If your network
  forces one, WireGuard will not work there; use OpenVPN over TCP instead.
  ShellPilot says this rather than timing out mysteriously.
- If a profile carries no IPv6 (`AllowedIPs` without `::/0`) and your machine
  has IPv6, IPv6 traffic bypasses the tunnel. ShellPilot warns at import.

---

## OpenVPN

**OpenVPN is not bundled with ShellPilot.** It is GPL-2.0 licensed and
ShellPilot is MIT; distributing the binary would create a corresponding-source
obligation this project cannot honestly maintain across every platform, in
perpetuity. See [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md).

So you install OpenVPN yourself and ShellPilot drives the copy you already
have, over OpenVPN's own management interface — the same mechanism the official
GUI uses.

| Platform | Install |
|---|---|
| Windows | the official OpenVPN MSI (installs the Interactive Service too — see below) |
| macOS | `brew install openvpn` |
| Debian/Ubuntu | `apt install openvpn` |
| Fedora | `dnf install openvpn` |

ShellPilot looks in a fixed list of standard locations, and on POSIX also on
`PATH`. **It never searches `PATH` on Windows**, where `PATH` and
current-directory search is a well-known way to get the wrong `openvpn.exe`
run. You can point at a specific binary explicitly; ShellPilot records its path,
version and SHA-256 in the audit log the first time it is used and whenever it
changes.

### Administrator rights

OpenVPN has no userspace mode — it needs a TUN device, so it needs elevation.
ShellPilot asks per connect and never stores the answer:

- **Windows**: if the OpenVPN Interactive Service is present (it comes with the
  official MSI) ShellPilot uses it and there is no UAC prompt. Otherwise you get
  one UAC prompt per connect.
- **macOS**: the standard macOS administrator dialog. ShellPilot never sees,
  stores or transmits your password — macOS collects it.
- **Linux**: `pkexec`, falling back to `sudo`. ShellPilot does not install a
  helper, does not use `setcap`, and does not create a service.

Dismissing the prompt is a normal outcome, not an error.

### `.ovpn` files are executable content — read this part

An OpenVPN configuration file can run programs. `up`, `down`, `route-up`,
`ipchange`, `tls-verify`, `client-connect`, `learn-address`,
`auth-user-pass-verify` and `plugin` all execute something, and the `up` script
runs *before any server is contacted* — so a malicious profile needs no server
at all, just for you to open it. This is a documented attack class, not a
hypothetical.

ShellPilot therefore **never hands your file to OpenVPN**. It parses the file
into a typed model and generates a fresh configuration from that model. Three
outcomes per directive:

1. **Kept** — the connection settings, ciphers, remotes, certificates.
2. **Dropped, and listed for you** — things that are noise or mildly unsafe:
   `verb` above 4 (a log flood), `comp-lzo`/`compress` (compression under TLS in
   a VPN is a known plaintext-recovery weakness), anything unrecognised.
3. **Rejected — the whole import fails** — anything that runs a program, reads
   or writes an arbitrary file, or re-points the management interface. The
   offending line is quoted back to you.

A rejection is not ShellPilot being fussy. A profile that uses `up` expects
those side effects; connecting without them would be a different thing than the
one you were given, and you would not know.

Certificates referenced by path are read **only** from the directory you
imported from — no absolute paths, no `..`, no symlinks leading out.

A clean local file is only half of it: a hostile *server* can push options too.
ShellPilot always runs OpenVPN with `--script-security 0` and a set of
`--pull-filter reject` rules so a pushed `up` or `script-security` is refused at
the source.

### Split tunnelling

`redirect-gateway` is **off by default**, even when the profile asks for it.
Downloading a profile should not silently reroute your entire machine.
ShellPilot adds `--route-nopull` and ignores a pushed `redirect-gateway` unless
you explicitly turn full-tunnel on for that profile.

### One-time codes

Profiles using a static challenge (`SC:` on the password request) prompt for the
code each time. The code is never stored and never pre-filled. With
`--auth-nocache` — which ShellPilot always sets — a reconnect asks again. That
is expected behaviour, not a failure, and ShellPilot waits in
"authenticating" rather than dropping the connection if you are away from the
keyboard.

---

## frp — publishing a local port

frp is the opposite direction from a VPN: instead of reaching in, it makes
something on your machine reachable **from** an frp server. ShellPilot bundles
`frpc` v0.71.0 (Apache-2.0, built from source).

This inverts ShellPilot's usual threat model, so it is gated accordingly:

- Every proxy has a confirmation whose label is literal: *"Make 127.0.0.1:5432
  reachable from frp.example.com."* You cannot start the profile until every
  proxy is ticked.
- Local address is forced to `127.0.0.1` unless you deliberately change it.
- TLS to the frp server is on by default.
- The `unix_domain_socket` and `static_file` plugins are **not offered**.
  Pointing `unix_domain_socket` at `/var/run/docker.sock` is root-equivalent
  remote code execution; `static_file` exposes a directory. Configs using them
  are rejected on import.
- **An AI agent can never start an frp profile.** See below.

Configuration is generated from the typed editor, not pasted. Importing an
existing `frpc.ini` or `.toml` runs it through the same allowlist and shows you
what was dropped.

frp exposes no client-side byte counters, so there is no rx/tx figure for an frp
profile. The per-proxy status table is the telemetry, and frp's own error text
(`port already used`, `proxy name already exists`) is shown verbatim because it
is already the actionable thing.

---

## Using a VPN for SSH and databases

A server or database connection can name a VPN profile. When you connect:

1. ShellPilot starts the profile if it is not already up and waits for it.
2. In userspace mode it opens a short-lived local forward into the tunnel and
   dials that. In system mode the route already exists and it just dials.
3. If the VPN fails to come up, you see **the VPN's** error, not a downstream
   connection timeout. An unexplained `ETIMEDOUT` is the worst failure mode this
   kind of feature has.

Stopping a VPN that live sessions are riding asks first, naming the count. On
confirm, the sessions are closed before the transport, so nothing observes a
half-dead network. If the tunnel drops on its own, dependent sessions are closed
with an explicit reason — there is no silent fallback to an unprotected path.

### There is no kill switch

ShellPilot tears down what it started when a tunnel drops. It does **not**
install firewall rules to block all other traffic, and it does not claim to.
A real fail-closed kill switch means OS-level firewall state that has to survive
the app being killed, and calling anything less by that name would be
misleading.

---

## Secrets

Keys, certificates, passwords and tokens live in the encrypted vault, as a `VPN
profile` entry. They travel with an encrypted backup exactly as an SSH key does.
Starting a profile while the vault is locked prompts you to unlock it — it never
falls back to an unencrypted copy, because there isn't one.

Nothing sensitive is passed on a command line, where any other process on the
machine can read it:

| Engine | How the secret reaches it |
|---|---|
| WireGuard | written to the sidecar's stdin; never touches disk |
| OpenVPN — password, OTP, key passphrase | the management channel |
| OpenVPN — config and certificates | the process's stdin on Linux, where `pkexec` and `sudo` fork the engine so a pipe reaches it. On macOS and Windows the administrator prompt starts the engine detached from ShellPilot, so there is no pipe to inherit: the config goes into a `0600` file inside a `0700` directory, is deleted on stop, and any left by a crash are swept at the next launch |
| frp | the child process's environment (`/proc/<pid>/environ` is owner-only; a command line is world-readable) |

Engine output is scrubbed before it is stored, not before it is shown — the log
you can read has already had keys removed from it. One consequence: WireGuard
*public* keys are redacted too, because nothing in a log line distinguishes a
public key from a private one. ShellPilot shows public keys from the profile
itself instead.

---

## AI agents and VPN control

Granting an AI access group the **VPN & reverse proxies** capability lets an
agent start and stop VPN profiles you have already defined. That changes which
network your subsequent SSH and database sessions traverse, so:

- The capability is **denied by default** for every access group, including
  Full Access.
- **Starting a VPN always asks for approval**, even for a group where the
  capability is set to allow.
- **An agent can never start an frp profile.** That refusal is hard-coded, not a
  policy setting, because an frp proxy makes one of your local ports reachable
  from a remote server.
- There is no tool to create or edit a VPN profile. An agent can only run one
  you wrote.

See [AI-SECURITY.md](AI-SECURITY.md).

---

## Troubleshooting

| What you see | What it usually means |
|---|---|
| WireGuard connects but nothing works; handshake never happens | Wrong endpoint, UDP blocked, or a captive portal you have not signed into |
| Amber "degraded" after working fine | The tunnel stopped passing traffic — often a network change; it usually recovers |
| Large transfers stall, small ones work | MTU. Try 1280 |
| "The program that runs this tunnel could not be found" | For OpenVPN, install it. For WireGuard or frp, reinstall ShellPilot — antivirus sometimes quarantines bundled binaries |
| "does not match its expected checksum" | The bundled binary was altered. Reinstall; do not override |
| OpenVPN asks for the code again after a reconnect | Expected. Codes are never cached |
| frp says "port already used" | Another proxy — possibly someone else's — already claims that remote port on that frp server |

The per-profile log drawer holds the engine's own output, already scrubbed of
secrets. It is the first place to look for anything not in this table.
