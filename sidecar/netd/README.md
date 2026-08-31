# shellpilot-netd

ShellPilot's WireGuard sidecar. A single static Go binary that speaks
newline-delimited JSON. By default it needs **no root, on any platform**;
`--privileged` opts into a real TUN device and does need root, per launch,
with nothing installed.

## Why it exists

A conventional WireGuard client creates a TUN device, rewrites the route
table and changes the system resolver. All three need elevation, and on
macOS and Windows they need an installed privileged helper — a launchd job or
a Windows service — which is a permanent piece of attack surface for a
desktop app that is only occasionally used as a VPN client.

`shellpilot-netd` runs the entire TCP/IP stack in-process on gVisor netstack
instead. There is no kernel interface, so there is nothing to elevate for:
the tunnel is exposed to the rest of the app as ordinary loopback listeners
(SOCKS5, HTTP CONNECT, and fixed local forwards). ShellPilot's SSH and
database code already knows how to consume a `{ port, close }` local
forward — see `openEphemeralForward` in `src/main/services/tunnel.ts` — so
"database over WireGuard" needs no database driver to learn about SOCKS.

The trade is honest and worth stating in the UI: **only traffic ShellPilot
sends through these listeners goes through the tunnel.** A peer configured
with `AllowedIPs = 0.0.0.0/0` does not route the machine's traffic here, and
we do not pretend otherwise (edge case E17 in the plan).

The same binary also has a **system mode** (`--privileged`) that does create a
real interface. It is a different device and a different transport, not a
different protocol — see [System mode](#system-mode---privileged) below.

## Protocol

One JSON object per line, in both directions.

**stdout carries protocol traffic and nothing else.** A single stray
`fmt.Println` desynchronises the parent's parser for the rest of the process
lifetime. Diagnostics go out as `log` events; genuine pre-protocol failures
(an unknown argv flag) go to stderr.

### Requests and responses

```jsonc
// →
{"id":"7","method":"wg.up","params":{ … }}
// ← success
{"id":"7","ok":true,"result":{ … }}
// ← failure
{"id":"7","ok":false,"error":{"code":"config-invalid","message":"…"}}
```

`id` is opaque and echoed verbatim. **Handlers run concurrently, so responses
arrive in completion order, not request order** — match them by `id`. The one
ordering guarantee: when the `shutdown` response arrives, every request sent
before it has already been answered.

`error.code` is always a member of the TypeScript `VpnErrorCode` union in
`src/shared/vpn.ts`. `protocol_test.go` reads that file and fails if netd can
emit a code the union does not contain, so the two cannot drift apart.

Codes this binary emits: `config-invalid`, `already-running`, `port-in-use`,
`permission-denied`, `dns-failure`, `network-unreachable`, `handshake-timeout`,
`unsupported`, `internal`.

### Events

Unsolicited messages carry `event` and no `id` — that is how the reader tells
them apart from responses.

```jsonc
{"event":"wg.state","data":{"tunnelId":"vpn-abc","state":"connected","assignedIp":"10.0.0.2","remoteEndpoint":"203.0.113.9:51820"}}
{"event":"log","data":{"level":"error","msg":"…","tunnelId":"vpn-abc"}}
```

`state` is a member of the TS `VpnState` union: `starting`, `connected`,
`degraded`, `error`, `stopped`. Events fire only on an actual change.

### Methods

| Method | Params | Result |
|---|---|---|
| `ping` | — | `{version, goVersion, buildSha}` |
| `wg.up` | see below | `{tunnelId, listeners[], assignedIp}` |
| `wg.stats` | `{tunnelId}` | see below |
| `wg.forward.open` | `{tunnelId, host, port, bindHost?, bindPort?}` | `{forwardId, bindHost, listenPort}` |
| `wg.forward.close` | `{forwardId}` | `{forwardId}` |
| `wg.down` | `{tunnelId}` | `{tunnelId}` |
| `auth` | `{nonce}` | `{authenticated, privileged, version, buildSha}` — **`--privileged` only, and only as the first message** |
| `shutdown` | — | `{stopping:true}`, then exit 0 |

**`wg.up`:**

```jsonc
{"id":"7","method":"wg.up","params":{
  "tunnelId":"vpn-abc",
  "iface":{
    "privateKey":"<base64>",          // 32 bytes; converted to hex for the UAPI
    "addresses":["10.0.0.2/32"],      // CIDR or bare address
    "dns":["10.0.0.1"],               // resolved INSIDE the tunnel
    "mtu":1420,                       // default 1420, range 576-9000
    "listenPort":0                    // optional; 0/absent picks a UDP port
  },
  "peers":[{
    "publicKey":"<base64>",
    "presharedKey":"<base64>",        // optional
    "endpoint":"vpn.example.com:51820",
    "allowedIps":["0.0.0.0/0","::/0"],
    "persistentKeepalive":25
  }],
  "listeners":[
    {"kind":"socks5","bindHost":"127.0.0.1","bindPort":1080},
    {"kind":"http","bindHost":"127.0.0.1","bindPort":0},
    {"kind":"forward","bindHost":"127.0.0.1","bindPort":0,
     "targetHost":"db.internal","targetPort":5432}
  ],
  "logLevel":"error",                 // "error" (default) | "debug" | "silent"
  "ifaceName":"wg-abc"                // system mode only; see below
}}
```

- **`wg.up` does not wait for a handshake.** It returns as soon as the device
  is up and the listeners are bound. Blocking would make a captive-portal
  network (E22) look like a hang; the handshake is reported through `wg.state`
  and `wg.stats` instead.
- **`bindPort: 0` is supported and the actual bound port is always returned**
  in `result.listeners[].bindPort`.
- **`bindHost` is echoed back verbatim, never normalised** (E25). If the
  caller asks for `0.0.0.0` the response says `0.0.0.0`, so the TS side can
  warn that the proxy is reachable from the LAN. Silently rewriting it to
  loopback would be worse: the user would believe the setting took effect.
  The default when absent is `127.0.0.1`.
- A listener that fails to bind fails the whole `wg.up` and the tunnel is torn
  down. A half-configured tunnel that reports success is worse than none.
- `logLevel` is an addition to the plan's §6.1 shape. wireguard-go's device
  logger emits a line per worker goroutine at startup — roughly sixty log
  events per `wg.up` competing with responses on the same pipe. Verbose is
  therefore opt-in per tunnel; errors always get through.

**`wg.stats` result:**

```jsonc
{"tunnelId":"vpn-abc","rxBytes":2201316,"txBytes":148900,
 "lastHandshakeUnixSec":1717000000,"remoteEndpoint":"203.0.113.9:51820",
 "assignedIp":"10.0.0.2","peers":1,"sampledAt":1717000123456}
```

`lastHandshakeUnixSec` is an **absolute unix second, not an age** (E63). The
parent computes the age itself against a monotonic base, so a system clock
jump while connected cannot produce a nonsense or negative age. The field is
**absent when there has never been a handshake** (E22, E27) — netd does not
synthesise a zero age, and the parent decides when "never" becomes
`handshake-timeout`. `rxBytes`/`txBytes` are summed across peers; the
handshake and endpoint come from the peer with the most recent handshake.

netd also emits `handshake-timeout` on `wg.state` if 30 s pass with no
handshake at all, with the plan's wording: *"No response from &lt;endpoint&gt;.
Check the endpoint address and that UDP :&lt;port&gt; is not blocked."*

### Lifecycle

`shutdown`, `SIGTERM`/`SIGINT`, and **stdin reaching EOF** all do the same
thing: close every listener, cancel every relay, wait for the goroutines,
close the devices, exit 0.

The stdin-EOF case is the orphan safety net and is not optional. If the
Electron main process dies without saying `shutdown`, netd would otherwise sit
there holding listen ports and a live tunnel until the machine reboots.

`wg.down` blocks until teardown is complete, so the caller may assume the
ports are free the moment it returns — a `wg.down` immediately followed by a
`wg.up` on the same ports works.

### Secrets

Keys arrive **only on stdin**, never on argv and never in the environment.
argv is world-readable through `ps aux` on POSIX and
`Get-CimInstance Win32_Process` on Windows; nothing here ever touches disk.

Every string leaving the process passes through `redact()`, which scrubs
44-char base64 and 64-char hex key shapes. Private, public and preshared keys
are indistinguishable by shape, so all three are scrubbed — a redacted public
key costs a support ticket, a leaked private key costs the tunnel. Show public
keys in the UI from the model, never scraped from a log. Rejected key material
is never quoted back in an error message either, which is why `json.Unmarshal`
errors are replaced rather than passed through: they quote the offending value.

## System mode (`--privileged`)

```
shellpilot-netd --privileged --socket <path> --nonce-file <path>
```

Creates a **real TUN device** with `tun.CreateTUN(name, mtu)` instead of a
gVisor netstack, gives it the interface addresses and brings it up. Everything
after the device — the UAPI string, `IpcGet` stats, the handshake monitor, the
teardown, the NDJSON dispatch — is the same code as userspace mode. The
protocol is not forked.

This mode requires root. **ShellPilot never installs anything to get it:** no
setuid bit, no `setcap`, no launchd plist, no systemd unit, no Windows
service, no privileged helper. The app asks the OS for administrator rights
once per launch and those rights die with the process, so uninstalling
ShellPilot leaves nothing behind that can still become root. Do not add an
installed helper; a design that appears to need one needs a different design.

### The control channel, and why it is a socket

An elevated child has no stdio connected to us on two of the three platforms
(`osascript` starts the command detached; UAC goes through `ShellExecute`,
which cannot redirect a pipe). So the privileged process **listens** and the
unprivileged parent connects:

1. The parent creates a `0700` directory, writes a **32-byte nonce** as 64 hex
   characters into a `0600` file inside it, and picks a random socket name in
   the same directory. Only the *paths* go on the command line — argv is
   world-readable.
2. The privileged process reads the nonce file, **deletes it**, binds the unix
   socket (`0600`, in a directory it re-chmods to `0700`) and waits up to 60 s
   for exactly one connection. The listener is closed the moment it accepts:
   there is no second client.
3. The **first line on the connection must be an `auth` request carrying that
   nonce**, within 10 s and under 4 KiB. It is compared in constant time.
   Wrong, absent, malformed, oversized or late: the process replies
   `permission-denied` — with no hint as to which part was wrong — and exits
   **4**. A root process listening unauthenticated is worse than no feature.
4. When that connection ends, the process shuts down. This is the socket
   equivalent of stdin EOF in userspace mode, and it is the orphan safety net:
   closing the tunnel destroys the TUN device, and destroying the device takes
   every route bound to it with it.

On Windows the file-mode half is weaker — `chmod` cannot express `0700` there
and the socket inherits the directory ACL — which is exactly why the nonce
exists rather than relying on file modes.

Exit codes: **2** bad arguments, **3** setup refused (not root, unreadable
nonce, unusable socket path), **4** authentication failed, **0** normal.

### Differences in `wg.up`

- **`ifaceName` is required** on Linux and Windows and validated before it
  becomes an argument to a command running as root (Linux: ≤ 15 characters,
  `[A-Za-z0-9_.-]`; Windows: an adapter display name, no quotes or control
  characters). On **macOS it is ignored and forced to `utun`**, because the
  kernel allocates the number.
- **The result carries `ifaceName`: the name the kernel actually chose.**
  Routes and DNS are applied against that value. Guessing `utun4` is how
  system mode silently routes nothing.
- **Listeners are refused**, with `config-invalid`. They are a userspace
  concept — they exist because netstack has no other way in — and in system
  mode the route table already carries the traffic. Refused rather than
  ignored: a listener silently dropped is a port the caller believes is open.
- Addresses keep their prefix length here (`10.0.0.2/24` and `10.0.0.2/32`
  are different statements about what is on-link); a bare address means `/32`
  or `/128`.

### What configures the interface

The addresses, the link state and (on Windows) the MTU are applied by
executing the operating system's own tools — `ip` on Linux, `ifconfig` on
macOS, `netsh` on Windows — rather than by driving netlink or winipcfg from
Go. Three reasons: it adds no dependency, so the sidecar stays a pure-Go
`CGO_ENABLED=0` cross-compile to six targets from one machine, which is what
makes `scripts/build-sidecar.sh` work at all; it is the same mechanism the
TypeScript routing and DNS managers already use, so there is one convention to
audit rather than two; and the arguments are literal `exec` argv with no shell
anywhere. The cost — a dependency on iproute2 / netsh being present — is
reported as a coded error rather than a mystery.

Tools are resolved from a **fixed list of absolute paths**, never from `PATH`:
this process is root, and an attacker-writable directory early in an inherited
`PATH` would otherwise decide what `ip` means.

`tun.CreateTUN` already sets the MTU on Linux and macOS; Wintun only records
it in userspace, so Windows sets it with `netsh` explicitly.

### Refusals

| Situation | Answer |
|---|---|
| Not running as root (POSIX) | stderr + exit 3. Not a panic. |
| Linux without `/dev/net/tun` (container, hardened kernel) | `permission-denied` naming `/dev/net/tun` and pointing at userspace mode (E06) |
| Windows without `wintun.dll` | `unsupported`, naming the missing driver |
| `ip` / `ifconfig` / `netsh` not installed | `unsupported`, naming the tool |
| Listeners requested | `config-invalid` |

### What has never been run

The privileged path is **not exercised end to end by any automated test.**
`privileged_test.go` covers the flag contract, the nonce file, the socket
modes, the authentication handshake over a real unix socket, the refusal when
not root, the interface-name rules for all three platforms and the device
error mapping — all of which run unprivileged. `tun.CreateTUN` and the
`ip`/`ifconfig`/`netsh` invocations need root and a real kernel, and no test
here fakes them. macOS system mode is refused by the driver (E02), so
`configureDarwin` is unreachable from the app.

## Building

```bash
bash scripts/build-sidecar.sh              # all six targets
bash scripts/build-sidecar.sh darwin-arm64 # one, while iterating
```

Output lands in `resources/bin/<platform>-<arch>/shellpilot-netd[.exe]`, using
**Node's** platform/arch names (`darwin-x64`, `darwin-arm64`, `linux-x64`,
`linux-arm64`, `win32-x64`, `win32-arm64`) rather than Go's, because the
TypeScript resolver looks the binary up with
`` `${process.platform}-${process.arch}` `` and electron-builder's
`${platform}-${arch}` macro expands to the same strings.

The script's last step merges hashes into `resources/bin/manifest.json` via
`scripts/update-bin-manifest.mjs`, which is shared with `scripts/build-frpc.sh`
and merges by binary name so the two scripts are order-independent.

> **CI must run `scripts/build-sidecar.sh` (and `scripts/build-frpc.sh`)
> before `electron-builder`.** `electron-builder.yml` pulls
> `resources/bin/${platform}-${arch}` in through `extraResources`, and a
> missing directory is silent at package time — it surfaces only at runtime,
> as every profile reporting `binary-missing`.

`resources/bin/` is gitignored except for `manifest.json`: the binaries are
build output, the manifest is committed so a clone knows which hashes it
expects.

`CGO_ENABLED=0` is load-bearing rather than a preference. It makes this a pure
cross-compile with no per-platform C toolchain and keeps the binary from
picking up a host libc. Nothing in the dependency tree needs cgo — netstack is
pure Go, which is the whole reason this design needs no root. `-trimpath` and
an empty `-buildid` make the output reproducible, which is what makes the
recorded SHA-256 mean anything.

## Developing

```bash
cd sidecar/netd
go vet ./... && go test ./... && go build ./...
go test -race ./...
go test -short ./...   # skips the tests that stand up real devices
```

`tunnel_test.go` stands up two real userspace WireGuard devices in-process and
makes them handshake over loopback UDP, with a TCP echo service and a DNS
responder living inside the server node's netstack. That last part is how
`TestTunnelSocks5ResolvesDomainInsideTheTunnel` proves the DNS claim below:
`echo.test` exists only inside the tunnel, so the test could not pass if netd
had resolved it on the host.

Drive the built binary by hand:

```
$ printf '%s\n' '{"id":"1","method":"ping"}' '{"id":"2","method":"shutdown"}' \
    | ./resources/bin/darwin-arm64/shellpilot-netd
{"id":"1","ok":true,"result":{"version":"0.4.4","goVersion":"go1.26.5","buildSha":"b35037e"}}
{"id":"2","ok":true,"result":{"stopping":true}}
```

`--version` prints `{"version","goVersion","buildSha"}` and exits; that is
what the TypeScript driver's `probe()` calls before it will trust the binary
with a key.

## DNS

Hostnames given to a listener are resolved with `tnet.LookupContextHost`,
which speaks DNS to the servers on `iface.dns` **over the tunnel**.

This is the point, not an implementation detail. A SOCKS5 client that sends a
domain-type address must not cause a lookup on the host resolver, because that
lookup travels in the clear and leaks exactly the thing the tunnel exists to
hide. `net.Dial` anywhere in that path would be a DNS leak, not a shortcut.

The one deliberate exception is the **peer endpoint**, which is resolved on
the host resolver before the device is configured. It has to be: the peer sits
on the outside of a tunnel that does not exist yet. Doing it explicitly rather
than inside `IpcSet` also buys a specific `dns-failure` instead of an opaque
device error.

## Deviations from the plan

Five, all additive:

1. **`lastHandshakeUnixSec` instead of `lastHandshakeSec`.** The TS
   `VpnStats.lastHandshakeSec` is documented as an *age*; §6.1 and E63 want an
   *absolute* value so the parent can age it against a monotonic base. Two
   different meanings under one name is how a clock-jump bug gets written, so
   the wire field is named for what it carries and the driver converts.
2. **`logLevel` on `wg.up` params.** Not in §6.1. Explained above.
3. **`ifaceName` on `wg.up` params and on its result.** §6.1 does not name a
   field for it. System mode needs both halves: a name to ask for, and the
   name the kernel actually gave, because on macOS they are never the same and
   routes applied against the wrong one apply against nothing.
4. **A `--nonce-file` rather than the nonce on the already-elevated channel.**
   §6.1 says the nonce is "passed over the already-elevated channel". Only
   Linux's `pkexec`/`sudo` route can carry a pipe to the elevated child at all
   — `Elevator.carriesStdin` is false everywhere else — so on Windows there is
   no such channel. A `0600` file in a `0700` directory, whose *path* (never
   its contents) goes on the command line and which the privileged process
   deletes on first read, is the one mechanism that works identically on both
   open platforms.
5. **No `ping` listener kind.** §6.1 sketches `tnet.Dial("ping4", host)` for
   latency. `VpnStats.latencyMs` is optional and nothing consumes it yet, so
   it is not implemented rather than half-implemented; netstack's `PingConn`
   is there when it is wanted.

UDP `ASSOCIATE` and `BIND` are likewise unimplemented in the SOCKS5 server —
both answer `0x07 command not supported`, which every client understands. The
HTTP proxy implements `CONNECT` only and answers `501` to anything else:
absolute-form proxying would mean this process parsing and re-emitting user
traffic, and every client that matters issues `CONNECT` for `https://`.

## Licensing

`shellpilot-netd` is part of ShellPilot and is Apache-2.0, like the rest of the
repository.

| Dependency | Licence |
|---|---|
| `golang.zx2c4.com/wireguard` (wireguard-go) | MIT |
| `gvisor.dev/gvisor` (netstack) | Apache-2.0 |
| `golang.org/x/{crypto,net,sys,time}` | BSD-3-Clause |
| `github.com/google/btree` | Apache-2.0 |
| `golang.zx2c4.com/wintun` | MIT |

All permissive; bundling the binary carries no obligation beyond preserving
the copyright and permission notices. `scripts/build-sidecar.sh` writes the
resolved dependency list to `resources/licenses/shellpilot-netd/VERSION`, and
`THIRD-PARTY-NOTICES.md` lists the bundled binaries and their licences.

This is the specific reason WireGuard is bundled and OpenVPN is not: OpenVPN
is GPL-2.0, and distributing the binary would trigger a perpetual
corresponding-source obligation per platform. See section 4 of
`docs/plans/vpn-tunnel-clients.md`.

WireGuard is a registered trademark of Jason A. Donenfeld.

## A note on the module proxy

`go.sum` was generated against the public checksum database. If your
`GOPROXY` points at a mirror whose `sumdb` endpoint is unavailable, module
fetches fail with a 502 from `.../sumdb/sum.golang.org/supported`. Build with
`GOPROXY=https://proxy.golang.org,direct`, or configure the mirror's sumdb
proxy. The committed `go.sum` pins every hash either way.
