# VPN & Tunnel Clients for ShellPilot

> **Status: partly superseded, 2026-08-31.** This is the design record as written,
> kept unedited below so the reasoning stays readable. One decision has since been
> reversed: **OpenVPN is now bundled on macOS and Linux.** The §3 corresponding-source
> obligation this document treats as disqualifying is real, and is discharged by
> publishing the exact pinned source tarball as a release asset; the aggregation
> question is settled by running `openvpn` as a separate process over its management
> socket (GPL-2.0 §2), so ShellPilot stays MIT. Windows is unchanged and still needs a
> system install, for driver reasons rather than licence ones. Wintun's proprietary DLL
> is also now bundled. See `docs/VPN.md` and `THIRD-PARTY-NOTICES.md` for what actually
> ships; where they disagree with this file, they are right.

## 1. Executive summary + recommendation

Ship **WireGuard first, in fully userspace mode, with no admin rights** — a single small MIT Go sidecar (`shellpilot-netd`) that statically links `wireguard-go` plus its gVisor `tun/netstack` TCP/IP stack and exposes each tunnel as a local SOCKS5 listener and/or ephemeral port-forwards, driven over newline-delimited JSON on stdin/stdout so private keys never touch argv or disk. This maps one-to-one onto the SOCKS/local-forward UX the app already has (`src/main/services/tunnel.ts:250-262`) and onto `openEphemeralForward` (`src/main/services/tunnel.ts:313`), which means SSH-over-VPN and DB-over-VPN fall out almost for free. **Bundle `frpc` (Apache-2.0) and drive it through its documented admin API**; **never bundle `openvpn`** — it is GPL-2.0 and shipping the binary would saddle an MIT volunteer project with a perpetual per-platform corresponding-source obligation, so detect a system install instead and drive it through the management interface. Model VPN as a **separate `VpnProfile` domain**, not an extension of `TunnelKind` — `TunnelConfig` (`src/shared/tunnel.ts:5-16`) is SSH-shaped and the renderer already has a `vpns` slice waiting for a real type (`src/renderer/src/types.ts:82-97`, `src/renderer/src/store/app.ts:93`). Treat every imported `.ovpn`/`.conf`/`.toml` as hostile input: parse into a typed model against a strict allowlist and **re-emit** a config we generated, because `up`/`down`/`script-security` in a `.ovpn` and `unix_domain_socket` in an frp TOML are both remote-code-execution primitives.

---

## 2. Current-state analysis

### 2.1 The existing tunnel domain is SSH-shaped

| Concept | Location | Notes |
|---|---|---|
| `TunnelKind` | `src/shared/tunnel.ts:3` | `'local' \| 'remote' \| 'socks'` — all three are SSH channel semantics |
| `TunnelConfig` | `src/shared/tunnel.ts:5-16` | `listenHost/listenPort/targetHost/targetPort`; every field is meaningless for a WireGuard peer |
| `TunnelSshConfig` | `src/shared/tunnel.ts:18-21` | extends `SshHop`; carries `serverId` + `hops[]` |
| `TunnelState` | `src/shared/tunnel.ts:23` | `starting/active/error/stopped` — no `authenticating`, no `reconnecting`, no `degraded` |
| `TunnelStatus` | `src/shared/tunnel.ts:25-33` | `connections` (a socket count) + `listenPort`. No bytes, no handshake age, no assigned IP |
| `parseEndpoint` | `src/shared/tunnel.ts:42-50` | reusable as-is for VPN listener parsing |

Forcing WireGuard into this shape would mean six of eight `TunnelConfig` fields being unused and `TunnelStatus.connections` lying. **Decision: new domain.**

### 2.2 The lifecycle idioms worth copying

`src/main/services/tunnel.ts` is the template:

- `interface Active` + `const tunnels = new Map<string, Active>()` (`:12-24`) — one record per live thing, keyed by config id.
- `emit(t)` guards a destroyed `WebContents` and sends on a **per-id channel** `tunnel:status:${id}` (`:29-39`). The comment at `:26-28` explicitly handles "started by an AI agent, no renderer to push to" — the VPN manager needs exactly the same property.
- `setState(t, state, error?)` (`:41-45`) — single mutation point.
- `listen()` (`:84-103`) maps `EADDRINUSE` → *"Port N on H is already in use."* and `EACCES` → *"ports below 1024 need elevated rights"*. **This is the actionable-error-mapping convention the VPN drivers must follow.**
- `tunnelStart` calls `await tunnelStop(cfg.id)` first (`:201`) — idempotent restart, kills the double-start race.
- `client.on('close')` at `:222-227` sets `error` and tears down: *"A dropped SSH connection must not leave a listener accepting traffic that has nowhere to go."* The VPN equivalent (drop the dependents when the tunnel dies) is the same rule.
- `tunnelStop` (`:271-294`) destroys sockets → closes server → ends SSH clients **in reverse order** (`:284`).
- `tunnelDisposeAll` (`:306-308`) called from `before-quit` (`src/main/index.ts:684`).
- `openEphemeralForward` (`:313-355`) returns `{ port, close }` — consumed by `src/main/services/db.ts:56-79`, which wraps the driver's `close` so the forward is torn down after the connection (`db.ts:65-73`). **The VPN sidecar should expose an identical `{port, close}` primitive.**

### 2.3 IPC wiring

- Main handlers: `src/main/index.ts:494-499` (`tunnel:start` / `tunnel:stop` / `tunnel:list`). `tunnel:start` passes `e.sender` and wraps ssh config in `resolveChainSecrets(ssh)` (`:496`).
- Preload: `src/preload/index.ts:200-210`, exposed via `contextBridge.exposeInMainWorld('shellpilot', api)` at `:353`, typed by `export type ShellPilotApi = typeof api` (`:355`) and re-declared on `Window` in `src/preload/index.d.ts:3-7`. Adding a namespace is purely additive.
- Renderer guards missing preload methods with `bridgeHas` / `bridgeOn` (`src/renderer/src/lib/bridge.ts:30-45`) — required, because `electron-vite dev` hot-reloads the renderer against a stale preload.
- Interactive prompting precedent: `setSshPrompter` (`src/main/services/ssh.ts:33-39`) + `SshPromptRequest` (`src/preload/index.ts:14-22`). OpenVPN OTP/password prompts reuse this exact shape.

### 2.4 Renderer

- `TunnelManager.tsx:37-51` subscribes per-id, keyed on `tunnels.map(t=>t.id).join(',')` with a long comment (`:29-35`) about why depending on the objects re-subscribes on every status tick. **Copy this verbatim** — VPN status ticks more often than tunnel status.
- `TunnelManager.tsx:54-60` reconciles against `list()` on mount.
- `TunnelForm` (`:185-275`) is the create-modal pattern; `TunnelSidebar.tsx:5-24` the sidebar section.
- `ActivityBar.tsx:6-13` — seven activities; `Sidebar.tsx:12-18` maps activity → title.
- **The `vpns` scaffolding already exists**: `types.ts:82-97` (`VpnKind`/`VpnProfile`, currently a mock with `rx`/`tx`/`connectedSince` and kinds `pritunl`/`easyconnect`), `store/app.ts:93, 140, 220, 290, 334, 601, 908`, `store/persist.ts:17, 87, 104, 137`, and `store.ts:5` already says *"workspaces, folders, servers, vpns, tunnels"*. Nothing reads it. **Replace the mock shape; keep the slice.**

### 2.5 Secrets

- `src/main/services/secrets.ts` — `safeStorage`-sealed base64 map at `shellpilot-secrets.json`, mode `0600` (`:22`). Refuses to persist rather than store plaintext (`:30`).
- `src/main/services/vault.ts` — AES-256-GCM under scrypt `N=32768,r=8,p=3` (`:27`); key lives only in main memory; the comment at `:11-16` is honest that decrypted entries do reach the renderer.
- `src/main/services/credentialResolver.ts` — `SecretBlob.vaultEntryId` (`:12`) is the canonical pattern: *a reference to a vault entry, one record, changed in one place when it rotates* (`:7-11`). `VaultLockedError` (`:32-39`) with the `SHELLPILOT_VAULT_LOCKED` marker (`:30`) survives the IPC boundary. `knownSecretValuesForServer` (`:122-142`) feeds redaction.
- `src/shared/vault.ts:10` `VaultKind`, `:126-134` `VAULT_KIND_FIELDS` (tests assert coverage — see the comment at `:120-125`).
- `src/main/services/secretRedaction.ts:12-35` `PATTERN_RULES`, `:59-61` `redactOutput(text, knownSecrets)`. `auditLog.ts:21-22` redacts *before* writing, not before displaying.

### 2.6 AI policy

- `AiCapability` union `src/shared/mcp.ts:10-21`, labels `:23-35`.
- `evaluateCapability` (`policyEngine.ts:26-34`) — **absent means deny** (`:32`), with the reasoning at `:28-31`.
- `mostRestrictive` (`:36-44`) — session group is a ceiling.
- `evaluateTunnelOpen` (`:428-435`) — *"Opening a tunnel binds a listener on the user's own machine… never granted silently"*: `allow` is clamped to `ask`.
- `allowAll()` (`policyStore.ts:16-35`) — `manageServers: 'deny'` with an explicit comment (`:26-32`) about not silently widening existing groups. `backfillCapabilities` (`policyStore.ts:120`) handles upgrades.
- MCP tools: `list_tunnels` (`mcpServer.ts:903`), `set_tunnel` (`mcpServer.ts:930`) — note the start/stop asymmetry at `:963-971` and the `risk: running ? 'high' : 'low'` gate.
- `approvals.ts:34-51` `requestApproval`; the comment at `:6-9` — the MCP surface can never resolve its own request.
- `mcpDataCache.ts:48-57` `CachedTunnel`, `:212` `listCachedTunnels`.

### 2.7 Packaging & process constraints

- `electron-builder.yml:14-29`: `files: out/** bin/** resources/** package.json`; `asarUnpack` keeps `out/cli/**` and `bin/**` outside the archive *"cmd.exe/a shell can't execute a script or load a module from inside an asar archive at all"*.
- `clientConfig.ts:18-25` is the resolution idiom: `appPath.endsWith('app.asar') ? appPath + '.unpacked' : appPath`.
- **macOS has no Developer ID** (`electron-builder.yml:64-85`): `identity: '-'` (ad-hoc), not notarized. `hardenedRuntime: true` (`:103`) with `build/entitlements.mac.plist` disabling library validation (`:92-95`) for the unpacked `ssh2`/`cpu-features` binaries. **This rules out `SMJobBless` and any installed privileged helper on macOS, permanently, until a certificate exists.**
- Windows: `nsis` + `portable` (`:31-39`), no code-signing block.
- Linux: `AppImage` + `deb` (`:128-132`).
- Portable mode: `src/main/portable.ts:12-18` redirects `userData` beside the exe when `PORTABLE_EXECUTABLE_DIR` is set, and the file must be imported first (`src/main/index.ts:3`).
- Single-instance lock at `src/main/index.ts:744-752`.
- `before-quit` at `src/main/index.ts:680-689` is **fully synchronous** — adding an async VPN teardown requires the `preventDefault` + `app.quit()` re-entry pattern.
- `process.on('uncaughtException')` / `unhandledRejection` are swallowed at `src/main/index.ts:693-694`, explicitly citing *"a failed child_process spawn"*.

### 2.8 Tests

`vitest.config.ts` aliases `electron` → `tests/mocks/electron.ts`, which mints a fresh `mkdtempSync` userData per test file and stubs `safeStorage` as identity. `tests/dbTunnelPolicy.test.ts:94-102` is the template for a new `evaluateVpnControl` suite.

---

## 3. Engine / library selection matrix

### WireGuard

| Option | License | Platforms | Root? | Stats API | Verdict |
|---|---|---|---|---|---|
| **`wireguard-go` + `tun/netstack` (gVisor), embedded in our own sidecar** | **MIT** | win/mac/linux, amd64+arm64 | **No** | `dev.IpcGet()` → `last_handshake_time_sec`, `rx_bytes`, `tx_bytes` | ✅ **CHOSEN — default mode** |
| `wireguard-go` binary + real TUN + `wg`/UAPI socket | MIT | all | **Yes** (utun/Wintun/`/dev/net/tun`) | UAPI over `/var/run/wireguard/*.sock` or `\\.\pipe\WireGuard\wg0` | ✅ chosen for opt-in `system` mode, Phase 6 |
| `boringtun` / `boringtun-cli` | BSD-3 | linux/mac only for the CLI | Yes | UAPI-compatible | ❌ no netstack mode, no Windows CLI, repo self-describes as *"currently undergoing a restructuring… should probably not rely on the master branch"* |
| `wireproxy` (`windtf/wireproxy`, 5.7k★, active) | ISC | all | No | **none** | ❌ config-file-driven (private key on disk), one process per tunnel, no stats. Good prior art, wrong shape |
| Kernel WireGuard + `wg-quick` | GPL-2.0 tools | Linux only | Yes | `wg show` | ❌ Linux-only; `wg-quick` configs carry `PostUp`/`PostDown` = shell execution |
| Node FFI / N-API bindings | — | — | — | — | ❌ nothing maintained enough to trust in a security tool |

**Why our own sidecar rather than shelling out to `wireproxy`:** three properties `wireproxy` cannot give us — (1) secrets arrive on **stdin**, never a file, never argv; (2) **one process, many tunnels**, so lifecycle/backoff/reaping is one supervisor not N; (3) **live stats** via `IpcGet()` and an **ephemeral-forward RPC** that returns `{port, close}` matching `openEphemeralForward` exactly. It is ~450 lines of Go over `device.NewDevice(tun, conn.NewDefaultBind(), logger)` + `netstack.CreateNetTUN(addrs, dns, mtu)`.

### OpenVPN

| Option | License | Platforms | Root? | Stats API | Verdict |
|---|---|---|---|---|---|
| **System-installed `openvpn` 2.6/2.7 + management interface** | GPL-2.0 (**not bundled**) | all | Yes (Win: interactive service = no UAC) | `>STATE:`, `>BYTECOUNT:`, `state`, `bytecount N` | ✅ **CHOSEN** |
| Bundled `openvpn` binary | GPL-2.0 | all | Yes | same | ❌ triggers GPLv2 §3 corresponding-source obligation per platform, forever — see §4 |
| `openvpn3` / `openvpn3-linux` D-Bus | AGPL-3.0 | Linux only (+ macOS via OpenVPN Connect, closed) | Yes | D-Bus props | ❌ Linux-only, AGPL, and OpenVPN's own policy is *"you will have to comply with the GPL (2.x) or AGPL (3.x)"* |
| Re-implement the protocol | — | — | — | — | ❌ absurd |

Latest upstream at time of writing: **OpenVPN 2.7.6** (2026-08-06). Management interface version 5; unchanged in the ways that matter since 2.4.

### frp

| Option | License | Platforms | Root? | Stats API | Verdict |
|---|---|---|---|---|---|
| **Bundled `frpc` binary + admin API** | **Apache-2.0** | 17 platform tarballs incl. win/mac/linux × amd64/arm64 | **No** | `GET /api/status`, `/healthz`, `GET /api/reload`, `POST /api/stop`, `GET`/`PUT /api/config` | ✅ **CHOSEN** |
| Embed `github.com/fatedier/frp/client` in our sidecar | Apache-2.0 | all | No | in-process | ❌ frp's client package is not a stable public API; version skew against `frps` becomes our problem |
| Bring-your-own `frpc` | — | — | — | — | ⚠️ offered as an *advanced* override only |

Pin **v0.71.0** (2026-08-14). **TOML only** — INI was deprecated at v0.52.0 and new features are TOML/YAML/JSON-only.

### Architecture question: one sidecar or several?

**Verdict: two bundled binaries + one detected.** A single monolithic Go sidecar embedding wireguard-go *and* frp was considered and rejected: frp's client API is internal and churns, its config surface is enormous, and its own admin API is a better, documented, stable control channel than anything we'd wrap. But **do not** shell out to three unrelated CLIs with three ad-hoc scrape-the-stdout protocols either — that is where every VPN GUI goes wrong. The line is: *own the thing that has no control protocol (wireguard-go), use the control protocol where one exists (frpc admin API, openvpn management interface).*

Both bundled binaries are built from **pinned source in CI** with `-trimpath -ldflags="-s -w"`, not downloaded from releases at build time — reproducible, one supply-chain surface, and we already need the Go toolchain for `netd`.

---

## 4. Licensing analysis + distribution recommendation

ShellPilot is MIT (`LICENSE`, `package.json:"license":"MIT"`). Three distinct questions get conflated constantly; separate them.

**Q1 — does talking to a GPL program over a socket make our code GPL?** No. `openvpn` runs as a separate process; ShellPilot exchanges bytes over a UNIX socket / loopback TCP / pipe. Arm's-length inter-process communication does not create a derivative work under GPLv2. ShellPilot's source stays MIT regardless.

**Q2 — does *distributing* the GPL binary create obligations?** **Yes, and this is the one that bites.** GPLv2 §3 requires that anyone who distributes a binary accompany it with the complete corresponding machine-readable source, or a written offer valid for three years. Concretely, shipping `openvpn.exe` in the NSIS installer would mean: hosting the exact `openvpn-2.7.x` source tarball plus every patch plus the build recipe, plus (because you linked them) OpenSSL, lzo, pkcs11-helper and `tap-windows6`, for **every** release artifact, **for three years after the last distribution** — on a volunteer project with no legal function. It also means the Windows installer would need to install the TAP/DCO driver, which requires an EV-signed installer this project does not have (`electron-builder.yml` has no `win.certificateFile` and `mac.identity: '-'`).

**Q3 — the OpenSSL exception?** OpenVPN's `COPYING` grants permission to link against OpenSSL and (separately) APL-2 libraries. It relaxes *OpenVPN's* linking constraints. It grants nothing to a downstream redistributor of the binary, and it does not weaken §3.

### Verdict per binary

| Binary | License | Bundle? | Obligation if bundled | Decision |
|---|---|---|---|---|
| `shellpilot-netd` (our code + `wireguard-go`) | **MIT** + MIT | **Yes** | Preserve copyright + permission notice | ✅ bundle; add WireGuard's MIT text to `THIRD-PARTY-LICENSES.md` |
| `frpc` | **Apache-2.0** | **Yes** | Retain LICENSE, retain/propagate `NOTICE`, state changes if modified (we make none) | ✅ bundle; ship `LICENSE` + `NOTICE` under `resources/bin/frp/` and list in `THIRD-PARTY-LICENSES.md` |
| `boringtun` | BSD-3 | n/a | Reproduce copyright + disclaimer, no endorsement | not used |
| **`openvpn`** | **GPL-2.0** | **NO** | Perpetual per-platform corresponding-source offer + driver signing | ❌ **bring-your-own** |

### Recommendation

1. **Never ship an `openvpn` binary in any ShellPilot artifact.** Detect a system install. If missing, the OpenVPN profile UI shows a per-OS install hint (`brew install openvpn`, `sudo apt install openvpn`, `winget install OpenVPNTechnologies.OpenVPN`) and a "Locate binary…" file picker. `errorCode: 'binary-missing'`.
2. Add `THIRD-PARTY-LICENSES.md` at the repo root, generated in CI from `resources/bin/manifest.json`, and surface it in Settings → About.
3. Add a `LICENSING.md` note for downstream packagers: *"Do not vendor `openvpn` into a ShellPilot AppImage/Flatpak/Homebrew cask without independently satisfying GPLv2 §3."* An AppImage that bundles openvpn is a redistribution and the obligation lands on whoever built it.
4. `NOTICE` propagation for frp is a hard requirement, not a courtesy — Apache-2.0 §4(d).

---

## 5. Architecture

### 5.1 New shared types — `src/shared/vpn.ts`

```ts
export type VpnKind = 'wireguard' | 'openvpn' | 'frp'

/** userspace: netstack, local listeners only, zero elevation, no OS routing change.
 *  system:    real TUN device + routes + DNS. Requires elevation. */
export type VpnMode = 'userspace' | 'system'

/** A pointer into the vault. A literal secret must never appear in a VpnProfile:
 *  profiles are persisted by store.ts into plain JSON (shellpilot-data.json). */
export interface VpnSecretRef { vaultEntryId: string; field: VpnSecretField }
export type VpnSecretField =
  | 'privateKey' | 'presharedKey' | 'password' | 'username'
  | 'keyPassphrase' | 'token' | 'configBody'

export type VpnListener =
  | { kind: 'socks5'; bindHost: string; bindPort: number }
  | { kind: 'http';   bindHost: string; bindPort: number }
  | { kind: 'forward'; bindHost: string; bindPort: number; targetHost: string; targetPort: number }

export interface WireGuardPeer {
  publicKey: string                    // base64, 44 chars
  presharedKeyRef?: VpnSecretRef
  endpoint: string                     // host:port | [v6]:port
  allowedIps: string[]                 // CIDR
  persistentKeepalive?: number         // seconds, 0 = off
}

export interface WireGuardSpec {
  kind: 'wireguard'
  mode: VpnMode
  privateKeyRef: VpnSecretRef
  addresses: string[]                  // e.g. ['10.0.0.2/32', 'fd00::2/128']
  dns: string[]
  mtu?: number                         // default 1420
  peers: WireGuardPeer[]
  listeners: VpnListener[]             // userspace mode only
}

export interface OpenVpnSpec {
  kind: 'openvpn'
  /** The SANITIZED config we re-emitted, incl. inline <ca>/<cert>/<key>/<tls-crypt>.
   *  Stored whole in the vault; never on disk in cleartext except the run dir. */
  configRef: VpnSecretRef
  authMode: 'none' | 'userpass' | 'userpass-otp'
  usernameRef?: VpnSecretRef
  passwordRef?: VpnSecretRef
  keyPassphraseRef?: VpnSecretRef
  staticChallenge?: { text: string; echo: boolean }
  /** false => --route-nopull + explicit routes. Default false: never hijack the
   *  default route because a downloaded profile asked us to. */
  redirectGateway: boolean
  httpProxy?: { host: string; port: number; auth?: 'none' | 'basic' | 'ntlm' }
  /** Kept so the import warning can be shown again at any time, not just once. */
  strippedDirectives: string[]
  /** Explicit user override; undefined = allowlisted auto-detect. */
  binaryPath?: string
}

export type FrpProxyType = 'tcp'|'udp'|'http'|'https'|'stcp'|'sudp'|'xtcp'|'tcpmux'

export interface FrpProxy {
  name: string
  type: FrpProxyType
  localIp: string                      // forced to 127.0.0.1 unless confirmed
  localPort: number
  remotePort?: number
  customDomains?: string[]
  subdomain?: string
  secretKeyRef?: VpnSecretRef          // stcp/sudp/xtcp
  plugin?: { name: 'socks5' | 'http_proxy'; username?: string; passwordRef?: VpnSecretRef }
  /** The user ticked "this makes localhost:<port> reachable from <serverAddr>".
   *  start() refuses without it. */
  acknowledgedExposure: boolean
}

export interface FrpSpec {
  kind: 'frp'
  serverAddr: string
  serverPort: number
  auth: { method: 'token' | 'oidc'; tokenRef?: VpnSecretRef; oidc?: FrpOidc }
  transport: {
    protocol: 'tcp' | 'kcp' | 'quic' | 'websocket' | 'wss'
    tlsEnable: boolean                 // default true (frp default since v0.50)
    proxyUrl?: string                  // corporate proxy: http/socks5/ntlm
    poolCount?: number
    heartbeatIntervalSec?: number
  }
  proxies: FrpProxy[]
  visitors: FrpVisitor[]
}

export type VpnSpec = WireGuardSpec | OpenVpnSpec | FrpSpec

export interface VpnProfile {
  id: string
  workspaceId: string
  name: string
  autoStart: boolean
  spec: VpnSpec
}

// ---------------------------------------------------------------- status
export type VpnState =
  | 'stopped' | 'starting' | 'authenticating' | 'connected'
  | 'reconnecting' | 'degraded' | 'error'

export interface VpnStats {
  rxBytes: number
  txBytes: number
  lastHandshakeSec?: number            // WG only; age in seconds, undefined = never
  assignedIp?: string                  // WG address / OpenVPN VIP4
  remoteEndpoint?: string
  latencyMs?: number
  proxies?: { name: string; status: string; remoteAddr?: string; error?: string }[]  // frp
  sampledAt: number
}

export type VpnErrorCode =
  | 'binary-missing' | 'binary-untrusted' | 'config-invalid' | 'config-rejected'
  | 'auth-failed'   | 'auth-otp-required' | 'tls-handshake-failed' | 'cert-expired'
  | 'handshake-timeout' | 'dns-failure'  | 'port-in-use'  | 'permission-denied'
  | 'elevation-declined' | 'network-unreachable' | 'server-rejected'
  | 'crash-loop'    | 'vault-locked'    | 'proxy-required' | 'version-mismatch'
  | 'interface-conflict' | 'already-running' | 'clock-skew'

export interface VpnStatus {
  id: string
  kind: VpnKind
  state: VpnState
  since?: number                       // epoch ms of last state change
  error?: string                       // human, localized, actionable
  errorCode?: VpnErrorCode             // machine-readable; drives "how to fix"
  listeners?: { kind: string; bindHost: string; bindPort: number }[]
  stats?: VpnStats
  restarts: number
}

export interface VpnResult { ok: boolean; error?: string; errorCode?: VpnErrorCode }

export interface VpnValidationIssue {
  path: string                         // 'peers[0].endpoint'
  severity: 'error' | 'warning'
  code: string
  message: string
}
export interface VpnValidation { ok: boolean; issues: VpnValidationIssue[] }

export interface VpnEngineInfo {
  kind: VpnKind
  available: boolean
  path?: string
  version?: string
  sha256?: string
  bundled: boolean
  reason?: string                      // why unavailable
}

/** An import that has been through the sanitizer. `stripped` is never empty
 *  silently — the UI must show it. */
export interface VpnImportResult {
  ok: boolean
  error?: string
  spec?: VpnSpec
  secrets?: Record<VpnSecretField, string>   // main-process only, never crosses IPC to the renderer
  stripped: { directive: string; reason: string; severity: 'removed' | 'rejected' }[]
  warnings: string[]
}
```

**Note on `VpnImportResult.secrets`:** the import IPC handler puts the material straight into the vault in main and returns only refs. The field exists on the internal type, not the wire type — split it into `VpnImportResultInternal` and `VpnImportResult` so the compiler enforces it.

### 5.2 Driver interface — `src/main/services/vpn/driver.ts`

```ts
export interface VpnPrompt {
  id: string
  profileId: string
  profileName: string
  kind: 'password' | 'otp' | 'passphrase'
  label: string                        // ">PASSWORD:Need 'Auth' username/password SC:1,Enter OTP"
  echo: boolean
}

export interface VpnDriverContext {
  /** 0700 scratch dir, unique per run, swept at startup and deleted on stop. */
  runDir: string
  /** Plaintext, resolved from the vault. Main-process only. Never logged, never emitted. */
  secrets: ResolvedVpnSecrets
  /** Coalesced + change-detected by the manager before it reaches IPC. */
  emit(patch: Partial<VpnStatus>): void
  /** Already passed through redactOutput(). Goes to the bounded ring buffer. */
  log(line: string, stream: 'stdout' | 'stderr' | 'ctl'): void
  /** Resolves to null if the user cancelled. Reuses the SSH prompter plumbing. */
  askUser(p: Omit<VpnPrompt, 'id' | 'profileId' | 'profileName'>): Promise<string | null>
  /** The supervisor. Drivers never call child_process directly. */
  supervisor: Supervisor
}

export interface VpnStartResult extends VpnResult {
  listeners?: { kind: string; bindHost: string; bindPort: number }[]
}

export interface VpnDriver<S extends VpnSpec = VpnSpec> {
  readonly kind: VpnKind

  /** Pure, synchronous, no I/O, no secrets. Safe to call from a form on keystroke. */
  validateConfig(spec: S): VpnValidation

  /** Locate + integrity-check the engine. Cached per app run. Never spawns a profile. */
  probe(): Promise<VpnEngineInfo>

  start(profile: VpnProfile & { spec: S }, ctx: VpnDriverContext): Promise<VpnStartResult>

  /** Graceful by default: control-channel stop, then signals. force skips straight to kill. */
  stop(id: string, opts?: { force?: boolean }): Promise<void>

  status(id: string): VpnStatus | null

  stats(id: string): Promise<VpnStats | null>

  /** Apply a changed spec without dropping the connection. frp only today
   *  (PUT /api/config + GET /api/reload). Absent => manager does stop+start. */
  reload?(id: string, spec: S): Promise<VpnResult>

  /** Userspace-mode only: an ephemeral 127.0.0.1 listener forwarding into the
   *  tunnel. Shape deliberately identical to openEphemeralForward
   *  (src/main/services/tunnel.ts:313) so db.ts can consume either. */
  openForward?(id: string, host: string, port: number): Promise<{ port: number; close: () => void }>
}
```

Registry: `const DRIVERS: Record<VpnKind, VpnDriver> = { wireguard, openvpn, frp }`. The manager (`vpn/manager.ts`) owns the `Map<string, Live>` and never branches on kind.

### 5.3 Process supervisor — `src/main/services/vpn/supervisor.ts`

```ts
export interface SupervisedSpec {
  id: string
  command: string
  args: string[]                       // NEVER contains a secret
  env?: Record<string, string>         // secrets allowed here (frp only)
  cwd: string
  /** Written to the child's stdin, then the pipe is ended. Preferred secret channel. */
  stdinPayload?: string
  /** Resolves when the run is up. Rejecting triggers backoff. */
  readiness(h: SupervisorHandle): Promise<void>
  readinessTimeoutMs: number           // default 30_000
  healthCheck?(h: SupervisorHandle): Promise<void>
  healthIntervalMs?: number            // default 15_000
  /** Ordered graceful stop attempted before any signal. */
  gracefulStop?(h: SupervisorHandle): Promise<void>
  gracefulTimeoutMs?: number           // default 5_000
  restart: 'never' | 'on-failure' | 'always'
  backoff: { baseMs: number; maxMs: number; jitter: number }   // 1_000 / 60_000 / 0.3
  crashLoop: { windowMs: number; maxRestarts: number }         // 120_000 / 5
  logRing: { maxLines: number; maxBytes: number }              // 2_000 / 1 MiB
  /** Literal values scrubbed from every captured line before it is stored. */
  redact: string[]
}
```

Behaviour, precisely:

- **Backoff:** `delay = min(maxMs, baseMs * 2^n) * (1 ± jitter)`. Reset `n` to 0 after `readiness` has held for 60 s. Jitter is not decorative — five profiles pointed at the same downed endpoint must not stampede.
- **Crash-loop:** more than `maxRestarts` exits inside `windowMs` → terminal `state:'error'`, `errorCode:'crash-loop'`, restarts stop, and the last 40 log lines are attached to the error. The user must press Start again. Never restart forever.
- **Graceful shutdown ordering:** `gracefulStop()` (control channel) → wait `gracefulTimeoutMs` → `SIGTERM` → 5 s → `SIGKILL` / `taskkill /T /F /PID`. Windows has no `SIGTERM` for a non-console child, so the control-channel stop is *load-bearing* there, not a nicety.
- **Orphan reaping:** every run writes `<userData>/vpn-run/<runId>.pid` = `{pid, startedAtIso, exePath, exeSha256, kind, profileId}` **before** spawn completes. On app start, `reapOrphans()`:
  1. read every `*.pid`;
  2. `process.kill(pid, 0)` — gone? delete the file, done;
  3. **verify identity before killing** — Linux `readlink /proc/<pid>/exe`, macOS `ps -o comm=,lstart= -p <pid>`, Windows `Get-CimInstance Win32_Process -Filter "ProcessId=<pid>"` → `ExecutablePath` + `CreationDate`. Path must match `exePath` **and** start time must be ≥ `startedAtIso`. This is the PID-reuse defence and it is not optional;
  4. kill, then delete the file and the run dir.
  Also sweep any `vpn-run/*` directory with no matching live run.
- **Log capture:** `readline` over stdout/stderr → `redactOutput(line, redact)` → ring buffer with a **byte** cap as well as a line cap (one 4 MB stack trace on a single line otherwise defeats a line-only cap). No `child.stdout.on('data')` string concatenation — that is the unbounded-growth bug.
- **Multiple app instances:** already prevented by `app.requestSingleInstanceLock()` (`src/main/index.ts:744`). Portable mode is the hole — two copies of the portable exe in different folders each get their own `userData` and their own lock, so two `netd` instances can fight over a listen port. Handled by per-run `bindPort: 0` where possible + an `EADDRINUSE` message naming the other instance.

### 5.4 IPC surface

`src/main/index.ts`, immediately after the Tunnels block at `:494-499`:

```ts
// ---- VPN ----
ipcMain.handle('vpn:list',    ()            => vpnList())
ipcMain.handle('vpn:start',  (e, id: string) => vpnStart(e.sender, id))
ipcMain.handle('vpn:stop',   (_e, id: string, force?: boolean) => vpnStop(id, { force }))
ipcMain.handle('vpn:reload', (_e, id: string) => vpnReload(id))
ipcMain.handle('vpn:validate', (_e, spec: VpnSpec) => vpnValidate(spec))
ipcMain.handle('vpn:probe',  (_e, kind: VpnKind) => vpnProbe(kind))
ipcMain.handle('vpn:import', (_e, kind: VpnKind, text: string, baseDir?: string) =>
  vpnImport(kind, text, baseDir))     // returns refs, never material
ipcMain.handle('vpn:logs',   (_e, id: string, limit?: number) => vpnLogs(id, limit))
ipcMain.handle('vpn:dependents', (_e, id: string) => vpnDependents(id))
setVpnPrompter(async (req) => { /* mirrors setSshPrompter, src/main/index.ts near :364 */ })
```

Preload, mirroring `src/preload/index.ts:200-210`:

```ts
vpn: {
  list:  (): Promise<VpnStatus[]> => ipcRenderer.invoke('vpn:list'),
  start: (id: string): Promise<VpnResult> => ipcRenderer.invoke('vpn:start', id),
  stop:  (id: string, force = false): Promise<void> => ipcRenderer.invoke('vpn:stop', id, force),
  reload:(id: string): Promise<VpnResult> => ipcRenderer.invoke('vpn:reload', id),
  validate: (spec: VpnSpec): Promise<VpnValidation> => ipcRenderer.invoke('vpn:validate', spec),
  probe: (kind: VpnKind): Promise<VpnEngineInfo> => ipcRenderer.invoke('vpn:probe', kind),
  import:(kind: VpnKind, text: string, baseDir?: string): Promise<VpnImportResult> =>
    ipcRenderer.invoke('vpn:import', kind, text, baseDir),
  logs:  (id: string, limit?: number): Promise<VpnLogLine[]> => ipcRenderer.invoke('vpn:logs', id, limit),
  dependents: (id: string): Promise<VpnDependent[]> => ipcRenderer.invoke('vpn:dependents', id),
  onStatus: (id: string, cb: (s: VpnStatus) => void): (() => void) => {
    const ch = `vpn:status:${id}`
    const h = (_e: IpcRendererEvent, s: VpnStatus): void => cb(s)
    ipcRenderer.on(ch, h)
    return () => ipcRenderer.removeListener(ch, h)
  },
  onLog: (id: string, cb: (l: VpnLogLine) => void): (() => void) => { /* same shape */ },
  onPrompt: (cb: (p: VpnPrompt) => void): (() => void) => { /* like SshPromptRequest */ },
  replyPrompt: (id: string, value: string | null): void =>
    ipcRenderer.send('vpn:prompt-reply', id, value)
}
```

**Back-pressure**, non-negotiable:

1. **Coalesce.** At most one `vpn:status:<id>` per **1000 ms** per profile, and only when the payload deep-differs from the last one sent. State *transitions* bypass the throttle and fire immediately — a user pressing Stop must not wait a second for the UI to move.
2. **Adaptive poll.** 1 s while the Tunnels view is the active activity, 10 s otherwise, **paused entirely** on `mainWindow.on('hide')` / `blur` past 30 s, resumed on `show`/`focus` with an immediate sample. WireGuard handshakes refresh every ≥120 s; polling `IpcGet()` faster than 1 Hz is pure waste.
3. **Logs are pull, not push, by default.** `vpn:log:<id>` only streams while the renderer has an active `onLog` subscription (ref-counted in main). Otherwise lines stop at the ring buffer and the drawer fetches them with `vpn:logs`.
4. **Renderer subscribes by joined id string**, exactly as `TunnelManager.tsx:36-51` does, and reconciles with `list()` on mount (`:54-60`).

### 5.5 Renderer UI

New directory `src/renderer/src/components/vpn/`, siblings of `components/tunnels/`:

| File | Role |
|---|---|
| `VpnManager.tsx` | list + start/stop + live stats; modelled on `TunnelManager.tsx` |
| `VpnSidebar.tsx` | sidebar section; modelled on `TunnelSidebar.tsx:5-24` |
| `VpnImportModal.tsx` | paste/drop a `.conf` / `.ovpn` / `.toml`; **shows the stripped-directive report before anything is saved** |
| `VpnProfileForm.tsx` | typed editor per kind (discriminated on `spec.kind`) |
| `VpnStatusCard.tsx` | handshake age, rx/tx, assigned IP, endpoint, listeners, per-proxy table for frp |
| `VpnPromptModal.tsx` | OTP / password re-prompt; mirrors `connections/SshPrompt.tsx` |
| `VpnLogDrawer.tsx` | bounded, redacted, subscribe-on-open |

**Placement decision: do not add an eighth activity icon.** Rename the existing `tunnels` activity from "SSH Tunnels" to **"Tunnels & VPN"** (`ActivityBar.tsx:9`, `Sidebar.tsx:15`) and give the view three sections: *SSH Tunnels* (existing), *VPN* (WireGuard/OpenVPN), *Reverse Proxies* (frp). `ActivityView` (`types.ts:130`) is unchanged. Rationale: these are all "make a remote thing reachable from here"; splitting them across two icons makes the user guess which one holds the thing they made yesterday.

**Import flows:**
- **WireGuard:** paste a `.conf`, or drag the file in, or **scan a QR code** — `wg` QR payloads are just the config text, so this is `jsQR` over a `getUserMedia` frame or an uploaded PNG. Worth it: it's how every WireGuard provider hands you a mobile profile. Phase 1 does paste/file; QR is a Phase 7 nicety.
- **OpenVPN:** paste/drop a `.ovpn`. If it references `ca`/`cert`/`key` by path, the picker asks for the directory and we read only files resolving inside it.
- **frp:** typed form only in v1. A "Import frpc.ini/toml" converter exists but runs the same allowlist and shows the same report.

**Status display:** a WireGuard tunnel is "healthy" iff `lastHandshakeSec < 180`. Show it as a relative age ("handshake 12s ago") not a timestamp, and go `degraded` — amber, not red — when the age exceeds 180 s while the process is still up. That distinction (up-but-not-passing-traffic vs. down) is the single most useful thing a WireGuard UI can show and almost none do.

### 5.6 Secret handling

**Storage.** Add `'vpn'` to `VaultKind` (`src/shared/vault.ts:10`), to `VAULT_KIND_LABEL` (`:68-74`) and to `VAULT_KIND_FIELDS` (`:126-134`) as `{ url: true, username: true, secret: 'password', keys: true }` — `privateKey` carries WG private keys / OpenVPN key material / the sanitized config body, `password` carries the auth password or frp token, `fields[]` carries the rest (preshared keys, per-proxy secretKeys). `tests/vaultKinds.test.ts` asserts coverage of that map, so the addition is caught if incomplete.

Why the vault and not `secrets.ts`: the vault comment at `src/shared/vault.ts:38-42` states the rule — *"a path is the one credential ShellPilot never actually held… which also does not travel with an encrypted backup."* A WireGuard private key must travel with `backupExport` exactly as an SSH key does.

**Resolution.** New `resolveVpnSecrets(profile): ResolvedVpnSecrets` in `credentialResolver.ts`, throwing `VaultLockedError` (`:32-39`) so the renderer's existing `withVaultUnlock` flow prompts. Starting a VPN with a locked vault fails with `errorCode:'vault-locked'` — **never** a fallback, matching the reasoning at `credentialResolver.ts:76-80`.

**Delivery to the child process — per protocol, and why not argv:**

| Protocol | Channel | Why |
|---|---|---|
| **WireGuard** | NDJSON request on `netd`'s **stdin** → `dev.IpcSet()` in-process | argv is world-readable via `ps aux` on Linux/macOS and `Get-CimInstance Win32_Process` on Windows. Nothing ever hits disk. |
| **OpenVPN — credentials** | **management interface**: `--management-query-passwords` + `username "Auth" <u>` / `password "Auth" <p>` written on the socket | `--auth-user-pass <file>` and `--askpass <file>` both put plaintext on disk |
| **OpenVPN — config + certs** | POSIX: `--config /dev/stdin`, body written to the child's stdin then closed. Windows: `%LOCALAPPDATA%\ShellPilot\vpn-run\<runId>\p.ovpn`, created 0600-equivalent in a 0700 dir, deleted on stop + swept at startup | OpenVPN cannot take inline cert material any other way. Windows has no `/dev/stdin`. Residual risk is documented, not hidden. Phase 7 hardening: `--management-external-key` moves the private key out of the file entirely and does the signing over the management channel |
| **frp** | Config uses frp's Go-template env syntax: `auth.token = "{{ .Envs.SP_FRP_TOKEN }}"`, `webServer.password = "{{ .Envs.SP_FRP_ADMIN }}"`; values passed in the child's **env** | frpc has no stdin config path. `/proc/<pid>/environ` is `0400` owner-only, argv is world-readable — env is strictly better, though not perfect. Say so |

**Redaction.** Add to `PATTERN_RULES` (`secretRedaction.ts:12-35`):

```ts
// WireGuard base64 keys (32 bytes) — private, public and preshared look identical
{ regex: /\b[A-Za-z0-9+/]{42}[AEIMQUYcgkosw]=\B/g, replace: () => PLACEHOLDER },
// UAPI hex form
{ regex: /\b((?:private|preshared)_key)=[0-9a-f]{64}\b/gi, replace: (m) => `${m[1]}=${PLACEHOLDER}` },
// OpenVPN static challenge response
{ regex: /SCRV1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/g, replace: () => PLACEHOLDER },
// frp / generic TOML+INI secret assignment
{ regex: /^(\s*(?:auth\.)?(?:token|secretKey|password)\s*=\s*).+$/gim, replace: (m) => `${m[1]}${PLACEHOLDER}` },
```

Note the public key is redacted too — the regex cannot distinguish it. That is the correct trade: a redacted public key costs a support ticket, a leaked private key costs the tunnel. Show public keys in the UI from the model, never scraped from a log.

### 5.7 Interaction with SSH tunnels and databases

Three concrete integrations, all leaning on the userspace forward:

1. **DB over VPN.** Add `vpnProfileId: UUID | null` to `DatabaseConn` (`types.ts:113-127`) beside `sshServerId`, and to `CachedDatabase` (`mcpDataCache.ts:31-46`). In `src/main/services/db.ts:40 build()`, ahead of the SSH branch: ensure the VPN is `connected` (bounded 30 s wait), then in **userspace** mode call `driver.openForward(id, targetHost, targetPort)` and rewrite `host/port` — byte-for-byte the same code path as the existing `openEphemeralForward` block at `db.ts:56-79`, including the `close`-wrapping at `:65-73`. In **system** mode the route already exists; do nothing. This gives DB-over-WireGuard without a single database driver learning about SOCKS.
2. **SSH over VPN.** Add `vpnProfileId` to `Server` (`types.ts:38-53`) and `CachedServer`. `openChain` (`ssh.ts:196`) dials the ephemeral loopback port in userspace mode.
3. **SSH tunnel over VPN.** Falls out of (2) — `tunnelStart` (`tunnel.ts:196`) calls `openChain`.

**Dependency graph.** `vpnDependents(vpnId)` returns every `Server`, `DatabaseConn` and `Tunnel` referencing it, plus every *live* session using one.

- **Start:** starting a dependent auto-starts its VPN and waits for `connected`. If the VPN is `error`, surface **the VPN's** error, not a downstream DNS timeout — an unexplained `ETIMEDOUT` is the single worst failure mode in this class of product.
- **Stop:** stopping a VPN with live dependents shows *"3 sessions are using this VPN"* and requires confirmation. On confirm, tear the dependents down **first**, then the VPN.
- **Drop:** when a VPN drops, every dependent is closed with an explicit `vpn-dropped` reason — the same discipline `tunnel.ts:222-227` already applies to a dropped SSH client.
- **Delete:** deleting a referenced profile is blocked with a "detach from 3 items" action. The workspace-delete cascade (`store/app.ts:601`) needs the same treatment.

**Quit ordering.** `src/main/index.ts:680-689` becomes:

```ts
let teardownStarted = false
app.on('before-quit', (e) => {
  if (teardownStarted) return
  teardownStarted = true
  e.preventDefault()
  sshDisposeAll(); sftpDisposeAll(); metricsDisposeAll()
  dbDisposeAll(); tunnelDisposeAll(); externalEditDisposeAll()
  vaultDispose(); void stopMcpServer()
  // Dependents are down; now the transports they rode on. Hard cap so a wedged
  // child can never hold the app open.
  void Promise.race([vpnDisposeAll(), delay(4000)]).finally(() => app.exit(0))
})
```

Order matters: dependents die before the transport, so nothing observes a half-dead network.

### 5.8 AI / MCP policy

New capability **`vpnControl`**:

- `src/shared/mcp.ts:10-21` — add to the `AiCapability` union.
- `src/shared/mcp.ts:23-35` — `{ id: 'vpnControl', label: 'VPN & reverse proxies' }`.
- `policyStore.ts:16-35` `allowAll()` — **`vpnControl: 'deny'`**, following the `manageServers` precedent and its comment at `:26-32`. `backfillCapabilities` (`policyStore.ts:120`) gives built-ins the fresh-seed value and custom groups `deny`, which is the correct default per `policyEngine.ts:28-31`.
- Per built-in group: Read Only `deny`; Read & Write `ask`; Sudo Access `ask`; Full Access `ask`. **No group gets `allow` by default.**

`policyEngine.ts`, next to `evaluateTunnelOpen` (`:428-435`):

```ts
export function evaluateVpnControl(
  group: AccessGroup | null,
  action: 'start' | 'stop',
  hasLiveDependents: boolean
): Decision {
  if (!group) return { decision: 'deny', reason: 'No AI access is assigned to this workspace.' }
  const cap = evaluateCapability(group, 'vpnControl')
  if (cap.decision === 'deny') return { decision: 'deny', reason: 'VPN control is denied for this access group.' }
  if (action === 'start') {
    return cap.decision === 'allow'
      ? { decision: 'ask', reason: 'Starting a VPN changes where your traffic goes and always requires approval.' }
      : cap
  }
  if (hasLiveDependents && cap.decision === 'allow') {
    return { decision: 'ask', reason: 'Stopping this VPN will close sessions that depend on it.' }
  }
  return cap
}
```

MCP tools in `mcpServer.ts`, mirroring `:903` and `:930`:

- **`list_vpns`** — `readOnlyHint: true`. Names, kinds, states. Never endpoints, never keys.
- **`set_vpn`** — `{ vpnName, running }`. Description states, in the same voice as `set_tunnel` (`:934-937`): *"This cannot create a VPN profile or change where one points — only run one the user has already defined."*
- **`set_vpn` refuses `kind === 'frp'` unconditionally**, whatever the access group says. An frp proxy makes a local port reachable from the public internet; an AI agent must not be the thing that opens it. This is a hard-coded refusal like the `UNRESTRICTED_SHELL_PATTERNS` block at `policyEngine.ts:50-58`, not a policy value.
- **No `add_vpn` / `edit_vpn` tool, ever.**
- Audit via `recordAudit` (`auditLog.ts:16`) with `capability: 'vpnControl'`, `risk: 'high'` on start, action text `Start VPN "<name>" (wireguard, userspace, 2 listeners)`.
- `mcpDataCache.ts` gains `CachedVpn` + `listCachedVpns(workspaceIds)` mirroring `:48-57` / `:212`.

**Security note to state loudly in `docs/AI-SECURITY.md`:** granting `vpnControl` lets an agent change which network the user's subsequent SSH and DB sessions traverse. Combined with `manageServers`, an agent could in principle add a server *and* route it through a VPN it started. That is why start is always `ask`, why frp is refused outright, and why profile creation has no tool.

---

## 6. Per-protocol integration detail

### 6.1 WireGuard — `shellpilot-netd`

**Sidecar protocol.** Newline-delimited JSON, request/response + unsolicited events, over stdio.

```jsonc
// → request
{"id":"7","method":"wg.up","params":{
  "tunnelId":"vpn-abc",
  "iface":{"privateKey":"<base64>","addresses":["10.0.0.2/32"],"dns":["10.0.0.1"],"mtu":1420},
  "peers":[{"publicKey":"<b64>","presharedKey":"<b64>","endpoint":"vpn.example.com:51820",
            "allowedIps":["0.0.0.0/0","::/0"],"persistentKeepalive":25}],
  "listeners":[{"kind":"socks5","bindHost":"127.0.0.1","bindPort":1080}]}}
// ← response
{"id":"7","ok":true,"result":{"listeners":[{"kind":"socks5","bindHost":"127.0.0.1","bindPort":1080}]}}
// ← event
{"event":"wg.state","data":{"tunnelId":"vpn-abc","state":"connected","assignedIp":"10.0.0.2"}}
```

Methods: `ping` → `{version, goVersion, buildSha}` · `wg.up` · `wg.stats {tunnelId}` · `wg.forward.open {tunnelId, host, port}` → `{listenPort, forwardId}` · `wg.forward.close {forwardId}` · `wg.down {tunnelId}` · `shutdown`.

**Go core** (~450 LOC):

```go
tun, tnet, err := netstack.CreateNetTUN(addrs, dnsAddrs, mtu)   // gVisor, no OS device, no root
dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(lvl, "["+id+"] "))
if err := dev.IpcSet(uapi); err != nil { ... }                  // uapi built from params
if err := dev.Up(); err != nil { ... }
// listeners:
//   socks5   -> our own SOCKS5 server, CONNECT dials tnet.DialContext
//   forward  -> net.Listen local, io.Copy both ways against tnet.DialContext
//   ping     -> tnet.Dial("ping4", host) for latency
```

**UAPI string** (`dev.IpcSet`), exactly the documented cross-platform configuration protocol:

```
private_key=<64 hex>
replace_peers=true
public_key=<64 hex>
preshared_key=<64 hex>
endpoint=203.0.113.9:51820
persistent_keepalive_interval=25
replace_allowed_ips=true
allowed_ip=0.0.0.0/0
allowed_ip=::/0
```

**Stats** (`dev.IpcGet()`), parsed for `last_handshake_time_sec`, `last_handshake_time_nsec`, `rx_bytes`, `tx_bytes`, `endpoint`, terminated by `errno=0`. Poll at the adaptive cadence from §5.4. Health rule: `now - last_handshake_time_sec > 180` → `degraded`; `last_handshake_time_sec == 0` after 30 s → `errorCode:'handshake-timeout'` with the message *"No response from &lt;endpoint&gt;. Check the endpoint address and that UDP :&lt;port&gt; is not blocked."*

**`.conf` parsing.** Standard `[Interface]` / `[Peer]` INI. Allowed keys: `PrivateKey`, `Address`, `DNS`, `MTU`, `ListenPort`, `Table`; per-peer `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs`, `PersistentKeepalive`. **`PreUp`/`PostUp`/`PreDown`/`PostDown` are `wg-quick` shell hooks — rejected outright**, whole-import failure, with the offending line quoted. They cannot be silently dropped: a config that uses them expects side effects, and a "successful" import that discards them is a lie.

**System mode (Phase 6).** Same binary, `--privileged`, launched through a per-launch OS elevation prompt, listening on a random-named unix socket in a 0700 dir (or a random named pipe with a per-launch nonce on Windows). It uses `tun.CreateTUN(name, mtu)` and applies addresses/routes/DNS per OS. The unprivileged main process is the only client, authenticated by a 32-byte nonce passed over the already-elevated channel. **No installed helper, no setuid binary, no launchd service.**

### 6.2 OpenVPN

**Spawn.** POSIX:

```
openvpn --config /dev/stdin
        --management <runDir>/mgmt.sock unix --management-client
        --management-query-passwords --management-hold
        --script-security 0
        --pull-filter reject "script-security"
        --pull-filter reject "up "
        --pull-filter reject "down "
        --pull-filter reject "route-method"
        --pull-filter reject "setenv opt "
        [--pull-filter ignore "redirect-gateway"]   # when redirectGateway === false
        [--route-nopull]                            # when redirectGateway === false
        --auth-nocache
        --verb 3
```

`--management-client` inverts the direction: **openvpn dials us**, so there is no window in which a listening management port sits unauthenticated. On POSIX the socket lives in a 0700 dir — filesystem permissions are the whole auth story and they are sufficient. On Windows there are no unix sockets: bind `127.0.0.1:0` ourselves, pass the port, keep `--management-client`, `server.close()` on the first accept, and require the first line to match `>INFO:OpenVPN Management Interface Version`. Residual local-race risk is documented in `SECURITY.md`, not papered over.

Windows also takes `--config <runDir>\p.ovpn` instead of `/dev/stdin`.

**Management dialogue** (exact wire format):

```
← >INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info
→ state on
→ bytecount 5
→ log on all
→ hold release
← >HOLD:Waiting for hold release
← >STATE:1756... ,CONNECTING,,,,,,
← >PASSWORD:Need 'Auth' username/password
→ username "Auth" alice
→ password "Auth" "s3cr3t"
← >PASSWORD:Need 'Auth' username/password SC:1,Enter your 6-digit code
→ username "Auth" alice
→ password "Auth" "SCRV1:<base64(password)>:<base64(otp)>"
← >PASSWORD:Need 'Private Key' password
→ password "Private Key" "<passphrase>"
← >PASSWORD:Verification Failed: 'Auth'
← >STATE:1756...,AUTH,,,,,,
← >STATE:1756...,GET_CONFIG,,,,,,
← >STATE:1756...,ASSIGN_IP,,10.8.0.6,,,,
← >STATE:1756...,CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,,
← >BYTECOUNT:184320,92160
← >STATE:1756...,RECONNECTING,tls-error,,,,,
← >FATAL:Cannot resolve host address: vpn.example.com
→ signal SIGTERM
```

State mapping: `CONNECTING|WAIT|RESOLVE` → `starting`; `AUTH|GET_CONFIG` → `authenticating`; `ASSIGN_IP|ADD_ROUTES` → `starting`; `CONNECTED` → `connected` (parse field 4 = local VIP4, 5/6 = remote ip/port); `RECONNECTING` → `reconnecting` (field 3 carries the reason — `tls-error`, `ping-restart`, `auth-failure`); `EXITING` → `stopped`.

Escaping: management values are `"`-quoted with `\` and `"` backslash-escaped. A password containing `"` is the classic injection here — escape it, and unit-test that.

**OTP.** `SC:<echo-flag>,<challenge text>` on the `>PASSWORD:` line means static challenge. Prompt the user (never cache), respond `SCRV1:<b64 password>:<b64 response>`. With `--auth-nocache`, a reconnect re-asks — so a re-prompt on `RECONNECTING`→`AUTH` is expected behaviour and the UI must not treat it as an error. If the user cancels the prompt, `signal SIGTERM` and stop cleanly with `errorCode:'auth-otp-required'`.

**Config sanitizer — this is the security-critical component.** A `.ovpn` file is executable content: `up`, `down`, `route-up`, `ipchange`, `tls-verify`, `client-connect`, `learn-address`, `auth-user-pass-verify` and `plugin` all run programs, and the `up` script runs *before* any server connection, so the attacker needs no server at all. This is a well-documented RCE class (Tenable, Claroty Team82). Design:

*We never hand the user's file to openvpn.* We parse it into `OpenVpnSpec` and **re-emit a config we generated**. Three tiers:

- **ALLOWED (emitted):** `client`, `dev tun`, `dev-type tun`, `proto {udp,udp4,udp6,tcp,tcp4,tcp6,tcp-client}`, `remote <host> <port> [proto]`, `remote-random`, `resolv-retry`, `nobind`, `persist-key`, `persist-tun`, `remote-cert-tls server`, `verify-x509-name`, `cipher`, `data-ciphers`, `data-ciphers-fallback`, `auth`, `tls-version-min`, `tls-cipher`, `tls-groups`, `key-direction`, `reneg-sec`, `ping`, `ping-restart`, `ping-timer-rem`, `mssfix`, `tun-mtu`, `fragment`, `float`, `auth-retry nointeract`, `auth-user-pass` (bare flag only), `static-challenge`, `redirect-gateway` (gated on `spec.redirectGateway`), `route`, `route-nopull`, `dhcp-option {DNS,DOMAIN,DOMAIN-SEARCH}`, `topology`, `sndbuf`, `rcvbuf`, `explicit-exit-notify`, `http-proxy`, `socks-proxy`, `tls-client`.
- **DROPPED with a report:** `verb` (clamped to ≤4 — a hostile `verb 11` is a log-flood DoS), `comp-lzo`/`compress` (VORACLE; dropped with a warning, since compression + TLS in a VPN is a known plaintext-recovery vector), `mute`, `nice`, `fast-io`, anything unrecognised.
- **HARD-REJECTED, whole import fails:** `up`, `down`, `up-restart`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`, `tls-export-cert`, `client-connect`, `client-disconnect`, `learn-address`, `auth-user-pass-verify`, `plugin`, `script-security`, `setenv` (except a tiny allowlist), `config` (nested include), `chroot`, `cd`, `tmp-dir`, `daemon`, `askpass`, `writepid`, `log`, `log-append`, `status`, `management*`, `--ifconfig-noexec`, `--route-method exe`, and any `ca`/`cert`/`key`/`tls-auth`/`tls-crypt`/`pkcs12`/`dh` given as a path that escapes the import directory.

Silently dropping the reject tier would be worse than failing: the profile author intended those side effects, so a "connected" tunnel without them is a different thing than the user asked for — and the user learns nothing about the fact that someone handed them a config that tried to run a program.

**Path traversal.** Path-form `ca`/`cert`/`key`/`tls-auth`/`tls-crypt` are read only if `realpath(join(baseDir, p))` starts with `realpath(baseDir) + sep`. No absolute paths, no `..`, no symlink escapes. Material is inlined into the vault; the emitted config carries `<ca>…</ca>` blocks.

**Server-pushed directives.** A clean local config is only half the job — a hostile *server* can `push` options. The `--pull-filter reject` list above is the second half, and `--pull-filter ignore "redirect-gateway"` + `--route-nopull` is what makes split-tunnel actually split.

**Binary resolution.** Ordered, allowlisted: (1) `spec.binaryPath` if the user set it and confirmed a dialog; (2) a fixed per-OS list — `/usr/sbin/openvpn`, `/usr/local/sbin/openvpn`, `/opt/homebrew/sbin/openvpn`, `/usr/bin/openvpn`, `C:\Program Files\OpenVPN\bin\openvpn.exe`, `C:\Program Files (x86)\OpenVPN\bin\openvpn.exe`; (3) `PATH` — **POSIX only, never on Windows**, where `PATH`/CWD search is the textbook hijack. Reject relative paths, world-writable parents, and symlink chains leaving the allowlisted root. Run `openvpn --version`, record path + sha256 + version in the audit log on first use, and warn on change.

**Elevation.** OpenVPN has no userspace mode — `--dev tun` needs `CAP_NET_ADMIN`/root. So OpenVPN is elevation-required and the UI says so *before* the profile can be created.

- **Windows:** if `\\.\pipe\openvpn\service` exists (the OpenVPN Interactive Service, installed by the standard MSI), use it — that is the supported no-UAC path and what OpenVPN-GUI does. Otherwise `Start-Process -Verb RunAs`, one UAC prompt per connect.
- **Linux:** per-launch `pkexec` (falling back to `sudo -A` with an askpass helper). Never `setcap`, never a persistent service unit.
- **macOS:** `osascript -e 'do shell script "…" with administrator privileges'`. ShellPilot never sees, stores or transports the password — the Apple dialog does. **No `SMJobBless`, no launchd privileged helper**: both require a Developer ID the project does not have (`electron-builder.yml:64-77`).

### 6.3 frp

**Generated `frpc.toml`** (from `FrpSpec`, never pasted raw):

```toml
serverAddr = "frp.example.com"
serverPort = 7000

auth.method = "token"
auth.token  = "{{ .Envs.SP_FRP_TOKEN }}"

transport.tls.enable        = true
transport.protocol          = "tcp"
transport.poolCount         = 1
transport.heartbeatInterval = 30
# transport.proxyURL = "http://corp-proxy:3128"

webServer.addr     = "127.0.0.1"
webServer.port     = 41731              # ephemeral, bound by us first then released
webServer.user     = "shellpilot"
webServer.password = "{{ .Envs.SP_FRP_ADMIN }}"

log.to = "console"
log.level = "info"

[[proxies]]
name       = "postgres"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 5432
remotePort = 15432
```

**Admin API** (verified against `client/api_router.go` at `dev`), HTTP Basic with the per-run credentials:

| Method | Path | Use |
|---|---|---|
| GET | `/healthz` | liveness probe → `healthCheck` |
| GET | `/api/status` | per-proxy `{name, type, status, err, local_addr, remote_addr, plugin}` → `VpnStats.proxies` |
| GET | `/api/config` | read active config |
| PUT | `/api/config` | replace config (hot) |
| GET | `/api/reload` | apply the replaced config without dropping the control connection |
| POST | `/api/stop` | graceful shutdown → `gracefulStop` |
| GET | `/api/proxy/{name}/config` | per-proxy detail |

`reload()` = `PUT /api/config` then `GET /api/reload`. This is the only driver that implements `reload` — WireGuard and OpenVPN do stop+start.

Readiness: poll `GET /api/status` until every configured proxy reports `running`, or until 30 s. A proxy in `start error` with `err` set maps to `state:'degraded'` with that error surfaced verbatim, because frp's proxy errors (`port already used`, `proxy name already exists`) are already actionable.

Bytes: frp exposes no client-side byte counters, so `VpnStats.rxBytes/txBytes` are omitted for frp rather than faked. The proxy table is the telemetry.

**Version skew.** Pin v0.71.0. Emit TOML only. Refuse legacy INI on import with a one-click converter. `frps` version mismatch surfaces as a login failure in stderr — map `login to server failed` / `authentication failed` / `version mismatch` to `errorCode:'version-mismatch'` or `'auth-failed'` with the frps-side hint.

**frp security — the exposure problem.** frp inverts the app's threat model: every `[[proxies]]` entry makes a local port reachable from `serverAddr`. Rules:

- `plugin = "unix_domain_socket"` and `plugin = "static_file"` are **not offered in v1**. `unix_domain_socket` pointed at `/var/run/docker.sock` is root-equivalent RCE reachable from the frp server; `static_file` is a directory-exposure primitive.
- `plugin = "socks5"` and `"http_proxy"` require an explicit confirm naming what they do.
- `localIP` is forced to `127.0.0.1`; setting `0.0.0.0` requires a confirm.
- `acknowledgedExposure` must be `true` per proxy or `start()` refuses. The checkbox label is literal: *"Make 127.0.0.1:5432 reachable from frp.example.com."*
- `transport.tls.enable` defaults to `true` and turning it off requires a confirm.
- MCP `set_vpn` refuses frp profiles entirely (§5.8).

---

## 7. Security model

1. **Config sanitization is an allowlist, and we re-emit.** Never pass a user-supplied `.ovpn`/`.conf`/`.toml` to an engine. Parse → typed model → generate. Three tiers (allow / drop-with-report / hard-reject). Hard-reject is a *whole-import failure*, never a silent strip. The import UI shows every stripped and rejected directive with a reason before anything is saved, and `strippedDirectives` is persisted so the warning can be shown again later.
2. **Secrets never in argv.** stdin for WireGuard and POSIX OpenVPN config, management channel for OpenVPN credentials, env-template for frp. Ephemeral files only where an engine leaves no alternative, always in a `0700` dir, always deleted on stop and swept at startup.
3. **Elevation is opt-in and per-launch.** Default mode needs none. No installed helper, no setuid binary, no persistent service — on macOS this is not a preference, it is forced by the absence of a Developer ID. Declining an elevation prompt is a first-class outcome (`errorCode:'elevation-declined'`), not a crash.
4. **Binary integrity.** Bundled binaries are SHA-256 verified against a signed manifest on every app run before first exec. User-supplied binaries resolve through an ordered allowlist with no `PATH` search on Windows, and their hash+version is audited on first use and on change.
5. **Redaction before storage, not before display.** Follows `auditLog.ts:21-22`. Ring buffers, audit entries and IPC events all carry already-redacted text.
6. **MCP capability `vpnControl`, default deny, start always ask, frp always refused, no create/edit tool.**
7. **Exposure is stated in plain language.** frp's UI says *"reachable from &lt;server&gt;"*, not "proxy". A VPN card says which of the user's traffic goes through it.

---

## 8. Edge-case register

| ID | Scenario | Detection | Handling | Test |
|---|---|---|---|---|
| **Privilege / platform** |
| E01 | TUN needs root (system mode) | `probe()` + mode | Userspace default; system mode gated behind an explicit per-profile toggle with an OS-specific warning | unit: mode gate |
| E02 | macOS: no Developer ID, `SMJobBless` impossible | build config | Never attempt a privileged helper; `osascript` per-launch only; macOS system mode blocked in v1 | manual |
| E03 | macOS hardened runtime blocks the sidecar | `codesign -dv` in CI | extraResources signed by electron-builder; `disable-library-validation` already present | CI: `codesign --verify --strict` on the packaged .app |
| E04 | Windows UAC declined | non-zero exit / `ERROR_CANCELLED` | `errorCode:'elevation-declined'`, no restart, "Try again" button | fake binary exits 1223 |
| E05 | Windows Interactive Service absent | `existsSync('\\\\.\\pipe\\openvpn\\service')` | Fall back to UAC, tell the user installing the OpenVPN MSI removes the prompt | manual |
| E06 | Linux `/dev/net/tun` missing (container, hardened kernel) | ENODEV on open | `errorCode:'permission-denied'` naming `/dev/net/tun`; offer userspace WG | manual (docker) |
| E07 | SmartScreen flags the unsigned installer | — | Documented in README; no code change | manual |
| **DNS** |
| E08 | DNS leak in system mode | resolver config after up | System mode sets tunnel DNS and asserts it; userspace mode resolves *inside* netstack via `LookupContextHost`, so there is nothing to leak | integration: resolve through `tnet` |
| E09 | macOS `scutil` resolver not restored after SIGKILL | startup scan of `/Library/Preferences/SystemConfiguration` snapshot | Snapshot before change, restore at startup if a stale marker exists | manual |
| E10 | Windows NRPT rules left behind | `Get-DnsClientNrptRule` filtered by our tag | Tag every rule `ShellPilot-<runId>`; sweep untagged-by-live-run at startup | manual |
| E11 | Linux systemd-resolved vs raw `resolv.conf` | `resolvectl status` / `is-symlink` | Prefer `resolvectl dns <if>`; fall back to a backed-up `resolv.conf` restored at startup | manual |
| E12 | Split DNS: only `*.corp` through the tunnel | `dhcp-option DOMAIN` | Supported in system mode; userspace mode documents that split DNS is per-connection, not system-wide | unit |
| **Routing** |
| E13 | `redirect-gateway def1` hijacks the default route | parser | **Default false.** Requires an explicit toggle + confirm; `--route-nopull` + `--pull-filter ignore` when off | unit: emitted config |
| E14 | Routes survive `kill -9` | startup route-table diff vs. saved snapshot | Snapshot routes before change into the run dir; restore any orphan-run's routes at startup | integration (Linux) |
| E15 | Conflicting route with another VPN | route already present for the same prefix | Detect before applying; refuse with a message naming the existing route | manual |
| E16 | IPv6 leak — v4-only tunnel, v6 default route live | peer `allowedIps` has no `::/0` and the host has v6 | Warn at import: *"This profile does not carry IPv6. IPv6 traffic will bypass it."* Offer "block IPv6 while connected" in system mode | unit: import warning |
| E17 | `allowedIps = 0.0.0.0/0` in **userspace** mode | parser | Harmless — userspace routes nothing system-wide. Explain in the UI so the user isn't misled into thinking all traffic is tunnelled | unit |
| **Availability** |
| E18 | Tunnel drops mid-session | WG handshake age > 180 s; OpenVPN `>STATE:…RECONNECTING`; frp `/healthz` fail | `degraded`/`reconnecting`; dependents closed with `vpn-dropped`; no silent plaintext fallback | integration: fake binary drops |
| E19 | Kill switch / fail-closed | — | **v1 does not claim a kill switch.** It tears down dependents on drop and says exactly that. Firewall-based fail-closed is Phase 6, opt-in, system mode only | — |
| E20 | Sleep/wake | `powerMonitor.on('resume')` | WG: force a handshake and resample. OpenVPN: `signal SIGUSR1` (soft restart). frp: `/healthz`, restart on fail | manual |
| E21 | Wi-Fi → Ethernet, IP change | `powerMonitor` + `os.networkInterfaces()` diff | WG roams natively (endpoint tracking). OpenVPN needs `--float` (emitted by default) or a `SIGUSR1`. frp reconnects on heartbeat timeout | manual |
| E22 | Captive portal | connect succeeds, no handshake, DNS returns a portal IP | `handshake-timeout` with *"You may need to sign in to this network first."* | unit: error mapping |
| E23 | MTU blackhole (PMTU broken) | large transfers stall, small ones work | Default MTU 1420 (WG) / `mssfix 1450` (OpenVPN); expose an MTU field; "Reduce MTU to 1280" quick-fix on a stall | manual |
| **Ports & binding** |
| E24 | Listener port already in use | `EADDRINUSE` | Reuse `tunnel.ts:86-94`'s exact message; offer port 0 (auto) | unit |
| E25 | Binding `0.0.0.0` exposes the SOCKS proxy to the LAN | `bindHost !== '127.0.0.1'` | Default `127.0.0.1`; `0.0.0.0` requires a confirm naming the risk | unit |
| E26 | Port < 1024 | `EACCES` | Reuse `tunnel.ts:92`'s message | unit |
| **Auth** |
| E27 | Wrong WG key | no handshake, ever | `handshake-timeout` + *"The server may not recognise this public key: `<pubkey>`"* (public key shown from the model, not the log) | integration |
| E28 | OpenVPN bad user/pass | `>PASSWORD:Verification Failed: 'Auth'` | `auth-failed`; do not retry with the same credentials (retry storms lock accounts); prompt once | fake binary |
| E29 | Static challenge / OTP | `SC:<flag>,<text>` on `>PASSWORD:` | Prompt via `VpnPromptModal`; `SCRV1:` response; **never cached** | fake binary |
| E30 | MFA re-prompt on reconnect | `RECONNECTING`→`AUTH` with `--auth-nocache` | Expected, not an error. Re-prompt; if the user is away, `state:'authenticating'` and wait, don't fail | fake binary |
| E31 | Expired client certificate | OpenVPN `certificate has expired`; TLS alert | `cert-expired` with the `notAfter` date parsed from the stored cert | unit: error mapping |
| E32 | Clock skew makes a valid cert look expired | cert `notBefore` in the future | `clock-skew` + *"Your system clock reads &lt;t&gt;; the certificate is valid from &lt;t2&gt;."* | unit |
| E33 | Wrong frp token | frpc stderr `authentication failed` | `auth-failed`, no restart loop | fake binary |
| E34 | Vault locked at start | `VaultLockedError` (`credentialResolver.ts:32`) | `vault-locked`; renderer's `withVaultUnlock` prompts; **never fall back** | unit |
| **Hostile config** |
| E35 | `.ovpn` with `up`/`script-security` → **RCE** | allowlist parser | **Hard reject the whole import**, quote the line, red banner | unit: 20+ hostile fixtures |
| E36 | `.ovpn` with `--config`, `--log`, `--status`, `--writepid` (arbitrary read/write) | allowlist | Hard reject | unit |
| E37 | `.ovpn` with `ca /etc/shadow` (path traversal) | realpath containment vs. baseDir | Reject; no file outside the import dir is ever read | unit |
| E38 | Server pushes dangerous directives | — | `--pull-filter reject` list, always emitted | unit: emitted argv |
| E39 | `wg-quick` `PostUp`/`PostDown` | parser | Hard reject | unit |
| E40 | frp `unix_domain_socket` → docker.sock | typed model | Plugin not offered in v1; raw-TOML import rejects it | unit |
| E41 | frp exposes a port publicly | every proxy | `acknowledgedExposure` required; MCP refuses frp outright | unit |
| **Binaries** |
| E42 | Bundled binary hash mismatch (tamper) | manifest verify on every run | Refuse to exec, `binary-untrusted` | unit: corrupt fixture |
| E43 | AV quarantined the sidecar | file missing / zero length | `binary-missing` naming AV + the exact path + a "Re-verify" button | unit |
| E44 | Windows PATH/CWD hijack of `openvpn.exe` | resolution order | **No PATH search on Windows**; `%ProgramFiles%` allowlist; user override requires a confirm | unit: resolver |
| E45 | User points at a random binary | resolution | Refuse relative paths, world-writable parents, escaping symlinks; audit path+hash | unit |
| **Process lifecycle** |
| E46 | App crashes, engine orphaned | pid file + identity check at startup | `reapOrphans()` verifies exe path **and** start time before killing | integration |
| E47 | PID reuse | start-time comparison | Never kill on pid alone | unit (mocked ps) |
| E48 | Stale run dir / socket / named pipe | startup sweep | Delete run dirs with no live run; unlink stale sockets before bind | unit |
| E49 | Two portable instances | separate `userData`, separate locks | `EADDRINUSE` message names the other instance; document | manual |
| E50 | Rapid start/stop toggling | in-flight map | `start()` awaits `stop()` first (`tunnel.ts:201` pattern); button disabled while `busy` (`TunnelManager.tsx:159`) | unit |
| E51 | Same profile started twice | manager map | Second call returns the live status, does not spawn | unit |
| E52 | Two profiles, same listen port | pre-bind check | `port-in-use` naming the other profile | unit |
| E53 | Two profiles, same interface name (system mode) | name registry | `interface-conflict` | unit |
| E54 | Engine wedged, never ready | `readinessTimeoutMs` | Kill, backoff, retry; crash-loop after 5 | unit (fake timers) |
| E55 | Crash loop | window counter | Terminal `error` + last 40 log lines; no further restarts | unit |
| E56 | Quit hangs on a wedged child | `Promise.race` + 4 s | `app.exit(0)` regardless; orphan reaped next launch | integration |
| **Logs** |
| E57 | Key printed in engine output | pattern rules + known values | `redactOutput` before the ring buffer | unit |
| E58 | Unbounded log growth | line **and** byte caps | Ring buffer, oldest dropped; a 4 MB single line cannot defeat a line-only cap | unit |
| E59 | `verb 11` log flood | parser clamps `verb` ≤ 4 | Clamp at import | unit |
| **Environment** |
| E60 | Portable mode, read-only install dir | run dir under `userData` (portable-redirected, `portable.ts:15`) | Never write beside the binary; verify bundled binaries are readable, not writable | integration (read-only fixture) |
| E61 | Corporate HTTP proxy | connect fails, proxy required | OpenVPN `--http-proxy`; frp `transport.proxyURL`; **WireGuard is UDP and cannot be proxied** — say so explicitly rather than failing mysteriously | unit: error mapping |
| E62 | TCP-over-TCP meltdown | `proto tcp` + slow link | Warn at import: *"TCP mode is slower and can stall under loss. Use UDP unless the network blocks it."* | unit: import warning |
| E63 | System time changed while connected | `Date.now()` jump > 60 s | Recompute handshake age from a monotonic base; never report a negative age | unit |
| E64 | `mtu` too large for the path | see E23 | — | manual |
| E65 | Raw stderr shown to the user | error mapper table | Every `errorCode` maps to a localizable message key + a suggested fix; the raw line stays in the log drawer only | unit: every code has a message |

---

## 9. Phased implementation plan

Each phase is independently shippable.

### Phase 0 — Foundations (3 days)
**New:** `src/shared/vpn.ts`; `src/main/services/vpn/{supervisor,binaries,runDir,errors,manager}.ts`
**Changed:** `src/main/services/secretRedaction.ts` (WG/frp/SCRV1 patterns); `src/main/index.ts` (async `before-quit` re-entry pattern, `:680`)
**Tests:** `tests/vpnSupervisor.test.ts` (backoff, crash-loop, graceful ordering, log-ring caps, fake timers), `tests/vpnBinaries.test.ts` (hash verify, resolver allowlist, Windows-no-PATH), `tests/vpnReap.test.ts` (pid identity + start-time), `tests/secretRedaction.test.ts` (+cases)
No UI. Internal only.

### Phase 1 — WireGuard userspace (6 days) ← the headline feature
**New:** `sidecar/netd/*.go` (~450 LOC) + `sidecar/netd/go.mod`; `.github/workflows/sidecar.yml` (6-target build matrix + `manifest.json` generation); `src/main/services/vpn/drivers/wireguard.ts`; `src/main/services/vpn/parsers/wgConf.ts`; `src/renderer/src/components/vpn/{VpnManager,VpnSidebar,VpnImportModal,VpnProfileForm,VpnStatusCard}.tsx`
**Changed:** `electron-builder.yml` (`extraResources` block); `src/preload/index.ts` (`vpn` namespace, after `:210`); `src/main/index.ts` (VPN IPC, after `:499`); `src/shared/vault.ts` (`'vpn'` kind at `:10`, `:68`, `:126`); `src/main/services/credentialResolver.ts` (`resolveVpnSecrets`); `src/renderer/src/types.ts:82-97` (replace the mock `VpnProfile`); `src/renderer/src/store/app.ts` (real actions on the existing `vpns` slice); `ActivityBar.tsx:9`, `Sidebar.tsx:15` (rename to "Tunnels & VPN")
**Tests:** `tests/wgConfParser.test.ts` (incl. `PostUp` rejection), `tests/vpnWireguard.integration.test.ts` (fake netd)
**Ships:** connect to a WireGuard peer, local SOCKS5 + forwards, live handshake/rx/tx, **zero admin rights, all three OSes**.

### Phase 2 — VPN as transport for SSH & DB (3 days)
**Changed:** `src/renderer/src/types.ts` (`vpnProfileId` on `Server`, `DatabaseConn`); `src/main/services/db.ts:40-79`; `src/main/services/ssh.ts:196`; `src/main/services/tunnel.ts` (VPN-aware `openChain`); `src/main/services/mcpDataCache.ts` (`CachedVpn`, `vpnProfileId` on server/db); `store/app.ts:601` (cascade); dependency graph + teardown ordering in `vpn/manager.ts`
**Tests:** `tests/vpnDependency.test.ts` (ordering, blocked delete, drop-closes-dependents)

### Phase 3 — OpenVPN (7 days) ← highest security risk
**New:** `src/main/services/vpn/drivers/openvpn.ts`; `src/main/services/vpn/openvpnManagement.ts`; `src/main/services/vpn/parsers/ovpn.ts` (**the sanitizer**); `src/main/services/vpn/elevation/{darwin,win32,linux}.ts`; `src/renderer/src/components/vpn/VpnPromptModal.tsx`; `tests/fixtures/ovpn/*.ovpn` (20+ hostile)
**Changed:** preload/main (prompter wiring, mirroring `setSshPrompter` at `ssh.ts:33`); `VpnImportModal.tsx` (stripped-directive report)
**Tests:** `tests/ovpnSanitizer.test.ts` (table-driven, one case per reject directive), `tests/ovpnManagement.test.ts` (recorded transcript), `tests/vpnOpenvpn.integration.test.ts` (fake openvpn)

### Phase 4 — frp (5 days)
**New:** `src/main/services/vpn/drivers/frp.ts`; `src/main/services/vpn/frpConfig.ts` (TOML generator); `src/main/services/vpn/frpAdminApi.ts`; `src/main/services/vpn/parsers/frpImport.ts` (INI→TOML converter + allowlist); `src/renderer/src/components/vpn/FrpProxyEditor.tsx`
**Changed:** `electron-builder.yml` (frpc in extraResources); sidecar CI workflow (build frpc from pinned source); `THIRD-PARTY-LICENSES.md` (+ frp `NOTICE`)
**Tests:** `tests/frpConfig.test.ts`, `tests/frpAdminApi.test.ts` (fake frpc HTTP server), exposure-gate tests

### Phase 5 — AI/MCP + audit (3 days)
**Changed:** `src/shared/mcp.ts:10-35`; `src/main/services/policyStore.ts:16-35` + backfill; `src/main/services/policyEngine.ts` (`evaluateVpnControl`); `src/main/services/mcpServer.ts` (`list_vpns`, `set_vpn` after `:1014`); `src/main/services/mcpDataCache.ts` (`listCachedVpns`); `src/renderer/src/components/ai/AiAccessGroups.tsx`; `docs/AI-SECURITY.md`, `docs/AI-MCP.md`
**Tests:** `tests/vpnPolicy.test.ts` (mirrors `dbTunnelPolicy.test.ts:94-102`), `tests/policyUpgrade.test.ts` (+`vpnControl` backfill), `tests/toolMetadata.integration.test.ts` (+2 tools)

### Phase 6 — System-mode WireGuard, routes, DNS, fail-closed (8 days) ← highest complexity, opt-in
**New:** `sidecar/netd/privileged_*.go`; `src/main/services/vpn/routing/{darwin,win32,linux}.ts`; `src/main/services/vpn/dns/{darwin,win32,linux}.ts`; route/DNS snapshot + restore-at-startup
**Changed:** `wireguard.ts` driver (mode branch); elevation modules; `VpnProfileForm` (mode toggle + warnings)
**Note:** macOS system mode stays **blocked** until a Developer ID exists.

### Phase 7 — Hardening & polish (4 days)
CLI `shellpilot vpn list|up|down|status` — **implemented as MCP tool calls over the existing paired session** (`src/cli/bridge.ts`, `src/cli/pairing.ts`), so it inherits `vpnControl` policy and approvals for free. **Never give the CLI a direct path into main.** Plus: localized error-message table, log drawer, WG QR import, `--management-external-key`, portable-mode verification, `docs/VPN.md`, README.

**Total ≈ 39 developer-days.**

---

## 10. Test strategy

**Unit (vitest, `tests/**`, `environment: 'node'`, electron aliased to `tests/mocks/electron.ts`):**
- **Config sanitizers** — table-driven, one case per rejected/dropped/allowed directive. 20+ hostile `.ovpn` fixtures (each RCE directive, nested `--config`, path traversal, `verb 11`, quote injection into management values), 10+ hostile `.conf` (`PostUp`, malformed base64, missing `[Peer]`), 10+ hostile frp TOML. **A CI check asserts every entry in the reject list has a fixture** — the allowlist and its tests must not drift.
- UAPI builder + `IpcGet` parser; management-interface line parser fed a recorded transcript; frp status mapper; supervisor backoff/crash-loop with fake timers; redaction; `evaluateVpnControl`; capability backfill.

**Integration with fake binaries** — the highest-value piece:
- `tests/fixtures/fake-openvpn.mjs` — speaks the management protocol: emits `>INFO:`, honours `--management-hold`, emits `>HOLD:`, `>PASSWORD:` (with and without `SC:`), `>STATE:` through the full ladder, `>BYTECOUNT:` on a timer, `>FATAL:`; accepts `state on`/`bytecount N`/`hold release`/`username`/`password`/`signal SIGTERM`. Scriptable failure modes via argv.
- `tests/fixtures/fake-frpc.mjs` — serves `/healthz`, `/api/status`, `/api/config`, `/api/reload`, `/api/stop` with Basic auth.
- `tests/fixtures/fake-netd.mjs` — speaks the NDJSON protocol.

All three are plain Node, cross-platform, and let the **entire lifecycle** run in CI with no real VPN: start → ready → stats → auth failure → OTP → crash → backoff → crash-loop → graceful stop → orphan reap → quit-under-wedge.

**Real-binary E2E**, gated on `VPN_E2E=1`, Linux-only, nightly: docker-compose with `linuxserver/wireguard`, an `frps`, and an OpenVPN server; assert a real handshake, real bytes, real proxy status.

**Manual matrix (per release):**

| Case | Win 11 | macOS (Intel) | macOS (arm) | Ubuntu 24 | Fedora | AppImage | Portable |
|---|---|---|---|---|---|---|---|
| WG userspace connect + SOCKS | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| WG stats + degraded on drop | ✓ | ✓ | ✓ | ✓ | ✓ | — | — |
| DB over WG | ✓ | ✓ | ✓ | ✓ | — | — | — |
| OpenVPN + UAC / interactive service | ✓ | — | — | — | — | — | — |
| OpenVPN + osascript sudo | — | ✓ | ✓ | — | — | — | — |
| OpenVPN + pkexec | — | — | — | ✓ | ✓ | ✓ | — |
| OpenVPN OTP | ✓ | ✓ | ✓ | ✓ | — | — | — |
| frp proxy + hot reload | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Sleep/wake reconnect | ✓ | ✓ | ✓ | ✓ | — | — | — |
| Wi-Fi→Ethernet roam | ✓ | ✓ | ✓ | ✓ | — | — | — |
| Kill app → orphan reaped | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Binary hash tamper refused | ✓ | ✓ | ✓ | ✓ | — | — | ✓ |

---

## 11. Open questions / decisions needed from the maintainer

1. **Go toolchain in the release pipeline.** Phase 1 requires building `shellpilot-netd` (and Phase 4 `frpc`) for 6 platform/arch targets in CI, adding roughly 25 MB to each installer. Acceptable? If not, WireGuard degrades to "bring your own `wireproxy`/`boringtun`", which is a materially worse product and I would rather drop WireGuard than ship that.
2. **Confirm the never-bundle-OpenVPN call**, and therefore that OpenVPN profiles show an "install openvpn" hint on a clean machine.
3. **macOS system mode.** Without a Developer ID, system-mode VPN on macOS means an `osascript` sudo prompt raised by an ad-hoc-signed, unnotarized app. My recommendation is to **block macOS system mode entirely** until a certificate exists, and ship userspace only there. Confirm?
4. **Workspace scoping.** VPN profiles workspace-scoped (matching the existing `vpns` slice and `Tunnel`) or global? Recommendation: workspace-scoped, with vault entries able to be shared via the existing `workspaceId?` escape hatch (`src/shared/vault.ts:16-28`).
5. **UI placement.** Recommendation is to rename the `tunnels` activity to "Tunnels & VPN" with three sections rather than add an eighth activity icon. Confirm, or do you want a separate icon?
6. **Kill switch.** A real fail-closed kill switch means OS firewall rules, elevation, and state that outlives a crash. Recommendation for v1: ship dependent-teardown-on-drop only and **do not use the words "kill switch"** anywhere in the UI or README. Confirm?
7. **`VaultKind: 'vpn'`** — adding it touches `VAULT_KIND_FIELDS`, which `tests/vaultKinds.test.ts` asserts coverage on, and shows a new type in the Vault UI. Preferred over overloading `'key'`/`'note'`?

---

## Sources

- [WireGuard cross-platform userspace / configuration protocol](https://www.wireguard.com/xplatform/)
- [golang.zx2c4.com/wireguard/tun/netstack](https://pkg.go.dev/golang.zx2c4.com/wireguard/tun/netstack)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go) (MIT)
- [cloudflare/boringtun](https://github.com/cloudflare/boringtun) (BSD-3)
- [windtf/wireproxy](https://github.com/windtf/wireproxy) (ISC)
- [OpenVPN management-notes.txt](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
- [OpenVPN COPYING](https://github.com/OpenVPN/openvpn/blob/master/COPYING) (GPL-2.0 + linking exceptions)
- [Reverse Shell from an OpenVPN Configuration File — Tenable](https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da)
- [All Roads Lead to OpenVPN — Claroty Team82](https://claroty.com/team82/research/all-roads-lead-to-openvpn-pwning-industrial-remote-access-clients)
- [fatedier/frp](https://github.com/fatedier/frp) (Apache-2.0), [client/api_router.go](https://github.com/fatedier/frp/blob/dev/client/api_router.go), [frpc_full_example.toml](https://github.com/fatedier/frp/blob/dev/conf/frpc_full_example.toml), [Configuration File docs](https://gofrp.org/en/docs/features/common/configure/)

---

### Critical Files for Implementation
- `/Users/zeeshan/ShellPilot/.claude/worktrees/vpn-client-implementation-c87bab/src/main/services/tunnel.ts`
- `/Users/zeeshan/ShellPilot/.claude/worktrees/vpn-client-implementation-c87bab/src/main/index.ts`
- `/Users/zeeshan/ShellPilot/.claude/worktrees/vpn-client-implementation-c87bab/src/main/services/credentialResolver.ts`
- `/Users/zeeshan/ShellPilot/.claude/worktrees/vpn-client-implementation-c87bab/src/main/services/policyEngine.ts`
- `/Users/zeeshan/ShellPilot/.claude/worktrees/vpn-client-implementation-c87bab/electron-builder.yml`

---

## Summary for the parent agent

**File path:** not written — read-only mode blocked it. Save the document above to `docs/plans/vpn-tunnel-clients.md`.

**Headline recommendation (5 bullets)**
- **WireGuard via our own MIT Go sidecar** (`wireguard-go` + gVisor `tun/netstack`), fully userspace, exposed as local SOCKS5/port-forwards — zero admin rights, and it reuses `openEphemeralForward`'s `{port, close}` shape so SSH-over-VPN and DB-over-VPN come nearly free.
- **Never bundle OpenVPN** (GPL-2.0 → perpetual per-platform corresponding-source obligation on an MIT project); detect a system install and drive it through the management interface with `--management-client --management-hold --management-query-passwords`.
- **Bundle `frpc` (Apache-2.0) v0.71.0**, TOML-only, controlled via its admin API (`/api/status`, `/api/reload`, `/api/stop`); secrets injected through frp's `{{ .Envs.X }}` templating, never argv.
- **Separate `VpnProfile` domain, not an extended `TunnelKind`** — the renderer's `vpns` slice already exists as a mock waiting to be replaced.
- **Every imported config is hostile input**: parse to a typed model against a strict allowlist and re-emit; `.ovpn` `up`/`script-security` and frp `unix_domain_socket` are RCE primitives and are hard-rejected, never silently stripped.

**Top 5 risks**
1. Config sanitization is the security-critical path — a gap in the `.ovpn` allowlist is an RCE inside a security tool.
2. Adding a Go build matrix + 2 bundled binaries to the release pipeline (size, macOS extraResources signing under hardened runtime, AV false positives on unsigned Go binaries).
3. GPL-2.0 re-entry through downstream packagers (an AppImage/Flatpak/cask that vendors `openvpn`).
4. Elevation UX on macOS with no Developer ID — a sudo prompt from an ad-hoc-signed, unnotarized app; `SMJobBless` is permanently unavailable.
5. Scope creep of system mode (routes, DNS, kill switch, restore-after-`kill -9`) — ~60% of the edge-case register for ~15% of the user value; it must stay in Phase 6 and stay opt-in.

**Phases**
| # | Phase | Days |
|---|---|---|
| 0 | Foundations: types, supervisor, binary integrity, run dirs, orphan reaper | 3 |
| 1 | WireGuard userspace (Go sidecar + driver + UI + vault kind) | 6 |
| 2 | VPN as transport for SSH/DB + dependency graph + quit ordering | 3 |
| 3 | OpenVPN (management interface, `.ovpn` sanitizer, elevation, OTP) | 7 |
| 4 | frp (TOML generator, admin API, exposure gating, hot reload) | 5 |
| 5 | AI/MCP `vpnControl` capability, `list_vpns`/`set_vpn`, audit | 3 |
| 6 | System-mode WireGuard: routes, DNS, fail-closed (opt-in) | 8 |
| 7 | Hardening & polish: CLI via MCP, error localization, QR import, docs | 4 |
| | **Total** | **39** |