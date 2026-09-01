# Third-Party Notices

ShellPilot is licensed under the [MIT Licence](LICENSE). It also incorporates
open-source software from other projects, distributed under their own
licenses. This file lists that software and satisfies the attribution
requirements of those licenses.

No third-party source code is vendored or copied into this repository. Most of
what is listed below is consumed as a normal npm package dependency,
unmodified. The exceptions are the components under **Bundled binaries**: they
are compiled from pinned upstream source at build time (or, for Wintun,
downloaded from the vendor and verified against a pinned hash) and shipped
inside the installer, so they are distributed rather than merely depended on.
Licenses for everything listed here are unmodified and are not affected by
ShellPilot's own license.

Three of the npm packages also carry **prebuilt native binaries** that npm
installs and the installer then ships: `ssh2`, `cpu-features` and
`@lydell/node-pty`. They stay in the npm tables rather than under **Bundled
binaries**, because that section is about provenance — code this repository's
own `scripts/` compile or fetch — and these arrive from the registry like any
other dependency. They are called out under **Key runtime dependencies** so
that "merely depended on" is not read as "not distributed".

**One shipped component is not open source.** `wintun.dll` is proprietary. It is
the only one, it is Windows-only, and it is described in full below rather than
left to a table — ShellPilot is presented as open-source software and that
claim should not have an unmentioned exception behind it.

This list was generated from the actual installed dependency tree
(`npm ls --all`), not by inspection of `package.json` alone, so it also
covers indirect (transitive) dependencies pulled in by the packages below.

## Bundled binaries

Built or fetched by the scripts in `scripts/`, verified against
`resources/bin/manifest.json`, and shipped inside the installer at
`Resources/bin/<platform>-<arch>/`. Unlike the npm packages below, these are
*distributed*, so their licence terms apply to the installer itself.

| Component | Version | License | Platforms | Source |
|---|---|---|---|---|
| `shellpilot-netd` | in-tree | MIT | all | `sidecar/netd/` in this repository |
| `wireguard-go` (linked into `shellpilot-netd`) | pinned in `sidecar/netd/go.mod` | MIT | all | `golang.zx2c4.com/wireguard` |
| gVisor `netstack` (linked into `shellpilot-netd`) | pinned in `sidecar/netd/go.mod` | Apache-2.0 | all | `gvisor.dev/gvisor` |
| `frpc` | v0.71.0 | Apache-2.0 | all | `github.com/fatedier/frp` |
| `openvpn` | v2.6.22 | **GPL-2.0** with OpenSSL exception | macOS, Linux | `github.com/OpenVPN/openvpn` |
| OpenSSL (statically linked into `openvpn`) | 3.5.8 | Apache-2.0 | macOS, Linux | `github.com/openssl/openssl` |
| `wintun.dll` | 0.14.1 | **Proprietary** — see below | Windows | `wintun.net/builds` (prebuilt, unmodified) |

Apache-2.0 section 4 requires the licence text and any `NOTICE` file to travel
with the binary. `scripts/build-frpc.sh` copies frp's `LICENSE` and `NOTICE`
into `resources/licenses/frp/`, which ships inside the app. The same is done
for OpenVPN (`resources/licenses/openvpn/`) and Wintun
(`resources/licenses/wintun/`).

### OpenVPN is bundled on macOS and Linux, and it is GPL-2.0

`scripts/build-openvpn.sh` compiles OpenVPN 2.6.22 from the pinned upstream tag
and ships the result inside the installer. Two things follow from that, and
neither is optional.

**ShellPilot stays MIT.** OpenVPN 2.x is GPL-2.0 (with an OpenSSL linking
exception, which is what makes the static OpenSSL link lawful). ShellPilot does
not link against OpenVPN: it starts `openvpn` as a *separate process* and
drives it over OpenVPN's own management socket — separate address space, no
shared symbols, a documented control protocol. That is GPL-2.0 §2 "mere
aggregation" — two programs on one medium, not one combined work — so the GPL
does not reach ShellPilot's own source.

**ShellPilot owes you the source.** What bundling *does* create is the GPL-2.0
§3 obligation that falls on anyone who distributes GPL binaries. It is
discharged by publication, not by an offer: every ShellPilot release that
contains an OpenVPN binary also carries `openvpn-<version>-source.tar.gz` as a
release asset — a `git archive` of the exact commit that was compiled, with its
SHA-256 in the release's checksum table. `scripts/build-openvpn.sh` in this
repository is the recipe that turns that source into the shipped binary, and it
pins the tag, the commit hash, the OpenSSL version and the OpenSSL tarball
hash. Nothing about the build depends on what happened to be installed on the
machine that ran it.

The build switches off `--enable-plugins`, `--enable-lzo`, `--enable-lz4`,
`--enable-pkcs11` and `--enable-dco`. Removing plugin support is a security
decision as much as a size one: ShellPilot already rejects `plugin` directives
when importing a `.ovpn`, and a binary that cannot load a plugin cannot be
talked into loading one.

**Windows is the exception, and still needs an install.** OpenVPN on Windows
needs a tun adapter driver, and neither of the two available drivers can be
provided by copying a file. `tap-windows6` is a kernel driver with its own
installer. Wintun would seem to be the way out — ShellPilot does bundle
`wintun.dll` — but `openvpn.exe` never loads it: it opens an adapter that
already exists (`at_least_one_tap_win` in `tun.c`) and has no code path that
calls `WintunCreateAdapter`, which is the only way an adapter, and Wintun's
driver, come into being. So on Windows ShellPilot still drives an OpenVPN the
user installed, whose installer brings the driver — and the Interactive
Service, which removes the elevation prompt on every connect.

**Bundling removes the install, not the administrator prompt.** OpenVPN has no
userspace mode: it needs a TUN device, so it needs elevation, and ShellPilot
still asks on every connect. That was true before this change and is true
after it.

**If you repackage ShellPilot** — an AppImage, a Flatpak, a Homebrew cask, a
distro package — the GPL-2.0 §3 obligation for the OpenVPN binary inside it
travels with your package and lands on **you**. The source archive on the
matching ShellPilot release is what you need to redistribute alongside it.

### Wintun is bundled on Windows, and it is **not open source**

This is the one component in ShellPilot that is proprietary software, and it is
stated here in the open rather than filed in a table.

`wintun.dll` is the userspace half of the Wintun network adapter driver.
Windows **system mode** — WireGuard with a real network interface — cannot work
without it. Wintun's *source* is GPL-2.0, but the prebuilt DLLs published at
wintun.net are not: they carry a separate **"Prebuilt Binaries License"** from
WireGuard LLC, which is proprietary and is the only terms under which
redistribution is permitted at all. The full text ships in the app at
`resources/licenses/wintun/LICENSE.txt`.

Redistribution is permitted here because clause 3(d) allows it "insofar as the
Software is distributed alongside other software that uses the Software only
via the Permitted API" — the interfaces declared in `wintun.h`. ShellPilot's
sidecar uses exactly that API, through `golang.zx2c4.com/wintun`, and nothing
else. The conditions that come with it are honoured as follows:

- **Unmodified.** `scripts/fetch-wintun.sh` copies `wintun.dll` straight out of
  the official signed ZIP. It is never rebuilt, repacked, stripped or re-signed
  (clause 3(a)).
- **Nothing extracted from it.** The DLL carries Wintun's kernel driver inside
  it and installs it itself on first use. ShellPilot does not unpack that
  (clause 3(a)).
- **Its notices travel with it.** `LICENSE.txt` is copied into
  `resources/licenses/wintun/` and ships in the installer (clause 3(c)).
- **No endorsement is implied.** ShellPilot is not affiliated with, and not
  endorsed by, WireGuard LLC or the Wintun project (clause 3(e)).

The ZIP is pinned by SHA-256 (`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
for 0.14.1) and verified on every build, because HTTPS authenticates the host
and says nothing about the bytes.

**If a proprietary component in the installer is not acceptable to you**, the
DLL is only reached by WireGuard *system* mode on Windows. Userspace mode — the
default, on every platform — never loads it, and deleting
`resources/bin/win32-*/wintun.dll` from a build removes it entirely at the cost
of that one feature.

### Trademarks

WireGuard is a registered trademark of Jason A. Donenfeld. OpenVPN is a
registered trademark of OpenVPN Inc. ShellPilot is not affiliated with or
endorsed by either project, nor by fatedier and the frp contributors.

## Key runtime dependencies

These are the libraries ShellPilot is built directly on top of. Some are
declared under `devDependencies` in `package.json` because a bundler
(Vite/electron-vite) compiles them into the application rather than loading
them from `node_modules` at runtime (noted below) — they are still part of
what ships in the packaged app and are attributed here for that reason.

| Package | Version | License | Role |
|---|---|---|---|
| Electron | 43.4.1 | MIT | Desktop application runtime (Chromium + Node.js) |
| React | 19.2.8 | MIT | UI framework (bundled into the renderer) |
| React DOM | 19.2.8 | MIT | UI framework (bundled into the renderer) |
| scheduler | 0.27.0 | MIT | React's internal scheduler (bundled into the renderer) |
| @xterm/xterm | 5.5.0 | MIT | Terminal emulator |
| @xterm/addon-fit, addon-search, addon-web-links, addon-webgl | 0.10.0 / 0.15.0 / 0.11.0 / 0.18.0 | MIT | xterm.js addons |
| @lydell/node-pty | 1.2.0-beta.15 | MIT | Pseudo-terminal for local shells — pinned to an exact version, and it ships native binaries (see below) |
| ssh2 | 1.17.0 | MIT | SSH/SFTP client |
| mongodb | 7.5.0 | Apache-2.0 | MongoDB driver |
| mssql | 12.7.0 | MIT | SQL Server driver |
| mysql2 | 3.23.4 | MIT | MySQL/MariaDB driver |
| pg | 8.23.0 | MIT | PostgreSQL driver |
| ioredis | 6.0.0 | MIT | Redis client |
| zustand | 5.0.15 | MIT | Application state management |
| lucide-react | 0.469.0 | ISC | Icon set |
| clsx | 2.1.1 | MIT | Class-name utility |
| zod | 4.4.3 | MIT | Schema validation |
| @modelcontextprotocol/sdk | 1.30.0 | MIT | MCP server implementation (AI agent bridge) |
| electron-updater | 6.8.9 | MIT | Auto-update client |
| electron-builder | 26.15.3 | MIT | Packaging tool only — a build-time dependency, not distributed inside the packaged app |

Electron itself bundles Chromium, V8 and Node.js under their own upstream
licenses (BSD-style and MIT). ShellPilot redistributes these only as the
official, unmodified Electron binary via `electron-builder` and does not
alter or separately relicense them.

### `@lydell/node-pty` is an npm dependency that ships executables

It is listed here rather than under **Bundled binaries** because that is what it
is: a package `npm ci` installs, pinned to the exact string `1.2.0-beta.15` in
`package.json` — not a caret range, so a later beta cannot arrive on its own.
Nothing in `scripts/` builds or fetches it, and it is not verified against
`resources/bin/manifest.json`, which is what everything in that other table has
in common. `ssh2` and `cpu-features` are in the same position and are listed the
same way.

It is worth naming separately anyway, because it is the furthest an npm package
in this tree goes toward being a shipped binary. `@lydell/node-pty` itself is a
five-file meta package with no binary in it; at runtime it requires
`@lydell/node-pty-${process.platform}-${process.arch}`, and that sibling —
installed for one platform and architecture only, via `optionalDependencies`
gated on `os`/`cpu` — is where `prebuilds/<platform>-<arch>/` holds:

- **`pty.node`**, a Node-API binding, `dlopen`ed like `ssh2`'s and
  `cpu-features`'.
- **`spawn-helper`** on macOS and Linux, a Mach-O/ELF **executable** that node-pty
  `posix_spawn`s for every session. That is a program in the installer, not a
  library — which is why `electron-builder.yml` unpacks the whole package
  directory out of the asar archive (a `*.node` glob would leave the helper
  inside, with no path on disk to hand to `posix_spawn`) and why the release
  verifier asserts its `+x` bit.

Both packages are MIT. The sibling's `LICENSE` carries three notices — Christopher
Jeffrey (`pty.js`), Daniel Imms and Microsoft (`node-pty`) — reproduced unmodified
in the package as installed, which is what MIT attribution requires; this fork
adds Simon Lydell's own MIT notice on the meta package. Upstream is
`github.com/lydell/node-pty`, a repackaging of `github.com/microsoft/node-pty`.

## Full dependency license inventory (production tree)

Every package below is a direct or transitive **production** dependency —
i.e. code that can end up inside the packaged, distributed application.
Build-only tooling (TypeScript, Vite, Vitest, esbuild, electron-builder,
`@types/*`, etc.) is excluded, since it never ships. License data comes
from each package's own `package.json`.

License summary: **201 MIT · 12 ISC · 7 BSD-3-Clause · 7 Apache-2.0 · 2
BlueOak-1.0.0 · 2 BSD-2-Clause · 1 Python-2.0 · 1 0BSD · 1 Unlicense** — 234
packages total. No GPL, AGPL, LGPL, SSPL, or proprietary-licensed
dependencies were found anywhere in the tree.

That statement is about the **npm tree only**. It is not a statement about the
installer, which also contains a GPL-2.0 program (`openvpn`) and a proprietary
library (`wintun.dll`) — both described under **Bundled binaries** above.

The count includes one `@lydell/node-pty-<platform>-<arch>` sibling. Six of them
exist upstream, each declaring `os` and `cpu`, so `npm ci` installs only the one
matching the host and a tree installed elsewhere carries a differently named
package in that row. The macOS release job installs both `darwin` siblings
deliberately, because it packs an x64 and an arm64 dmg out of one `node_modules`
(see `.github/workflows/release.yml`). All six are MIT, so none of this changes
the licence position.

<details>
<summary>Full list (click to expand)</summary>

| Package | Version | License |
|---|---|---|
| @azure-rest/core-client | 2.8.0 | MIT |
| @azure/abort-controller | 2.2.0 | MIT |
| @azure/core-auth | 1.11.0 | MIT |
| @azure/core-client | 1.11.0 | MIT |
| @azure/core-lro | 2.7.2 | MIT |
| @azure/core-paging | 1.7.0 | MIT |
| @azure/core-process | 1.0.0 | MIT |
| @azure/core-rest-pipeline | 1.25.0 | MIT |
| @azure/core-tracing | 1.4.0 | MIT |
| @azure/core-util | 1.14.0 | MIT |
| @azure/identity | 4.13.2 | MIT |
| @azure/keyvault-common | 2.1.0 | MIT |
| @azure/keyvault-keys | 4.10.2 | MIT |
| @azure/logger | 1.4.0 | MIT |
| @azure/msal-browser | 5.19.0 | MIT |
| @azure/msal-common | 16.13.0 | MIT |
| @azure/msal-node | 5.6.0 | MIT |
| @hono/node-server | 2.1.1 | MIT |
| @ioredis/commands | 2.0.0 | MIT |
| @js-joda/core | 6.1.0 | BSD-3-Clause |
| @lydell/node-pty | 1.2.0-beta.15 | MIT |
| @lydell/node-pty-`<platform>`-`<arch>` | 1.2.0-beta.15 | MIT |
| @modelcontextprotocol/sdk | 1.30.0 | MIT |
| @mongodb-js/saslprep | 1.5.0 | MIT |
| @tediousjs/connection-string | 1.1.0 | MIT |
| @types/node | 22.20.1 | MIT |
| @types/react | 19.2.18 | MIT |
| @types/readable-stream | 4.0.24 | MIT |
| @types/webidl-conversions | 7.0.3 | MIT |
| @types/whatwg-url | 13.0.0 | MIT |
| @typespec/ts-http-runtime | 0.3.8 | MIT |
| @xterm/addon-fit | 0.10.0 | MIT |
| @xterm/addon-search | 0.15.0 | MIT |
| @xterm/addon-web-links | 0.11.0 | MIT |
| @xterm/addon-webgl | 0.18.0 | MIT |
| @xterm/xterm | 5.5.0 | MIT |
| abort-controller | 3.0.0 | MIT |
| accepts | 2.0.0 | MIT |
| agent-base | 7.1.4 | MIT |
| ajv | 8.20.0 | MIT |
| ajv-formats | 3.0.1 | MIT |
| argparse | 2.0.1 | Python-2.0 |
| asn1 | 0.2.6 | MIT |
| aws-ssl-profiles | 1.1.2 | MIT |
| base64-js | 1.5.1 | MIT |
| bcrypt-pbkdf | 1.0.2 | BSD-3-Clause |
| bl | 6.1.6 | MIT |
| body-parser | 2.3.0 | MIT |
| bson | 7.3.2 | Apache-2.0 |
| buffer | 6.0.3 | MIT |
| buffer-equal-constant-time | 1.0.1 | BSD-3-Clause |
| buildcheck | 0.0.7 | MIT |
| builder-util-runtime | 9.7.0 | MIT |
| bundle-name | 4.1.0 | MIT |
| bytes | 3.1.2 | MIT |
| call-bind-apply-helpers | 1.0.2 | MIT |
| call-bound | 1.0.4 | MIT |
| clsx | 2.1.1 | MIT |
| cluster-key-slot | 1.1.1 | Apache-2.0 |
| commander | 11.1.0 | MIT |
| content-disposition | 1.1.0 | MIT |
| content-type | 1.0.5 | MIT |
| content-type | 2.1.0 | MIT |
| cookie | 0.7.2 | MIT |
| cookie-signature | 1.2.2 | MIT |
| cors | 2.8.6 | MIT |
| cpu-features | 0.0.10 | MIT |
| cross-spawn | 7.0.6 | MIT |
| csstype | 3.2.3 | MIT |
| debug | 4.4.3 | MIT |
| default-browser | 5.5.1 | MIT |
| default-browser-id | 5.0.1 | MIT |
| define-lazy-prop | 3.0.0 | MIT |
| denque | 2.1.0 | Apache-2.0 |
| depd | 2.0.0 | MIT |
| dunder-proto | 1.0.1 | MIT |
| ecdsa-sig-formatter | 1.0.11 | Apache-2.0 |
| ee-first | 1.1.1 | MIT |
| electron-updater | 6.8.9 | MIT |
| encodeurl | 2.0.0 | MIT |
| es-define-property | 1.0.1 | MIT |
| es-errors | 1.3.0 | MIT |
| es-object-atoms | 1.1.2 | MIT |
| escape-html | 1.0.3 | MIT |
| etag | 1.8.1 | MIT |
| event-target-shim | 5.0.1 | MIT |
| events | 3.3.0 | MIT |
| eventsource | 3.0.7 | MIT |
| eventsource-parser | 3.1.1 | MIT |
| express | 5.2.1 | MIT |
| express-rate-limit | 8.6.2 | MIT |
| fast-deep-equal | 3.1.3 | MIT |
| fast-uri | 3.1.5 | BSD-3-Clause |
| finalhandler | 2.1.1 | MIT |
| forwarded | 0.2.0 | MIT |
| fresh | 2.0.0 | MIT |
| fs-extra | 10.1.0 | MIT |
| function-bind | 1.1.2 | MIT |
| generate-function | 2.3.1 | MIT |
| get-intrinsic | 1.3.0 | MIT |
| get-proto | 1.0.1 | MIT |
| gopd | 1.2.0 | MIT |
| graceful-fs | 4.2.11 | ISC |
| has-symbols | 1.1.0 | MIT |
| hasown | 2.0.4 | MIT |
| hono | 4.13.4 | MIT |
| http-errors | 2.0.1 | MIT |
| http-proxy-agent | 7.0.2 | MIT |
| https-proxy-agent | 7.0.6 | MIT |
| iconv-lite | 0.7.3 | MIT |
| ieee754 | 1.2.1 | BSD-3-Clause |
| inherits | 2.0.4 | ISC |
| ioredis | 6.0.0 | MIT |
| ip-address | 10.5.0 | MIT |
| ipaddr.js | 1.9.1 | MIT |
| is-docker | 3.0.0 | MIT |
| is-inside-container | 1.0.0 | MIT |
| is-promise | 4.0.0 | MIT |
| is-property | 1.0.2 | MIT |
| is-wsl | 3.1.1 | MIT |
| isexe | 2.0.0 | BlueOak-1.0.0 |
| jose | 6.2.10 | MIT |
| js-md4 | 0.3.2 | MIT |
| js-yaml | 4.3.1 | MIT |
| json-schema-traverse | 1.0.0 | MIT |
| json-schema-typed | 8.0.2 | BSD-2-Clause |
| jsonfile | 6.2.1 | MIT |
| jsonwebtoken | 9.0.3 | MIT |
| jwa | 2.0.1 | MIT |
| jws | 4.0.1 | MIT |
| lazy-val | 1.0.5 | MIT |
| lodash.escaperegexp | 4.1.2 | MIT |
| lodash.includes | 4.3.0 | MIT |
| lodash.isboolean | 3.0.3 | MIT |
| lodash.isequal | 4.5.0 | MIT |
| lodash.isinteger | 4.0.4 | MIT |
| lodash.isnumber | 3.0.3 | MIT |
| lodash.isplainobject | 4.0.6 | MIT |
| lodash.isstring | 4.0.1 | MIT |
| lodash.once | 4.1.1 | MIT |
| long | 5.3.2 | Apache-2.0 |
| lru.min | 1.1.4 | MIT |
| lucide-react | 0.469.0 | ISC |
| math-intrinsics | 1.1.0 | MIT |
| media-typer | 1.1.1 | MIT |
| memory-pager | 1.5.0 | MIT |
| merge-descriptors | 2.0.0 | MIT |
| mime-db | 1.54.0 | MIT |
| mime-types | 3.0.2 | MIT |
| mongodb | 7.5.0 | Apache-2.0 |
| mongodb-connection-string-url | 7.0.2 | Apache-2.0 |
| ms | 2.1.3 | MIT |
| mssql | 12.7.0 | MIT |
| mysql2 | 3.23.4 | MIT |
| named-placeholders | 1.1.6 | MIT |
| nan | 2.28.0 | MIT |
| native-duplexpair | 1.0.0 | MIT |
| negotiator | 1.1.0 | MIT |
| object-assign | 4.1.1 | MIT |
| object-inspect | 1.13.4 | MIT |
| on-finished | 2.4.1 | MIT |
| once | 1.4.0 | ISC |
| open | 10.2.0 | MIT |
| parseurl | 1.3.3 | MIT |
| path-key | 3.1.1 | MIT |
| path-to-regexp | 8.4.2 | MIT |
| pg | 8.23.0 | MIT |
| pg-cloudflare | 1.4.0 | MIT |
| pg-connection-string | 2.14.0 | MIT |
| pg-int8 | 1.0.1 | ISC |
| pg-pool | 3.14.0 | MIT |
| pg-protocol | 1.16.0 | MIT |
| pg-types | 2.2.0 | MIT |
| pgpass | 1.0.5 | MIT |
| pkce-challenge | 5.0.1 | MIT |
| postgres-array | 2.0.0 | MIT |
| postgres-bytea | 1.0.1 | MIT |
| postgres-date | 1.0.7 | MIT |
| postgres-interval | 1.2.0 | MIT |
| process | 0.11.10 | MIT |
| proxy-addr | 2.0.7 | MIT |
| punycode | 2.3.1 | MIT |
| qs | 6.15.3 | BSD-3-Clause |
| range-parser | 1.3.0 | MIT |
| raw-body | 3.0.2 | MIT |
| react | 19.2.8 | MIT |
| readable-stream | 4.7.0 | MIT |
| redis-errors | 1.2.0 | MIT |
| require-from-string | 2.0.2 | MIT |
| router | 2.2.0 | MIT |
| run-applescript | 7.1.0 | MIT |
| safe-buffer | 5.2.1 | MIT |
| safer-buffer | 2.1.2 | MIT |
| sax | 1.6.1 | BlueOak-1.0.0 |
| semver | 7.7.4 | ISC |
| semver | 7.8.5 | ISC |
| send | 1.2.1 | MIT |
| serve-static | 2.2.1 | MIT |
| setprototypeof | 1.2.0 | ISC |
| shebang-command | 2.0.0 | MIT |
| shebang-regex | 3.0.0 | MIT |
| side-channel | 1.1.1 | MIT |
| side-channel-list | 1.0.1 | MIT |
| side-channel-map | 1.0.1 | MIT |
| side-channel-weakmap | 1.0.2 | MIT |
| sparse-bitfield | 3.0.3 | MIT |
| split2 | 4.2.0 | ISC |
| sprintf-js | 1.1.3 | BSD-3-Clause |
| sql-escaper | 1.5.1 | MIT |
| ssh2 | 1.17.0 | MIT |
| standard-as-callback | 2.1.0 | MIT |
| statuses | 2.0.2 | MIT |
| string_decoder | 1.3.0 | MIT |
| tarn | 3.1.2 | MIT |
| tedious | 20.0.0 | MIT |
| tiny-typed-emitter | 2.1.0 | MIT |
| toidentifier | 1.0.1 | MIT |
| tr46 | 5.1.1 | MIT |
| tslib | 2.8.1 | 0BSD |
| tweetnacl | 0.14.5 | Unlicense |
| type-is | 2.1.0 | MIT |
| undici-types | 6.21.0 | MIT |
| universalify | 2.0.1 | MIT |
| unpipe | 1.0.0 | MIT |
| vary | 1.1.2 | MIT |
| webidl-conversions | 7.0.0 | BSD-2-Clause |
| whatwg-url | 14.2.0 | MIT |
| which | 2.0.2 | ISC |
| wrappy | 1.0.2 | ISC |
| wsl-utils | 0.1.0 | MIT |
| xtend | 4.0.2 | MIT |
| zod | 4.4.3 | MIT |
| zod-to-json-schema | 3.25.2 | ISC |
| zustand | 5.0.15 | MIT |
| react-dom | 19.2.8 | MIT (devDependency in package.json; bundled into the renderer by Vite, so listed here for completeness) |
| scheduler | 0.27.0 | MIT (transitive dependency of react-dom; bundled into the renderer) |

</details>

## Notes and flagged items

- **BlueOak-1.0.0** (`isexe`, `sax`): a modern, OSI-approved permissive
  license, comparable to MIT/ISC in what it allows. Not copyleft, not a
  compliance concern — flagged only because it is less common than MIT/ISC.
- **No GPL, LGPL, AGPL, or SSPL dependencies** were found in the production
  dependency tree. The bundled `openvpn` binary is GPL-2.0 and is not an npm
  dependency; see **Bundled binaries** for how that obligation is met.
- **No proprietary or "custom" licenses** were found; every package resolves
  to a standard SPDX identifier. The bundled `wintun.dll` is proprietary and,
  likewise, is not an npm dependency; see **Bundled binaries**.
- **No dependency had an unverifiable or missing license field** in the
  production tree audited above.
- This file was generated by walking the installed `node_modules` tree with
  `npm ls --all --omit=dev` and reading each package's own `license` field —
  it was not hand-typed or guessed. If a dependency's declared `license`
  field is later found to be inaccurate upstream, that inaccuracy would need
  correcting at the source package, not here.
- Regenerate this file after upgrading or adding a production dependency,
  since the list above is a snapshot of the tree as installed at the time
  of the Apache-2.0 migration.
