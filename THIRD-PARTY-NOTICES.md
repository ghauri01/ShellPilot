# Third-Party Notices

ShellPilot is licensed under the [MIT Licence](LICENSE). It also incorporates
open-source software from other projects, distributed under their own
licenses. This file lists that software and satisfies the attribution
requirements of those licenses.

No third-party source code is vendored or copied into this repository. Most of
what is listed below is consumed as a normal npm package dependency,
unmodified. The exception is the two tunnel engines described under **Bundled
binaries**: they are compiled from pinned upstream source at build time and
shipped inside the installer, so they are distributed rather than merely
depended on. Licenses for everything listed here are unmodified and are not
affected by ShellPilot's own license.

This list was generated from the actual installed dependency tree
(`npm ls --all`), not by inspection of `package.json` alone, so it also
covers indirect (transitive) dependencies pulled in by the packages below.

## Bundled binaries

Compiled from pinned upstream source by `scripts/build-sidecar.sh` and
`scripts/build-frpc.sh`, verified against `resources/bin/manifest.json`, and
shipped inside the installer at `Resources/bin/<platform>-<arch>/`. Unlike the
npm packages below, these are *distributed*, so their licence terms apply to
the installer itself.

| Component | Version | License | Source |
|---|---|---|---|
| `shellpilot-netd` | in-tree | MIT | `sidecar/netd/` in this repository |
| `wireguard-go` (linked into `shellpilot-netd`) | pinned in `sidecar/netd/go.mod` | MIT | `golang.zx2c4.com/wireguard` |
| gVisor `netstack` (linked into `shellpilot-netd`) | pinned in `sidecar/netd/go.mod` | Apache-2.0 | `gvisor.dev/gvisor` |
| `frpc` | v0.71.0 | Apache-2.0 | `github.com/fatedier/frp` |

Apache-2.0 section 4 requires the licence text and any `NOTICE` file to travel
with the binary. `scripts/build-frpc.sh` copies frp's `LICENSE` and `NOTICE`
into `resources/licenses/frp/`, which ships inside the app.

### OpenVPN is deliberately **not** bundled

OpenVPN 2.x is **GPL-2.0** and ShellPilot is MIT. ShellPilot supports OpenVPN by detecting a copy the user has already
installed and driving it over its management interface as a separate process —
it never links against it and never ships it.

This is a deliberate distribution decision, not an oversight. Bundling the
binary would put ShellPilot in the position of *distributing* GPL-2.0 software,
carrying a corresponding-source obligation (GPL-2.0 §3) for every platform
build, in perpetuity. Running an independently-installed program as a separate
process over a documented control protocol is ordinary use: it creates no
combined work and no source obligation.

Practical consequences, which the app states in its own UI rather than leaving
the user to discover:

- An OpenVPN profile cannot connect until OpenVPN is installed. ShellPilot says
  so, and says where to get it.
- ShellPilot resolves the binary from a fixed allowlist of standard install
  locations, and on POSIX only, also `PATH`. It never searches `PATH` on
  Windows, where `PATH`/CWD search is a well-known hijack vector.
- The resolved path, version and SHA-256 are recorded in the audit log on first
  use and whenever they change.

**If you repackage ShellPilot** — an AppImage, a Flatpak, a Homebrew cask, a
distro package — and you vendor `openvpn` into that package, the GPL obligation
lands on **you**, not on this project.

### Wintun is not bundled either

Windows **system mode** needs `wintun.dll`, the adapter driver the WireGuard
project ships. ShellPilot does not include it; installing
[WireGuard for Windows](https://www.wireguard.com/install/) provides it, and
userspace mode — the default — needs nothing.

Unlike OpenVPN this is not a licence obstacle. Wintun's *source* is GPL-2.0, but
wintun.net states the precompiled signed DLLs are released under "a more
permissive license than GPL 2.0", and that those signed DLLs are the only
supported way to redistribute Wintun. Bundling them is therefore likely
permissible; it has not been done because the exact terms live in the licence
file inside the official ZIP, and a redistribution decision should be made by a
human who has read it rather than inferred from a summary.

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

## Full dependency license inventory (production tree)

Every package below is a direct or transitive **production** dependency —
i.e. code that can end up inside the packaged, distributed application.
Build-only tooling (TypeScript, Vite, Vitest, esbuild, electron-builder,
`@types/*`, etc.) is excluded, since it never ships. License data comes
from each package's own `package.json`.

License summary: **199 MIT · 12 ISC · 7 BSD-3-Clause · 7 Apache-2.0 · 2
BlueOak-1.0.0 · 2 BSD-2-Clause · 1 Python-2.0 · 1 0BSD · 1 Unlicense** — 232
packages total. No GPL, AGPL, LGPL, SSPL, or proprietary-licensed
dependencies were found anywhere in the tree.

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
  dependency tree.
- **No proprietary or "custom" licenses** were found; every package resolves
  to a standard SPDX identifier.
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
