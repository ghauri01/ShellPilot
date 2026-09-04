# Docker fixtures

## Provenance, which matters more than it looks

`tests/engineAdvisories.test.ts` records the rule this directory follows: a fixture
invented from documentation is the thing most likely to be wrong, because it agrees
with whatever the parser author believed the format was. So provenance is stated per
file rather than assumed.

| File | Provenance |
|---|---|
| `system-df-v-docker-29.txt` | **Structure recorded from a real `docker system df -v` on Docker 29.5.3** — column positions, header spellings, the unicode ellipsis docker truncates `COMMAND` with, and the `Up 7 days (healthy)` status form are all verbatim. Identifiers, image names and container names were replaced, because the recording host was somebody's actual machine and this repository is public. Four rows were **added by hand** to cover states the recording host did not have: a `<none>:<none>` dangling image, an `Exited (137)` container, a `Created` container, and two volumes with `LINKS 0` — one anonymous, one named. |
| `compose-ls-docker-29.json` | **Recorded verbatim from `docker compose ls --all --format json` on Docker 29.5.3 / Compose v5.1.4**, against a three-project host. Project names and paths replaced; see the sanitisation note below. |
| `compose-ls-docker-29.txt` | The **same command's table form, recorded on the same run**. Kept alongside the JSON because a host whose compose predates `--format json` still answers the table, and because the table is where the column hazards are. |
| `compose-ls-partial-docker-29.txt` | **Recorded** from the same host after `docker compose stop worker`, to capture the compound `exited(1), running(2)` status. This is a separate recording, not the file above edited. |
| `compose-config-safe-docker-29.json` | **Recorded from `docker compose config --format json --no-interpolate --no-env-resolution`** on a purpose-built three-service project (nginx + redis + busybox) started for the recording and torn down after. |
| `compose-config-interpolated-docker-29.json` | **The same project, same run, same command WITHOUT those two flags.** It is here because it is the evidence: it contains `"REDIS_PASSWORD": "hunter2-not-a-real-password"` and `"WORKER_API_TOKEN": "tok-not-a-real-token"`, both resolved by compose out of a `.env` and an `env_file`. `tests/compose.test.ts` asserts that this file contains them and that its sibling does not, so if docker ever changes what those flags do, a test fails rather than a secret leaking. The two "secrets" are strings invented for the recording; nothing real was ever in this project. |
| `compose-ps-docker-29.txt` | **Recorded from `docker compose ps --all`** on the same project. Not currently parsed — the running half comes from the container labels `shared/docker.ts` already reads — and kept because it is the shape any future `compose ps` parser has to survive. |
| `reclaim-removed-docker-29.txt` | **Recorded from a real `docker rm` / `rmi` / `volume rm` / `network rm` on Docker 29.5.3**, against objects created for the recording and removed by it. See "recording a removal" below. |
| `reclaim-refused-docker-29.txt` | **A separate recording on the same host**, of the same four commands aimed at objects docker refuses to remove: a running container, an id that does not exist, an image held by a stopped container, an image held by a running one, and a volume in use. Nothing was removed by this run — which is why it could be recorded at all. |
| `reclaim-refused-shortname-docker-29.txt` | **A separate recording of one `docker volume rm` against a busy volume literally called `data`.** The short name is the entire reason it exists: references are matched longest-first, and a four-character volume name sorts *behind* the twelve-character container id that docker prints inside the refusal. A parser that pools the four blocks hands this line to the container and leaves the volume saying nothing happened, and no recording with a long volume name can catch that. |
| `reclaim-multitag-docker-29.txt` | **A third separate recording**, of `docker rmi <id>` against an image carrying two tags and no containers. It is here because it is the evidence for a claim `planDockerReclaim` makes in a caveat, and the claim is not obvious: on 29.5.3 removing a multi-tagged image BY ID is refused outright rather than silently untagging one of them. |

### Recording a removal, and the marker lines

The three `reclaim-*` files are the only fixtures in this directory whose lines are
not all docker's. The `===SHELLPILOT-RM…===` and `===SHELLPILOT-END===` lines are
**this repository's own**, echoed by `buildDockerReclaimCommand` between the four
docker invocations and inserted by hand into the recording script so the captured
file is exactly what `parseDockerReclaimOutput` is handed. **Every line between
them is docker's, verbatim** — no ids were shortened, no wording was tidied.

Nothing was sanitised, because nothing needed to be: every container, image,
volume and network named in these three files was created on the recording host
for the recording, under an `sp21b-` prefix, and destroyed afterwards. The hex
ids are real ids of objects that no longer exist.

### What the removal recordings proved, and the parser must survive

- **`rm`, `volume rm` and `network rm` echo the reference they were given,
  verbatim, one line each.** A short id in, the same short id out.
- **`rmi` does not.** It prints `Deleted: sha256:<64 hex>` — and, when the image
  had a tag, `Untagged: <ref>` first. The short id handed to it is a *prefix* of
  that digest, never equal to a whole line, so an attribution model matching
  lines by equality reports a successful `rmi` as "docker did not say what
  happened". That is why `parseDockerReclaimOutput` matches `Untagged:`/`Deleted:`
  lines by substring and everything else by equality.
- **A busy volume's error line names the CONTAINER holding it**, in full:
  `volume is in use - [f4a732d020f7376a…]`. That container id has nothing to do
  with any container the operator also selected, and it is the reason each kind
  is parsed inside its own marked block rather than from one pooled body.
- **Removing a multi-tagged image by id is refused**, `(must be forced) - image
  is referenced in multiple repositories`, and the image stays. This is the
  by-id rule failing safe: the alternative spelling, `docker rmi <repo>:<tag>`,
  would have quietly untagged instead.
- **Every refusal names the reference it refused**, which is what makes per-item
  attribution possible at all rather than aspirational.

### Sanitising the compose recordings, and why the alignment is intact

Two of the three project names on the recording host named a real employer's
internal systems, and one config path was `/Users/<person>/Desktop/DevSecOps
Operating Model/...`. Both were replaced. The replacements were chosen to be
**the same length as the originals** (`dsop-backend-test` → `billing-stage-api`,
17 characters; `wpmonk-route2-t51-o3` → `blog-prod-eu-west-01`, 20), because
`docker compose ls` renders a padded table and a shorter replacement would have
silently re-flowed the columns — turning a recorded fixture into a hand-made one
without anybody noticing. The paths were replaced with `/srv/...` and
`/opt/...` equivalents, and one of them deliberately **keeps a space in a
directory name** (`/srv/Ops Platform/billing/...`), because the original had one
and it is the reason the table parser splits on runs of two-or-more spaces
rather than on whitespace.

### What the compose recordings proved, and the parser must survive

- `docker compose ls` **without `--all` omits stopped projects entirely.** The
  same host reported `edge` as `running(2)` without the flag and
  `exited(1), running(2)` with it, in the same minute. So the collector always
  passes `--all`.
- STATUS is a **compound string with a comma and a space in it**.
- CONFIG FILES holds **several paths joined by a comma inside one field** —
  recorded by starting the project with `-f compose.yaml -f
  compose.override.yaml`.
- With `--no-interpolate`, compose renders one service's `environment` as a
  **map** and another's as a **`KEY=VALUE` list, in the same document**. A
  parser that handles only one shape reports the other service as having no
  environment at all.
- `config --images` prints images in a **different order** from
  `config --services`, so the two lists cannot be zipped together.


## The gap, stated rather than hidden

**There is no podman fixture**, because no podman host was available. Podman's
`system df -v` differs — it has historically omitted the build-cache section entirely
(`tests/dockerOps.test.ts` already covers that for the non-verbose form) and disagrees
on column sets. Any parser written against this directory alone is unproven on podman,
and the tests say so rather than implying a coverage that does not exist.

**The hole is at its worst for the removal recordings, and it is the reason
roadmap item 21b was deferred rather than shipped with 21a.** Podman's `rm`,
`rmi` and `volume rm` print *different* success lines and *different* refusal
wording from docker's — `podman rmi` prints bare digests where docker prints
`Untagged:`/`Deleted:`, and podman's daemonless errors carry no `Error response
from daemon:` prefix at all. `parseDockerReclaimOutput` attributes by looking
for the reference inside the line, which is the most runtime-agnostic rule
available, and it still means a podman host would most likely report every
object as "docker did not say what happened to this object" — the honest
failure rather than a wrong success, which is the best that can be claimed
without a host to record on. **No podman output was invented to fill this in.**
An invented refusal string is worse here than an absent one, because a test
asserting against it would read as evidence that podman works.

The same hole is wider for compose. **`podman compose` is not `docker compose`**
— on most installs it is a shim over `podman-compose`, a separate Python
program which has no `ls` subcommand at all and whose `config` does not accept
`--no-env-resolution`. Nothing in `tests/compose.test.ts` is evidence about
podman, and `src/shared/compose.ts` does not claim to drive it: a host that
answers `docker compose` with "unknown command" is reported as
`compose-unavailable`, which is a stated fact rather than a guess.

**There is also no compose v1 (`docker-compose`) fixture**, for the same
reason and one more: v1 is a different binary with different flags, and the
module deliberately does not fall back to it. Running an unverified command
line on someone else's production host to avoid an error message is the wrong
trade.

**Not captured: an engine too old for `--format json` on `config`.** The
recording host runs Compose v5.1.4 and there was no older engine available. The
`--services` fallback path is therefore exercised only against a constructed
"unknown flag" response, and `tests/compose.test.ts` says so at that test. What
IS real is that the fallback is reached at all, because the JSON block is built
with `|| true` ahead of the block whose exit status is read.

## What the recording proved, and the parser must survive

Two columns contain spaces inside a single cell, so the `/\s{2,}/` split that the
non-verbose `system df` parser uses will not work unmodified here:

- `COMMAND` is a quoted string — `"/bin/sh -c 'set -e\n…"` — containing spaces and a
  unicode ellipsis where docker truncated it.
- `STATUS` reads `Up 17 hours (healthy)` or `Exited (137) 2 days ago`.

A volume name is up to 64 hex characters, which is wider than its column header, and a
named volume is simply one a person typed — there is no flag distinguishing it, only
the shape.

## A trap when recording on this machine

A command-proxy tool on the recording machine rewrites some Docker output into a
token-optimised summary. `docker compose ps` came back as `[compose] 3 services: …`
rather than as Docker's table — a plausible-looking answer that is not the program's.
A fixture captured naively that way is **fabricated without anyone deciding to fabricate
it**, which is worse than an invented one, because it carries the authority of a recording.

Checked, since it bears on what has already shipped: `docker system df -v` is NOT rewritten.
The committed recording matches live output structurally, and the differences between them
are the proof rather than a worry — column widths vary between the two (`TAG` is one
character wider live; the build-cache columns are narrow here because this host's cache was
empty and wide there because it is not). That is Go's tabwriter padding every column to its
widest cell, header included, and it is exactly why the parser measures header offsets and
reads cells by name instead of by index.

**So: record through the proxy's passthrough form, and diff a fresh capture against the
committed one before trusting either.** The failure is silent and the output looks fine.

Checked again for the `reclaim-*` recordings, since a removal cannot be re-run to
compare afterwards. Every one of them was captured through the proxy's `proxy`
passthrough, and the check was made on throwaway objects first: `docker rm <id>`
and `docker volume rm <name>` were each run twice on identical scratch objects,
once through the passthrough and once bare, and the two outputs were the same
shape — a bare echoed reference. `rm`, `rmi`, `volume rm` and `network rm` are
**not** rewritten on this machine. The one command that *is* rewritten in this
family remains `docker compose ps`.
