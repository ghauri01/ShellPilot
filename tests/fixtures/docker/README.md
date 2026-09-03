# Docker fixtures

## Provenance, which matters more than it looks

`tests/engineAdvisories.test.ts` records the rule this directory follows: a fixture
invented from documentation is the thing most likely to be wrong, because it agrees
with whatever the parser author believed the format was. So provenance is stated per
file rather than assumed.

| File | Provenance |
|---|---|
| `system-df-v-docker-29.txt` | **Structure recorded from a real `docker system df -v` on Docker 29.5.3** — column positions, header spellings, the unicode ellipsis docker truncates `COMMAND` with, and the `Up 7 days (healthy)` status form are all verbatim. Identifiers, image names and container names were replaced, because the recording host was somebody's actual machine and this repository is public. Four rows were **added by hand** to cover states the recording host did not have: a `<none>:<none>` dangling image, an `Exited (137)` container, a `Created` container, and two volumes with `LINKS 0` — one anonymous, one named. |

## The gap, stated rather than hidden

**There is no podman fixture**, because no podman host was available. Podman's
`system df -v` differs — it has historically omitted the build-cache section entirely
(`tests/dockerOps.test.ts` already covers that for the non-verbose form) and disagrees
on column sets. Any parser written against this directory alone is unproven on podman,
and the tests say so rather than implying a coverage that does not exist.

## What the recording proved, and the parser must survive

Two columns contain spaces inside a single cell, so the `/\s{2,}/` split that the
non-verbose `system df` parser uses will not work unmodified here:

- `COMMAND` is a quoted string — `"/bin/sh -c 'set -e\n…"` — containing spaces and a
  unicode ellipsis where docker truncated it.
- `STATUS` reads `Up 17 hours (healthy)` or `Exited (137) 2 days ago`.

A volume name is up to 64 hex characters, which is wider than its column header, and a
named volume is simply one a person typed — there is no flag distinguishing it, only
the shape.
