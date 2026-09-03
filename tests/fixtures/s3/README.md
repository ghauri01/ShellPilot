# S3 fixtures, and the live MinIO suite

## Why this directory exists

Item 5 shipped an S3 backup driver that had been tested against a real HTTP
server and against an independently computed SigV4 vector, and its author said
in the same breath that it **had never talked to a real S3 server**. That was
the honest statement and it was also the whole risk: SigV4 is unforgiving, the
XML reader is hand-rolled, and a test double written by the same person who
wrote the driver agrees with the driver by construction.

Pointing it at a real MinIO found two bugs in the first ten minutes, one of them
the silent kind — see "What the recordings proved" below.

## Provenance, per file

The rule this directory follows is the one `tests/fixtures/docker/README.md`
states: a fixture invented from documentation is the thing most likely to be
wrong, because it agrees with whatever the parser author believed the format
was. So provenance is stated per file rather than assumed.

| File | Provenance |
|---|---|
| `capture.mjs` | The recorder. Run `node tests/fixtures/s3/capture.mjs` and then `git diff tests/fixtures/s3` — a clean diff is the statement that the committed bodies are still what the server says. It starts and stops its own container, or talks to one you name with `MINIO_ENDPOINT`/`MINIO_KEY`/`MINIO_SECRET`. Its SigV4 is a **second implementation written from the specification**, not an import of `src/main/services/backupTargets.ts`, because a recorder that signed with the code under test would only ever record responses that code already knows how to produce. |
| `list-v2-minio.xml` | **Recorded verbatim** from `GET /sp-fixture/?list-type=2&prefix=bundles%2F` against `quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e` (`RELEASE.2025-08-13`, the `mc` inside it reports `commit-id=7394ce0d`) on Docker 29.5.3. Seven objects, each one a character class that survives XML differently. |
| `list-v2-encoded-minio.xml` | **The same bucket, same run, same request plus `encoding-type=url`.** It is here as the evidence for the pair: the two files are the same seven keys and `tests/backupTargets.test.ts` asserts that the parser produces one identical list of names from both. |
| `list-v2-encoded-truncated-minio.xml` | **The same run again, with `max-keys=2`**, to record a real `<NextContinuationToken>` in place rather than a plausible-looking one. |
| `minio.ts` | Not a recording. The harness the live suite starts its container with. |

### The two fields the recorder normalises, and why

`capture.mjs` rewrites `<LastModified>` to a fixed timestamp and `<ETag>` to a
fixed digest before writing. Everything else — element order, the namespace,
`KeyCount`, the escaping, the continuation token — is verbatim, because those
are the parts a parser can be wrong about. The normalisation lives in the
script rather than in somebody's editor so that `git diff` after a re-run means
something: a fresh capture on a fresh container is byte-identical to what is
committed here, which was checked by running it twice and comparing md5s.

### A note about capturing on this machine

A command proxy on the machine these were recorded on rewrites some tool output
into summaries. A fixture captured naively through it would be **fabricated
without anybody deciding to fabricate it**. `capture.mjs` does not shell out for
the bodies at all — it writes them from the HTTP response itself — and the
docker invocations around it were run through the proxy's passthrough form
(`rtk proxy docker …`) so the recorded image digest above is the real one.

## What the recordings proved, and the parser must survive

- **`<Key>` is XML text, not the key.** MinIO returned `bundles/amp&amp;ersand.spbackup`
  for the key `bundles/amp&ersand.spbackup`, and `bundles/ctrl&#x1;char.spbackup`
  for a key holding a control character. The driver read those verbatim, so it
  reported names that are not in the bucket and then handed them back to GET and
  DELETE. (`&#x1;` is not even a legal XML 1.0 character reference; AWS
  documents `encoding-type` precisely because keys can hold characters XML
  cannot carry.)
- **`encoding-type=url` is form encoding, not percent encoding.** The key
  `space name.spbackup` came back as `space+name.spbackup` and
  `plus+name.spbackup` came back as `plus%2Bname.spbackup`. `decodeURIComponent`
  on its own gets the first of those wrong, silently.
- **`encoding-type` does not cover the continuation token.** It covers
  Delimiter, Prefix, Key and the marker fields. A token is base64 and base64
  contains `+`, `/` and `=`; decoding it would send an unopenable token back on
  the next page.
- **The store says whether it encoded anything**, with `<EncodingType>url</EncodingType>`
  in the body. The parser only percent-decodes when it sees that, so an
  S3-compatible store that ignores the parameter is still read correctly and a
  literal `%` in someone's key is not eaten.

## What the live suite covers

`tests/backupTargets.test.ts` and `tests/backupRuns.test.ts` each start their
own MinIO (different container name and port, so the two files can run in
parallel) and drive the **production driver** — `openTarget` /
`runBackupToDestination`, not a reimplementation.

Covered against a real server: put/get/list/delete; keys containing spaces,
`+`, `=`, `&`, `"`, `<`, `>`, `~!*()` and non-ASCII; a prefix containing `&`;
a zero-byte object; an object one byte past the 5 MiB multipart threshold;
`ListObjectsV2` paging across 1001 objects so the continuation token actually
engages; path-style and virtual-host-style addressing; a bucket name with dots
in it; a wrong secret key; a clock 45 minutes out; `Content-Length` asserted on
the wire through a TCP tee; and a full backup run with the restore-test
verification and retention, including the retention that the listing bug
silently disabled.

## What this cannot prove: MinIO is not AWS

Stated rather than implied, because a suite that is read as "S3 works" when it
means "MinIO works" is worse than no suite.

- **Region.** MinIO does not check it. The suite has a test that records this
  (`records that MinIO does not check the region…`) and it deliberately asserts
  that a destination configured with `ap-southeast-2` still works — because that
  is MinIO's behaviour, not correct behaviour. AWS answers `400
  AuthorizationHeaderMalformed` or `301 PermanentRedirect` with the right region
  in the body. **Unproven here.**
- **Region redirects.** Node's `fetch` follows redirects by default and undici
  strips `Authorization` across origins, so what this driver does with a real
  `301 PermanentRedirect` from AWS is **unproven**.
- **Real IAM.** Everything here runs as the MinIO root user. `AccessDenied` from
  a bucket policy, an expired STS token, `InvalidAccessKeyId` versus
  `SignatureDoesNotMatch`, KMS/SSE headers and requester-pays are all
  **unproven**. The wrong-secret test proves the driver surfaces the store's
  refusal, not that it surfaces every refusal AWS has.
- **Consistency.** S3 is strongly read-after-write for PUTs today, but LIST is
  not guaranteed to reflect a just-completed DELETE on every S3-compatible
  store. The retention tests here list immediately after deleting and pass
  against MinIO; that is **not** evidence about any other store.
- **TLS.** Everything here is plain HTTP over loopback. Certificate handling,
  SNI and the virtual-host wildcard-certificate problem that dotted bucket names
  cause on AWS are **unproven**.
- **Scale.** The listing loop stops after 20 pages, so a prefix holding more
  than 20 000 objects is truncated. Retention still removes the oldest, because
  S3 lists lexicographically and these names sort by timestamp — but that is an
  argument, not a test.
- **Multipart.** This driver never uses it, deliberately. An object larger than
  the 5 GiB single-PUT limit would fail, and nothing here exercises that.

## Running it, and how a skip is prevented from being silent

`minioSkipReason()` in `minio.ts` returns `null` when the suite can and
therefore must run. Otherwise it returns the sentence that is spliced into the
describe block's own name, so a skipped test reads:

```
↓ s3 target against a real MinIO in Docker [SKIPPED: Docker is not usable here (docker version: spawnSync docker ENOENT)] > uploads, reads back, lists and deletes
```

Three properties, each checked by running it:

- **With Docker present it genuinely runs.** `npm test` on the recording
  machine reports 0 skipped for these files and the live tests appear as `✓`,
  not `↓`. The first live test asserts `Server: MinIO` on a 403 from the
  container — a header nothing in this repository's own stand-ins sets — so the
  block cannot pass by talking to something in-process.
- **With Docker absent it skips, and says why.** Verified by re-running the
  same two files with `docker` removed from `PATH`: 109 passed, 18 skipped, and
  every skipped name carries the reason.
- **A machine that is meant to have Docker can refuse the skip.** Set
  `SHELLPILOT_S3_LIVE=1` and the always-running test `is skipped only for a
  reason it can name` fails instead. `SHELLPILOT_S3_LIVE=0` is the opposite
  lever, for bisecting something else.

If Docker answers but the container will not come up, `startMinio` **throws**
rather than skipping. Docker being present and the fixture being broken is not
a reason to report that everything is fine.

The credentials are throwaway, created and destroyed with the container, and
appear in `minio.ts` in plain sight. Nothing in this directory is a real key.
