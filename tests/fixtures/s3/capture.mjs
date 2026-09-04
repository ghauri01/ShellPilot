#!/usr/bin/env node
// Records the ListObjectsV2 bodies in this directory off a real MinIO.
//
// Run it, then `git diff tests/fixtures/s3` — a clean diff is the statement
// that the committed files are still what the server says. See README.md for
// why that matters here and for the two fields this script normalises.
//
//   node tests/fixtures/s3/capture.mjs            # start a container, record, stop
//   MINIO_ENDPOINT=http://127.0.0.1:9000 \
//   MINIO_KEY=... MINIO_SECRET=... node tests/fixtures/s3/capture.mjs
//
// The signing here is deliberately a SECOND implementation, written from the
// SigV4 specification, and not an import of src/main/services/backupTargets.
// A recorder that signed with the code under test would only ever record the
// responses that code already knows how to produce.

import { createHash, createHmac } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const IMAGE = 'quay.io/minio/minio:latest'
const CONTAINER = 'shellpilot-s3-fixture-capture'
const PORT = 19733
const BUCKET = 'sp-fixture'
const PREFIX = 'bundles/'

// Keys chosen because each one is a character class that survives XML
// differently. A U+0001 is in there because a key may legally hold one, and
// it is the case that stops an unencoded listing being well-formed XML at all.
const KEYS = [
  'amp&ersand.spbackup',
  'ctrl\u0001char.spbackup',
  'plain.spbackup',
  'plus+name.spbackup',
  'quote"lt<gt>.spbackup',
  'space name.spbackup',
  'unicodé-日本.spbackup'
]

const uriEncode = (value, keepSlash = false) => {
  let out = ''
  for (const byte of Buffer.from(value, 'utf8')) {
    const ch = String.fromCharCode(byte)
    if (/[A-Za-z0-9\-_.~]/.test(ch) || (keepSlash && ch === '/')) out += ch
    else out += '%' + byte.toString(16).toUpperCase().padStart(2, '0')
  }
  return out
}

function sign({ method, path, query, host, body, key, secret, region, amzDate }) {
  const hash = createHash('sha256').update(body ?? Buffer.alloc(0)).digest('hex')
  const date = amzDate.slice(0, 8)
  const scope = `${date}/${region}/s3/aws4_request`
  const canonical = [
    method,
    path,
    query,
    `host:${host}\nx-amz-content-sha256:${hash}\nx-amz-date:${amzDate}\n`,
    'host;x-amz-content-sha256;x-amz-date',
    hash
  ].join('\n')
  const toSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonical, 'utf8').digest('hex')
  ].join('\n')
  const mac = (k, m) => createHmac('sha256', k).update(m, 'utf8').digest()
  const signing = mac(mac(mac(mac(`AWS4${secret}`, date), region), 's3'), 'aws4_request')
  return {
    hash,
    authorization:
      `AWS4-HMAC-SHA256 Credential=${key}/${scope}, ` +
      `SignedHeaders=host;x-amz-content-sha256;x-amz-date, ` +
      `Signature=${createHmac('sha256', signing).update(toSign, 'utf8').digest('hex')}`
  }
}

async function s3(endpoint, key, secret, method, path, query, body) {
  const base = new URL(endpoint)
  const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')
  const { hash, authorization } = sign({
    method,
    path,
    query,
    host: base.host,
    body,
    key,
    secret,
    region: 'us-east-1',
    amzDate
  })
  const res = await fetch(`${base.origin}${path}${query ? `?${query}` : ''}`, {
    method,
    headers: { 'x-amz-content-sha256': hash, 'x-amz-date': amzDate, authorization },
    body
  })
  const text = await res.text()
  if (!res.ok) throw new Error(`${method} ${path}?${query} -> ${res.status}\n${text}`)
  return text
}

/**
 * The two fields a re-capture cannot reproduce.
 *
 * LastModified is the wall clock at the moment of the recording and ETag is a
 * digest of body bytes that the tests do not read. Everything else in these
 * files — element order, namespace, KeyCount, the escaping, the continuation
 * token — is verbatim, because those are the parts a parser can be wrong
 * about. Normalising here rather than by hand is what makes `git diff` after a
 * re-run mean something.
 */
const normalise = (xml) =>
  xml
    .replace(/<LastModified>[^<]*<\/LastModified>/g, '<LastModified>2024-01-15T10:30:00.000Z</LastModified>')
    .replace(/<ETag>[^<]*<\/ETag>/g, '<ETag>&#34;00000000000000000000000000000000&#34;</ETag>')

const pretty = (xml) => xml.replace(/></g, '>\n<') + '\n'

async function main() {
  let endpoint = process.env.MINIO_ENDPOINT
  let key = process.env.MINIO_KEY
  let secret = process.env.MINIO_SECRET
  let started = false

  if (!endpoint) {
    endpoint = `http://127.0.0.1:${PORT}`
    key = 'spilotthrowaway'
    secret = 'spilotthrowaway-secret-0'
    try {
      execFileSync('docker', ['rm', '-f', CONTAINER], { stdio: 'ignore' })
    } catch {
      /* not running */
    }
    execFileSync(
      'docker',
      [
        'run', '-d', '--rm', '--name', CONTAINER,
        '-p', `${PORT}:9000`,
        '-e', `MINIO_ROOT_USER=${key}`,
        '-e', `MINIO_ROOT_PASSWORD=${secret}`,
        IMAGE, 'server', '/data'
      ],
      { stdio: 'inherit' }
    )
    started = true
    for (let i = 0; i < 100; i++) {
      try {
        const res = await fetch(`${endpoint}/minio/health/live`)
        if (res.ok) break
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 200))
    }
    console.log(
      'minio image:',
      execFileSync('docker', ['image', 'inspect', IMAGE, '--format', '{{index .RepoDigests 0}}'])
        .toString()
        .trim()
    )
  }

  try {
    await s3(endpoint, key, secret, 'PUT', `/${BUCKET}/`, '')
  } catch (err) {
    if (!String(err).includes('BucketAlreadyOwnedByYou')) throw err
  }
  for (const k of KEYS) {
    await s3(endpoint, key, secret, 'PUT', `/${BUCKET}/${uriEncode(PREFIX + k, true)}`, '', Buffer.from('x'))
  }

  const q = (...parts) => parts.sort().join('&')
  const captures = [
    ['list-v2-minio.xml', q('list-type=2', `prefix=${uriEncode(PREFIX)}`)],
    ['list-v2-encoded-minio.xml', q('list-type=2', 'encoding-type=url', `prefix=${uriEncode(PREFIX)}`)],
    [
      'list-v2-encoded-truncated-minio.xml',
      q('list-type=2', 'encoding-type=url', 'max-keys=2', `prefix=${uriEncode(PREFIX)}`)
    ]
  ]

  mkdirSync(HERE, { recursive: true })
  for (const [file, query] of captures) {
    const xml = await s3(endpoint, key, secret, 'GET', `/${BUCKET}/`, query)
    writeFileSync(join(HERE, file), pretty(normalise(xml)))
    console.log('wrote', file)
  }

  if (started) execFileSync('docker', ['rm', '-f', CONTAINER], { stdio: 'ignore' })
}

await main()
