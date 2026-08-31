#!/usr/bin/env node
// A scriptable stand-in for a VPN engine, so the supervisor can be tested
// against a real process — real pipes, real readline framing, real exit codes
// — rather than against a mock that agrees with whatever the supervisor does.
//
// Flags (all optional):
//   --print-argv          print `ARGV <json>` (proves argv carries no secret)
//   --read-stdin          drain stdin, then print its length and SHA-256.
//                         Deliberately never the content: a test that proved
//                         delivery by echoing the secret would put the secret
//                         in the log it is also asserting is clean.
//   --print=TEXT          print TEXT to stdout (repeatable)
//   --stderr=TEXT         print TEXT to stderr (repeatable)
//   --repeat-lines=N      print N numbered lines
//   --huge-line=N         print one line of N bytes with no newline in it
//   --ready-after=MS      print READY after MS
//   --ignore-sigterm      catch SIGTERM and keep running
//   --exit=N              exit code to use
//   --exit-after=MS       exit after MS
//   --stay                keep the event loop alive indefinitely
import { createHash } from 'node:crypto'

const argv = process.argv.slice(2)
const has = (name) => argv.includes(`--${name}`)
const all = (name) => argv.filter((a) => a.startsWith(`--${name}=`)).map((a) => a.slice(name.length + 3))
const one = (name) => all(name)[0]
const num = (name, dflt) => {
  const v = one(name)
  return v === undefined ? dflt : Number(v)
}

async function main() {
  if (has('ignore-sigterm')) {
    process.on('SIGTERM', () => console.log('SIGTERM-IGNORED'))
  }

  if (has('print-argv')) console.log(`ARGV ${JSON.stringify(argv)}`)
  for (const line of all('print')) console.log(line)
  for (const line of all('stderr')) console.error(line)

  const repeat = num('repeat-lines', 0)
  for (let i = 0; i < repeat; i++) console.log(`line ${i}`)

  const huge = num('huge-line', 0)
  if (huge > 0) console.log('H'.repeat(huge))

  if (has('read-stdin')) {
    const chunks = []
    for await (const chunk of process.stdin) chunks.push(chunk)
    const body = Buffer.concat(chunks)
    console.log(`STDIN-LEN ${body.length}`)
    console.log(`STDIN-SHA256 ${createHash('sha256').update(body).digest('hex')}`)
  }

  const readyAfter = num('ready-after', -1)
  if (readyAfter >= 0) setTimeout(() => console.log('READY'), readyAfter)

  const exitAfter = num('exit-after', -1)
  if (exitAfter >= 0) setTimeout(() => process.exit(num('exit', 0)), exitAfter)
  else if (!has('stay')) process.exitCode = num('exit', 0)

  if (has('stay')) setInterval(() => {}, 1 << 30)
}

main()
