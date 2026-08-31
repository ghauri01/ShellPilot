import { spawn } from 'node:child_process'
import net from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'

// What this test does and does not claim.
//
// `tests/vpnOpenvpnDriver.test.ts` fails intermittently on a `waitFor` for a
// management line. Two independent readings of the code reached the same
// diagnosis: the supervisor sends a real POSIX SIGTERM once `gracefulTimeoutMs`
// expires, the fixture had no handler, so the default action terminated it and
// discarded whatever was still buffered on the stdout pipe — usually the line
// under assertion. Raising the `waitFor` budget could not help, because the
// line is destroyed at a fixed moment rather than delayed.
//
// **The original flake is not reproduced here, and this test is not evidence
// that it is fixed.** It fired roughly once in thirty runs for the agent who
// found it, and a direct harness that signals mid-write did not lose the line
// in five consecutive runs either way. Claiming a fix on that basis would be
// exactly the mistake the diagnosis warns about: watching a rate drop and
// calling it a cure.
//
// What is demonstrable, deterministically and every run, is the mechanism the
// diagnosis rests on. Without a handler the fixture is *killed by the signal*
// — exit code null, termination signal SIGTERM, no drain, buffers discarded at
// the OS's discretion. With one it runs its existing `exit()` path and leaves
// with code 0 having drained. Whether or not that closes the flake, a fixture
// that dies by signal is the precondition for losing a line, and a fixture that
// exits cleanly cannot lose one this way.
//
// So: this pins the precondition, and says so, rather than overstating itself.

const FIXTURE = fileURLToPath(new URL('./fixtures/fake-openvpn.mjs', import.meta.url))

let dir: string | undefined
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true })
  dir = undefined
})

interface Outcome {
  stdout: string
  code: number | null
  signal: NodeJS.Signals | null
}

/** Run the fixture against a real management socket, send one command, deliver
 *  a real SIGTERM, and report how it left. */
async function runAndTerminate(command: string): Promise<Outcome> {
  dir = mkdtempSync(join(tmpdir(), 'fake-ovpn-'))
  const socketPath = join(dir, 'mgmt.sock')

  const connected = new Promise<net.Socket>((resolve) => {
    const server = net.createServer((sock) => {
      resolve(sock)
      server.close()
    })
    server.listen(socketPath)
  })

  // The fixture speaks openvpn's own argv: `--management <path> unix`.
  const child = spawn(
    process.execPath,
    [FIXTURE, '--management', socketPath, 'unix', '--management-client'],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  )

  let stdout = ''
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', (c: string) => {
    stdout += c
  })

  const sock = await connected
  // 'close', not 'exit'. 'exit' fires when the process is gone, which can be
  // before the last chunk of its stdout has been handed to us — reading the
  // buffer there makes this test race the very pipe it is asserting about.
  // 'close' waits for the stdio streams, which is the point.
  const exited = new Promise<Outcome>((resolve) => {
    child.on('close', (code, signal) => resolve({ stdout, code, signal }))
  })

  // Wait for the greeting, so this is about the signal rather than a race to
  // be ready.
  await new Promise<void>((resolve) => {
    const onData = (): void => {
      sock.off('data', onData)
      resolve()
    }
    sock.on('data', onData)
  })

  sock.write(`${command}\n`)

  // Let the fixture settle before signalling, because that is what actually
  // happens: the supervisor runs gracefulStop, waits out `gracefulTimeoutMs`
  // (500 ms in the driver tests, 5 s by default) and only then sends SIGTERM.
  // Signalling with no gap at all races the fixture's own startup and tests a
  // sequence the supervisor cannot produce — which made this test itself flaky,
  // three runs in eight, before the gap was added.
  await new Promise((r) => setTimeout(r, 250))
  child.kill('SIGTERM')
  return exited
}

describe('the fake OpenVPN drains on a real SIGTERM instead of being killed by it', () => {
  it('leaves through its own exit path, not the default signal action', async () => {
    const { signal } = await runAndTerminate('signal SIGTERM')
    // `signal === null` is the whole claim: the process chose when to leave
    // rather than being terminated where it stood. Remove the handler and this
    // is 'SIGTERM' every run.
    //
    // The exit *code* is deliberately not asserted. It varies between 0 and 1
    // here, and the cause is this harness rather than the fixture: closing the
    // management socket from the test side trips the fixture's own
    // `socket.on('error')`, which exits 1. Pinning the code would be pinning an
    // artefact of the test, and it is what made this test flaky three runs in
    // eight. The supervisor does not care either way — it reads the signal.
    expect(signal).toBeNull()
  }, 20_000)

  it('still has the acknowledgement in its output when it goes', async () => {
    const { stdout } = await runAndTerminate('signal SIGTERM')
    expect(stdout).toContain('RECV signal SIGTERM')
  }, 20_000)

  it('does not trade a lost line for a hung stop', async () => {
    // Draining must not become ignoring. The supervisor escalates to SIGKILL
    // after TERM_TO_KILL_MS (5s), so a fixture that needed the escalation would
    // swap a flaky test for a slow one. Resolving inside the 20s budget without
    // having been killed is the assertion.
    const { signal } = await runAndTerminate('state')
    expect(signal).toBeNull()
  }, 20_000)
})
