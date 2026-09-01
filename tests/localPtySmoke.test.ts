import { describe, it, expect } from 'vitest'

// This runs under plain Node, not Electron, and that is the point. The binding
// is Node-API, so the exact same prebuilt .node loads in Node 20 and in
// Electron 43 — which is what makes a CI job that never launches Electron
// worth anything at all. node-pty@1.1.0 is NAN/V8 and could not be tested this
// way; see the plan's decision table.
//
// On POSIX this also exercises spawn-helper, which is posix_spawn'ed rather
// than dlopen'ed: it is the piece that a noexec mount or a missing exec bit
// breaks, and nothing else in the suite touches it.

// The same interop dance localPty.loadPty() does. @lydell/node-pty is CJS, so
// depending on how the test is transformed its exports land either on the
// namespace or on `.default`.
async function loadPty(): Promise<{
  spawn(
    file: string,
    args: string[],
    opts: Record<string, unknown>
  ): { onData(cb: (d: string) => void): unknown; kill(): void }
}> {
  const raw = await import('@lydell/node-pty')
  const mod = ((raw as { default?: unknown }).default ?? raw) as {
    spawn(
      file: string,
      args: string[],
      opts: Record<string, unknown>
    ): { onData(cb: (d: string) => void): unknown; kill(): void }
  }
  expect(typeof mod.spawn).toBe('function')
  return mod
}

function readUntilMarker(term: { onData(cb: (d: string) => void): unknown }): Promise<string> {
  return new Promise<string>((resolve) => {
    let buf = ''
    term.onData((d) => {
      buf += d
      if (buf.includes('SHELLPILOT_PTY_OK')) resolve(buf)
    })
    setTimeout(() => resolve(buf), 8000)
  })
}

describe('@lydell/node-pty spawns a real shell', () => {
  it.skipIf(process.platform === 'win32')('echoes back through a pty', async () => {
    const pty = await loadPty()
    const term = pty.spawn('/bin/sh', ['-c', 'echo SHELLPILOT_PTY_OK'], {
      name: 'xterm-256color',
      cols: 80,
      rows: 24,
      cwd: process.cwd(),
      env: { ...process.env, TERM: 'xterm-256color' } as Record<string, string>
    })
    const seen = await readUntilMarker(term)
    term.kill()
    expect(seen).toContain('SHELLPILOT_PTY_OK')
  })

  it.skipIf(process.platform !== 'win32')('echoes back through ConPTY', async () => {
    const pty = await loadPty()
    const term = pty.spawn(process.env.ComSpec ?? 'cmd.exe', ['/c', 'echo SHELLPILOT_PTY_OK'], {
      name: 'xterm-256color',
      cols: 80,
      rows: 24,
      cwd: process.cwd(),
      env: process.env as Record<string, string>,
      useConpty: true,
      // Matches localPty.ts: the redistributable ConPTY is deliberately not
      // shipped, so the smoke test must exercise the same conhost.exe path.
      useConptyDll: false
    })
    const seen = await readUntilMarker(term)
    term.kill()
    expect(seen).toContain('SHELLPILOT_PTY_OK')
  })

  // The options localPty passes are not node-pty defaults; if a future release
  // of the beta drops or renames them the terminal silently loses backpressure,
  // which surfaces as an out-of-memory renderer rather than as a test failure.
  // Q1 verified them at lib/terminal.js:33-35, 76-84 — this pins that answer.
  //
  // NOTE: `lib/` lives in the *sibling* package, not in the @lydell/node-pty
  // meta package (Q2: the meta package is 5 files and re-exports
  // @lydell/node-pty-${platform}-${arch} at runtime). Resolving it by globbing
  // the siblings keeps this working on every platform's runner.
  it('still ships the flow-control options localPty relies on', async () => {
    await loadPty()
    const { readdir, readFile } = await import('node:fs/promises')
    const scope = new URL('../node_modules/@lydell/', import.meta.url)
    const siblings = (await readdir(scope)).filter((n) => n.startsWith('node-pty-'))
    expect(siblings.length).toBeGreaterThan(0)

    for (const sibling of siblings) {
      const text = await readFile(new URL(`${sibling}/lib/terminal.js`, scope), 'utf8')
      expect(text).toContain('handleFlowControl')
      expect(text).toContain('flowControlPause')
      expect(text).toContain('flowControlResume')
    }
  })
})
