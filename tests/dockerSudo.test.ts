import { describe, it, expect } from 'vitest'
import { DockerReader } from '../src/main/services/docker'
import { buildDockerListCommand, resolveBinary, SUDO_PROBE, DOCKER_SEP } from '../src/shared/docker'

// Found by running 0.9.0 against a real host: the panel correctly said "this
// user cannot talk to the docker socket" and then stopped. Naming a problem is
// not handling it.
//
// The retry uses `sudo -n`, which NEVER prompts. That is what makes it safe to
// do automatically: it either works, because the user already configured
// passwordless sudo on that host, or it fails immediately. It cannot hang an
// exec waiting for a tty that is not there.

const DENIED =
  'permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'

const okOutput = (): string =>
  [
    '24.0.7',
    '===SHELLPILOT-PS===',
    ['abc123', 'web', 'nginx', 'running', 'Up 2 hours', '', 'now'].join(DOCKER_SEP)
  ].join('\n')

function reader(script: (cmd: string, n: number) => { ok: boolean; stdout?: string; code?: number }) {
  const commands: string[] = []
  let n = 0
  const r = new DockerReader({
    exec: async (_cfg, cmd) => {
      commands.push(cmd)
      return { code: 0, ...script(cmd, n++) }
    }
  })
  return { reader: r, commands }
}

describe('when the socket refuses this user', () => {
  it('retries as root and says that it did', async () => {
    const h = reader((cmd) =>
      cmd.includes('sudo -n true')
        ? { ok: true, stdout: 'SP_SUDO_OK' }
        : cmd.includes('sudo -n')
          ? { ok: true, stdout: okOutput() }
          : { ok: true, stdout: DENIED }
    )
    const r = await h.reader.list({})
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.containers).toHaveLength(1)
    // Escalating silently would be the wrong trade even when it is the only
    // way to get an answer.
    expect(r.usedSudo).toBe(true)
  })

  it('reports the ORIGINAL failure when root does not help either', async () => {
    // A second error about sudo would send the user somewhere unrelated to
    // their actual problem.
    const h = reader((cmd) =>
      cmd.includes('sudo -n true') ? { ok: true, stdout: 'SP_SUDO_OK' } : { ok: true, stdout: DENIED }
    )
    const r = await h.reader.list({})
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('permission-denied')
    expect(!r.ok && r.detail).toMatch(/docker\.sock/)
  })

  it('does not retry when passwordless sudo is unavailable', async () => {
    const h = reader((cmd) =>
      cmd.includes('sudo -n true') ? { ok: true, stdout: '' } : { ok: true, stdout: DENIED }
    )
    const r = await h.reader.list({})
    expect(r.ok).toBe(false)
    // Probed once, never actually run as root.
    expect(h.commands.filter((c) => c.includes('sudo -n "$SP_BIN"'))).toHaveLength(0)
  })

  it('can be told not to retry at all', async () => {
    const h = reader(() => ({ ok: true, stdout: DENIED }))
    const r = await h.reader.list({}, { autoSudo: false })
    expect(r.ok).toBe(false)
    expect(h.commands.some((c) => c.includes('sudo'))).toBe(false)
  })
})

describe('what is NOT worth retrying as root', () => {
  it('does not retry a missing binary', async () => {
    // Root does not install docker, and retrying just doubles the wait before
    // the same answer.
    const h = reader(() => ({ ok: true, stdout: 'bash: docker: command not found', code: 127 }))
    const r = await h.reader.list({})
    expect(!r.ok && r.reason).toBe('not-installed')
    expect(h.commands.some((c) => c.includes('sudo'))).toBe(false)
  })

  it('does not retry a dead daemon', async () => {
    const h = reader(() => ({
      ok: true,
      stdout: 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?'
    }))
    const r = await h.reader.list({})
    expect(!r.ok && r.reason).toBe('daemon-unreachable')
    expect(h.commands.some((c) => c.includes('sudo'))).toBe(false)
  })

  it('does not probe sudo at all on a healthy host', async () => {
    // An ordinary host should never pay for a capability it does not need.
    const h = reader(() => ({ ok: true, stdout: okOutput() }))
    const r = await h.reader.list({})
    expect(r.ok).toBe(true)
    expect(h.commands.some((c) => c.includes('sudo'))).toBe(false)
  })
})

describe('being told to use sudo up front', () => {
  it('skips the attempt that would be refused', async () => {
    const h = reader(() => ({ ok: true, stdout: okOutput() }))
    const r = await h.reader.list({}, { sudo: true })
    expect(r.ok && r.usedSudo).toBe(true)
    expect(h.commands).toHaveLength(1)
    expect(h.commands[0]).toMatch(/sudo -n "\$SP_BIN"/)
  })
})

describe('the sudo probe itself', () => {
  it('never prompts', async () => {
    // -n is the entire safety property: no tty, no hang, no interactively
    // consumed sudo timestamp.
    expect(SUDO_PROBE).toMatch(/sudo -n/)
    expect(SUDO_PROBE).not.toMatch(/sudo\s+(?!-n)/)
  })

  it('cannot fail the whole read', async () => {
    expect(SUDO_PROBE).toMatch(/\|\| true/)
  })
})

describe('finding a binary a non-login shell cannot see', () => {
  it('checks the paths ssh drops from PATH', () => {
    const cmd = buildDockerListCommand()
    for (const p of ['/usr/local/bin/docker', '/snap/bin/docker', '/opt/homebrew/bin/docker']) {
      expect(cmd, p).toContain(p)
    }
  })

  it('runs the resolved binary, not the bare name', () => {
    expect(buildDockerListCommand()).toMatch(/"\$SP_BIN" ps --all/)
  })

  it('asks the same question with and without sudo', () => {
    // A sudo path that read differently would answer a different question, and
    // the two results could not be compared.
    // Strip only the prefix. Substituting "$SP_BIN" itself also hit the
    // resolver's own `[ -z "$SP_BIN" ]`, which has no sudo form — so the two
    // sides were normalised differently and the test failed on its own
    // arithmetic rather than on the code.
    const plain = buildDockerListCommand()
    const sudo = buildDockerListCommand({ sudo: true }).replace(/sudo -n /g, '')
    expect(sudo).toBe(plain)
  })

  it('is reusable for other tools', () => {
    expect(resolveBinary('kubectl')).toContain('/usr/local/bin/kubectl')
  })
})
