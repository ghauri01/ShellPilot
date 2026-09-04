import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ComposeReader } from '../src/main/services/compose'
import { COMPOSE_MARKERS, COMPOSE_HEREDOC } from '../src/shared/compose'

// The round trip, and the two rules that only exist at this layer:
//
//  * reads auto-escalate through `sudo -n`, writes never do;
//  * a write re-derives its own plan from the file as it is on the host NOW,
//    and refuses when that is not the file the operator was shown.

const DENIED =
  'permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'

const LS_JSON = readFileSync(
  join(__dirname, 'fixtures', 'docker', 'compose-ls-docker-29.json'),
  'utf8'
)

const listOutput = (ls: string = LS_JSON, find = ''): string =>
  [
    COMPOSE_MARKERS.version,
    'v2.29.7',
    COMPOSE_MARKERS.find,
    find,
    COMPOSE_MARKERS.ls,
    ls,
    COMPOSE_MARKERS.end
  ].join('\n')

function reader(
  script: (cmd: string, n: number) => { ok: boolean; stdout?: string; stderr?: string; code?: number }
) {
  const commands: string[] = []
  let n = 0
  const r = new ComposeReader({
    exec: async (_cfg, cmd) => {
      commands.push(cmd)
      return { code: 0, ...script(cmd, n++) }
    }
  })
  return { reader: r, commands }
}

describe('reads escalate, exactly as docker reads do', () => {
  it('retries a refused socket as root and says that it did', async () => {
    const h = reader((cmd) =>
      cmd.includes('sudo -n true')
        ? { ok: true, stdout: 'SP_SUDO_OK' }
        : cmd.includes('sudo -n')
          ? { ok: true, stdout: listOutput() }
          : { ok: true, stdout: listOutput(DENIED) }
    )
    const r = await h.reader.list({})
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.projects.map((p) => p.name)).toEqual([
      'billing-stage-api',
      'edge',
      'blog-prod-eu-west-01'
    ])
    expect(r.usedSudo).toBe(true)
  })

  it('reports the ORIGINAL failure when root does not help either', async () => {
    const h = reader((cmd) =>
      cmd.includes('sudo -n true')
        ? { ok: true, stdout: 'SP_SUDO_OK' }
        : { ok: true, stdout: listOutput(DENIED) }
    )
    const r = await h.reader.list({})
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('permission-denied')
  })

  it('does not retry a server that has no compose plugin', async () => {
    // Root does not install the plugin, so the retry would only double the
    // wait before the same answer.
    const h = reader(() => ({
      ok: true,
      stdout: listOutput("docker: 'compose' is not a docker command.")
    }))
    const r = await h.reader.list({})
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.projectsFrom).toBe('unavailable')
    expect(h.commands.some((c) => c.includes('sudo -n true'))).toBe(false)
  })

  it('does not call a transport failure a compose failure', async () => {
    const h = reader(() => ({ ok: false }))
    const r = await h.reader.list({})
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('unknown')
    expect(r.detail).toBe('could not reach the server')
  })

  it('rejects the call when the project reference cannot be proved safe', async () => {
    const h = reader(() => ({ ok: true, stdout: '' }))
    await expect(
      h.reader.config({}, { name: "edge'; rm -rf /", files: ['/srv/edge/compose.yaml'] })
    ).rejects.toThrow(/invalid project name/)
    // Nothing was run. A refused build is a rejected call, not a host
    // condition dressed up as one.
    expect(h.commands).toEqual([])
  })
})

describe('env names never come back with values', () => {
  it('asks the server for names and gets names', async () => {
    const h = reader(() => ({
      ok: true,
      stdout: [
        COMPOSE_MARKERS.envNames,
        'FILE /srv/edge/.env',
        'S REDIS_PASSWORD',
        'E OPTIONAL_FLAG',
        COMPOSE_MARKERS.end
      ].join('\n')
    }))
    const r = await h.reader.envNames({}, ['/srv/edge/.env'])
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.files[0].names).toEqual([
      { name: 'REDIS_PASSWORD', set: true },
      { name: 'OPTIONAL_FLAG', set: false }
    ])
    // The command itself is the safety, so it is what is asserted.
    expect(h.commands[0]).toContain('index($0, "=")')
    expect(h.commands[0]).not.toContain('$2')
  })
})

// =====================================================================
// The write
// =====================================================================

const FILE = [
  '# the edge stack',
  'services:',
  '  gateway:',
  '    image: nginx:1.27-alpine',
  '  cache:',
  '    image: redis:7.2-alpine',
  ''
].join('\n')

const PLANNED = { line: 4, before: '    image: nginx:1.27-alpine' }

function writeReader(fileText: string, writeResult: { code?: number; stdout?: string; stderr?: string } = {}) {
  const commands: string[] = []
  const r = new ComposeReader({
    exec: async (_cfg, cmd) => {
      commands.push(cmd)
      if (cmd.startsWith('head -c')) return { ok: true, code: 0, stdout: fileText }
      return { ok: true, code: 0, stdout: '===SHELLPILOT-END===\n', ...writeResult }
    }
  })
  return { reader: r, commands }
}

describe('writeImageTag', () => {
  it('writes the edited file and names the backup', async () => {
    const h = writeReader(FILE)
    const r = await h.reader.writeImageTag(
      {},
      { path: '/srv/edge/compose.yaml', service: 'gateway', image: 'nginx:1.29-alpine', expect: PLANNED }
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.plan.from).toBe('nginx:1.27-alpine')
    expect(r.backup).toBe('/srv/edge/compose.yaml.shellpilot-bak')
    const write = h.commands[1]
    expect(write).toContain('image: nginx:1.29-alpine')
    // The one line changed and everything else is carried through verbatim.
    expect(write).toContain('# the edge stack')
    expect(write).toContain('image: redis:7.2-alpine')
    expect(write).toContain(`<<'${COMPOSE_HEREDOC}'`)
  })

  it('refuses when the file on the server is not the one the operator saw', async () => {
    // Somebody else edited it between the panel reading it and the operator
    // pressing the button. Writing the line they approved would put it in the
    // wrong place.
    const moved = FILE.replace('# the edge stack\n', '')
    const h = writeReader(moved)
    const r = await h.reader.writeImageTag(
      {},
      { path: '/srv/edge/compose.yaml', service: 'gateway', image: 'nginx:1.29-alpine', expect: PLANNED }
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toContain('changed since it was read')
    // Only the read ran.
    expect(h.commands).toHaveLength(1)
  })

  it('never escalates a write on its own', async () => {
    const h = writeReader(FILE)
    await h.reader.writeImageTag(
      {},
      { path: '/srv/edge/compose.yaml', service: 'gateway', image: 'nginx:1.29-alpine', expect: PLANNED }
    )
    // No `sudo -n true` probe, and no sudo in either command. The operator
    // approved changing a tag, not changing it as root.
    expect(h.commands.some((c) => c.includes('sudo'))).toBe(false)
  })

  it('does not report a half-finished write as a successful edit', async () => {
    // The write chain is `cp && tee && mv && echo <marker>`. A shell that died
    // between stages can still exit 0, so the marker is what proves the mv ran.
    const h = writeReader(FILE, { stdout: '' })
    const r = await h.reader.writeImageTag(
      {},
      { path: '/srv/edge/compose.yaml', service: 'gateway', image: 'nginx:1.29-alpine', expect: PLANNED }
    )
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('the compose file was not written')
  })

  it('reports a refused read rather than writing to a file it could not see', async () => {
    const r = new ComposeReader({
      exec: async () => ({ ok: true, code: 1, stdout: '', stderr: 'head: /srv/edge/compose.yaml: Permission denied' })
    })
    const out = await r.writeImageTag(
      {},
      { path: '/srv/edge/compose.yaml', service: 'gateway', image: 'nginx:1.29-alpine', expect: PLANNED }
    )
    expect(out.ok).toBe(false)
    if (out.ok) return
    expect(out.reason).toContain('Permission denied')
  })

  it('refuses a path or an image it cannot prove safe, without running anything', async () => {
    const h = writeReader(FILE)
    const bad = await h.reader.writeImageTag(
      {},
      { path: "/srv/edge/'; rm -rf /", service: 'gateway', image: 'nginx:1.29-alpine', expect: PLANNED }
    )
    expect(bad.ok).toBe(false)
    expect(h.commands).toEqual([])

    const badImage = await h.reader.writeImageTag(
      {},
      { path: '/srv/edge/compose.yaml', service: 'gateway', image: '../etc/passwd', expect: PLANNED }
    )
    expect(badImage.ok).toBe(false)
    if (badImage.ok) return
    expect(badImage.reason).toContain('not a valid image reference')
  })
})
