import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  DOCKER_MARKERS,
  buildDockerDiskCommand,
  buildDockerDiskDetailCommand,
  buildDockerInspectCommand,
  buildDockerListCommand,
  buildDockerLogsCommand,
  buildDockerShellCommand,
  DOCKER_SEP,
  parseDockerOutput,
  resolveBinary
} from '../src/shared/docker'

// Podman, tested against a real one rather than reasoned about.
//
// podman 5.8.4 in a container, driven with the exact templates this module
// ships. The fixture beside this file is its output, captured not written --
// see tests/fixtures/docker/README.md for why that distinction is enforced
// here.
//
// WHAT THIS COULD NOT VERIFY, said plainly rather than left to be discovered:
// port mappings. Podman nested inside Docker cannot publish a port, so
// `{{.Ports}}` came back empty for a container started with `-p 8080:80` and
// that empty string is an artefact of the harness, not a finding about podman.
// Nothing here asserts anything about ports, and nothing was changed on the
// strength of that reading.

const FIXTURE = readFileSync(
  join(__dirname, 'fixtures/docker/podman/podman-5.8.4.txt'),
  'utf8'
)
const section = (name: string): string => {
  const m = FIXTURE.split(`===${name}===`)[1] ?? ''
  return m.split('===')[0].trim()
}

/**
 * The fixture, reassembled into exactly what the module would receive over SSH.
 *
 * The version line comes first and the rows are separated by the real
 * DOCKER_SEP. The fixture stores `|` instead so that a diff of it is readable;
 * substituting here rather than at capture time keeps the file human-checkable
 * without weakening what the parser is fed.
 */
const podmanOutput = (): string => {
  const version = section('VERSION').replace(/^podman version /, '')
  const rows = section('PS')
    .split('\n')
    .map((l) => l.split('|').join(DOCKER_SEP))
    .join('\n')
  return `${version}\n${DOCKER_MARKERS.ps}\n${rows}\n`
}

describe('finding the runtime at all, which is where podman actually broke', () => {
  it('looks for podman as well as docker', () => {
    // The real gap, and it was never about parsing. A stock podman install has
    // NO `docker` binary -- confirmed, `command -v docker` finds nothing in the
    // official image -- so every call site that resolved only `docker` reported
    // the runtime absent on a server that was running containers.
    const probe = resolveBinary('docker', [], ['podman'])
    expect(probe).toContain('podman')
    expect(probe).toContain('/usr/bin/podman')
  })

  it('probes podman in the commands this module actually SHIPS', () => {
    // The test above passes `['podman']` in by hand, so it proves the helper
    // can look for podman and nothing about whether anything asks it to.
    // Deleting podman from every call site left it green. These are the built
    // commands, which is the thing that reaches a server.
    for (const [name, cmd] of [
      ['list', buildDockerListCommand()],
      ['disk', buildDockerDiskCommand()],
      ['disk detail', buildDockerDiskDetailCommand()],
      ['inspect', buildDockerInspectCommand('abc')],
      ['logs', buildDockerLogsCommand('abc')],
      ['shell', buildDockerShellCommand('abc')]
    ] as const) {
      expect(cmd, name).toContain('podman')
    }
  })

  it('still prefers docker on a machine that has both', () => {
    // Every path for docker before any path for podman. Interleaving by
    // directory would pick podman from /usr/bin over docker in
    // /usr/local/bin, which is a silent runtime switch on a working host.
    const probe = resolveBinary('docker', [], ['podman'])
    const firstPodman = probe.indexOf('podman')
    for (const p of ['docker', '/usr/bin/docker', '/usr/local/bin/docker', '/snap/bin/docker']) {
      expect(probe.indexOf(p), p).toBeLessThan(firstPodman)
    }
  })
})

describe('what podman actually printed for the templates this module ships', () => {
  it('renders the ps template in the same shape docker does', () => {
    // Reconstructed with the real separator: the fixture is captured with `|`
    // so it stays readable in a diff, and the parser is fed what the module
    // would actually receive.
    const probe = parseDockerOutput(podmanOutput(), 0)

    expect(probe.ok).toBe(true)
    expect(probe.ok && probe.containers.map((c) => c.name).sort()).toEqual(['dead', 'web'])
  })

  it('reports podman’s fully qualified image names without mangling them', () => {
    // podman says `docker.io/library/alpine:latest` where docker says
    // `alpine:latest`. Longer, and it contains the separator-adjacent
    // characters a naive split would trip on.
    const probe = parseDockerOutput(podmanOutput(), 0)
    for (const c of probe.ok ? probe.containers : []) {
      expect(c.image).toBe('docker.io/library/alpine:latest')
    }
  })

  it('uses the same state words docker does', () => {
    // `running` / `exited`, not a podman spelling. If this ever diverges the
    // panel's grouping silently empties.
    expect(section('PS')).toMatch(/\|exited\|/)
  })

  it('answers the compose label template rather than failing it', () => {
    // `{{.Label "com.docker.compose.project"}}` is a docker CLI template
    // method, and a runtime that cannot render it costs the panel its
    // grouping. Podman renders it, and renders an unlabelled container as
    // empty rather than as an error.
    const labels = section('LABELS').split('\n')
    expect(labels[0]).toMatch(/\|shop\|web$/)
    expect(labels[1]).toMatch(/\|\|$/)
  })

  it('lays system df out the way the disk view reads it', () => {
    const df = section('DF')
    expect(df.split('\n')[0]).toMatch(/TYPE\s+TOTAL\s+ACTIVE\s+SIZE\s+RECLAIMABLE/)
    expect(df).toMatch(/^Images\s/m)
    expect(df).toMatch(/^Containers\s/m)
    // Docker's own wording, which the parser keys on.
    expect(df).toMatch(/^Local Volumes\s/m)
  })
})
