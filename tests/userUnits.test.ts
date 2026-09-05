import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  USER_UNIT_MARKERS,
  buildUserUnitsCommand,
  parseLinger,
  parseUserUnitRow,
  parseUserUnits,
  summariseUserUnits
} from '../src/shared/userUnits'

// Read against a real RHEL 9.8 with systemd 252 — the OS this feature exists
// for — rather than from the manual. The fixture beside this file is what that
// server printed.

const FIXTURE = readFileSync(join(__dirname, 'fixtures/userunits/rhel9-systemd252.txt'), 'utf8')
const section = (name: string): string => {
  const after = FIXTURE.split(`===${name}===`)[1] ?? ''
  return after.split('===')[0].replace(/\n$/, '')
}
const output = (linger: string, units: string): string =>
  `${USER_UNIT_MARKERS.linger}\n${linger}\n${USER_UNIT_MARKERS.units}\n${units}\n`

describe('whether the account is lingering, which decides what "running" means', () => {
  it('reads the yes the server actually prints', () => {
    expect(parseLinger(section('LINGER-ON'))).toBe('lingering')
  })

  it('reads the FAILURE for a non-lingering account as not lingering', () => {
    // loginctl does not print `Linger=no` for an account with no session. It
    // fails: "Failed to get user: User ID 1001 is not logged in or lingering".
    // That is the answer, not an error — and treating it as unknown would drop
    // the warning in exactly the case the warning exists for, because an
    // account nobody is logged into is where a service quietly is not running.
    expect(parseLinger(section('LINGER-OFF'))).toBe('not-lingering')
    expect(section('LINGER-OFF')).toMatch(/not logged in or lingering/)
  })

  it('is unknown only when nothing was said at all', () => {
    expect(parseLinger('')).toBe('unknown')
    expect(parseLinger(undefined)).toBe('unknown')
  })
})

describe('the unit rows this server printed', () => {
  const units = section('UNITS')

  it('reads every service, including the failed one', () => {
    const r = parseUserUnits(output(section('LINGER-ON'), units), 0)
    expect(r.status).toBe('ok')
    expect(r.units.map((u) => u.name)).toContain('api.service')
    expect(r.units.find((u) => u.name === 'broken.service')?.active).toBe('failed')
  })

  it('keeps a description that contains spaces', () => {
    // DESCRIPTION is last and has spaces in it, so the split is bounded at
    // four columns. A greedy split loses every description worth showing.
    const r = parseUserUnits(output('Linger=yes', units), 0)
    expect(r.units.find((u) => u.name === 'api.service')?.description).toBe('Demo API')
    expect(
      r.units.find((u) => u.name === 'systemd-tmpfiles-setup.service')?.description
    ).toBe("Create User's Volatile Files and Directories")
  })

  it('ignores anything that is not a service unit', () => {
    expect(parseUserUnitRow('  dev-vda1.device loaded activating tentative /dev/vda1')).toBeNull()
    expect(parseUserUnitRow('')).toBeNull()
  })
})

describe('the reading that would otherwise be wrong in the reassuring direction', () => {
  it('ALARMS when services are running and the account is not lingering', () => {
    // The whole point. `su -` opens a session, so logind starts a user manager
    // and the units read as `active running` over SSH — and they are killed
    // when that session ends. The panel would say "running" about a service
    // that is about to stop.
    const r = parseUserUnits(output(section('LINGER-OFF'), section('UNITS')), 0)
    expect(r.linger).toBe('not-lingering')

    const s = summariseUserUnits(r)
    expect(s.level).toBe('alarm')
    expect(s.headline).toMatch(/stop when your last session ends/)
    // Said as what will happen, not as a config flag nobody can act on.
    expect(s.headline).toMatch(/enable-linger/)
  })

  it('does not raise that alarm when the account IS lingering', () => {
    const r = parseUserUnits(output(section('LINGER-ON'), section('UNITS')), 0)
    const s = summariseUserUnits(r)
    expect(s.headline).not.toMatch(/stop when/)
    // The failed unit is still worth saying.
    expect(s.level).toBe('alarm')
    expect(s.headline).toMatch(/failed/)
  })
})

describe('a server that cannot answer, told apart from one with nothing to say', () => {
  it('reports an unreachable user bus rather than an empty list', () => {
    // Observed on the same server with linger off and no session:
    // "Failed to connect to bus: No medium found". Zero units is what that
    // looks like to a naive reader, and it is not zero units.
    const r = parseUserUnits(output('', 'Failed to connect to bus: No medium found'), 1)
    expect(r.status).toBe('no-bus')
    expect(r.units).toEqual([])
    expect(summariseUserUnits(r).headline).toMatch(/enable-linger/)
  })

  it('tells a container without systemd apart from a server without systemctl', () => {
    // Every image built from a distro base has systemctl and no PID 1 systemd.
    // Calling that "not installed" sends somebody to install a package that is
    // already there.
    const noPid1 = parseUserUnits(
      output('', 'System has not been booted with systemd as init system (PID 1). Can\'t operate.'),
      1
    )
    expect(noPid1.status).toBe('unsupported')

    const noTool = parseUserUnits(output('', 'systemctl: command not found'), 127)
    expect(noTool.status).toBe('no-tool')
  })
})

describe('the command this module actually ships, run on a real RHEL 9 server', () => {
  // Not the parser fed a hand-built string: the built command was copied to a
  // RHEL 9.8 container running systemd 252 and executed as an unprivileged
  // account, and this is what came back. It is the difference between "the
  // regexes match what I typed" and "the shell fragment works over ssh".
  const REAL = readFileSync(
    join(__dirname, 'fixtures/userunits/rhel9-roundtrip.txt'),
    'utf8'
  )

  it('produces output this parser reads, end to end', () => {
    const r = parseUserUnits(REAL, 0)
    expect(r.status).toBe('ok')
    expect(r.linger).toBe('lingering')
    expect(r.units.find((u) => u.name === 'api.service')?.sub).toBe('running')
  })

  it('reads nothing and writes nothing', () => {
    // A supervisor reader that could start or stop a unit would be a supervisor,
    // which is the thing processes.ts refused to build remotely.
    const cmd = buildUserUnitsCommand()
    for (const verb of [' start ', ' stop ', ' restart ', ' enable ', ' disable ', 'daemon-reload']) {
      expect(cmd, verb).not.toContain(verb)
    }
    expect(cmd).toContain('list-units')
  })

  it('sets XDG_RUNTIME_DIR itself, because a non-login ssh shell has none', () => {
    // Without it `systemctl --user` cannot find the bus even where a manager is
    // running — a failure of the environment we handed it, which would
    // otherwise be reported as a fact about the server.
    expect(buildUserUnitsCommand()).toContain('XDG_RUNTIME_DIR')
    expect(buildUserUnitsCommand()).toContain('id -u')
  })
})
