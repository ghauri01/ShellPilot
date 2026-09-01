import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, symlinkSync, writeFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { LocalShell } from '../src/shared/local'
import {
  finaliseLabels,
  findShell,
  isInteractiveShell,
  listShells,
  parseDsclShell,
  parseWslDistros,
  sanitisedEnv,
  shellIdFor
} from '../src/main/services/shellDiscovery'

const scratch = mkdtempSync(join(tmpdir(), 'shellpilot-shells-'))

describe('WSL distro enumeration', () => {
  it('decodes `wsl -l -q` output as UTF-16LE with a BOM', () => {
    // wsl.exe writes UTF-16LE. Read as utf8 the names come back as
    // "U\0b\0u\0n\0t\0u\0" — visibly wrong in a dropdown, and unusable as a
    // -d argument. This is the single most common WSL integration bug.
    const buf = Buffer.from('\ufeffUbuntu-24.04\r\nDebian\r\n', 'utf16le')
    expect(parseWslDistros(buf)).toEqual(['Ubuntu-24.04', 'Debian'])
  })

  it('drops blank lines and trailing whitespace', () => {
    const buf = Buffer.from('Ubuntu \r\n\r\n  \r\nDebian\r\n', 'utf16le')
    expect(parseWslDistros(buf)).toEqual(['Ubuntu', 'Debian'])
  })

  it('returns nothing when WSL reports no distributions', () => {
    expect(parseWslDistros(Buffer.from('', 'utf16le'))).toEqual([])
  })
})

describe('dscl fallback on macOS', () => {
  it('reads the shell out of a dscl record', () => {
    expect(parseDsclShell('UserShell: /bin/zsh\n')).toBe('/bin/zsh')
  })

  it('returns null for a record with no UserShell', () => {
    expect(parseDsclShell('No such key: UserShell\n')).toBeNull()
  })
})

describe('interactive shell suitability', () => {
  it('rejects dash, which has no line editing or history', () => {
    // /bin/sh is dash on Debian and Ubuntu. Offering it as "your shell" gets
    // reported as a broken terminal: arrow keys print ^[[A and there is no
    // history at all.
    expect(isInteractiveShell('/bin/dash')).toBe(false)
    expect(isInteractiveShell('/usr/bin/dash')).toBe(false)
  })

  it('rejects nologin and false', () => {
    expect(isInteractiveShell('/usr/sbin/nologin')).toBe(false)
    expect(isInteractiveShell('/bin/false')).toBe(false)
  })

  it('accepts the real interactive shells', () => {
    for (const s of ['/bin/zsh', '/bin/bash', '/usr/bin/fish', '/opt/homebrew/bin/nu']) {
      expect(isInteractiveShell(s)).toBe(true)
    }
  })

  it('rejects a shell whose name is fine but which resolves to dash', () => {
    // The real Debian/Ubuntu shape: /bin/sh is a SYMLINK to dash, so the
    // basename never says "dash" and a name-only check waves it through. The
    // link is named something other than `sh` on purpose — a check that only
    // special-cases the literal name "sh" would pass this test without ever
    // resolving anything.
    writeFileSync(join(scratch, 'dash'), '')
    symlinkSync(join(scratch, 'dash'), join(scratch, 'localsh'))
    expect(isInteractiveShell(join(scratch, 'localsh'))).toBe(false)
  })

  it('accepts a /bin/sh-shaped link when it resolves to bash', () => {
    // Not every /bin/sh is dash: on RHEL and on macOS it is bash. Rejecting
    // the name outright would drop a perfectly good shell, which is why the
    // check resolves the link instead of denying the basename.
    writeFileSync(join(scratch, 'bash'), '')
    symlinkSync(join(scratch, 'bash'), join(scratch, 'sh'))
    expect(isInteractiveShell(join(scratch, 'sh'))).toBe(true)
  })

  it('does not throw on a broken symlink', () => {
    symlinkSync(join(scratch, 'does-not-exist'), join(scratch, 'dangling'))
    expect(() => isInteractiveShell(join(scratch, 'dangling'))).not.toThrow()
    expect(isInteractiveShell(join(scratch, 'dangling'))).toBe(true)
  })

  it('rejects the empty path', () => {
    expect(isInteractiveShell('')).toBe(false)
  })
})

describe('shell ids', () => {
  it('distinguishes two shells with the same name in different directories', () => {
    // The bug this replaces: `darwin-${basename(path)}` gave /bin/zsh and
    // /opt/homebrew/bin/zsh the same id, so the second was unselectable
    // (findShell matched the first) and React saw duplicate keys.
    expect(shellIdFor('darwin', '/bin/zsh')).not.toBe(shellIdFor('darwin', '/opt/homebrew/bin/zsh'))
  })

  it('is stable for a given path', () => {
    expect(shellIdFor('darwin', '/bin/zsh')).toBe(shellIdFor('darwin', '/bin/zsh'))
  })

  it('keeps the shell name readable in the id', () => {
    expect(shellIdFor('darwin', '/opt/homebrew/bin/zsh')).toMatch(/^darwin-zsh-[0-9a-f]{8}$/)
  })

  it('drops the .exe suffix so Windows ids read like the others', () => {
    expect(shellIdFor('win32', 'C:\\Windows\\System32\\cmd.exe')).toMatch(/^win32-cmd-[0-9a-f]{8}$/)
  })
})

describe('shell labels', () => {
  const shell = (path: string, isDefault = false): LocalShell => ({
    id: shellIdFor('darwin', path),
    label: '',
    kind: 'posix',
    path,
    args: ['-l'],
    isDefault
  })

  it('names the directory when two shells share a name', () => {
    // Distinct ids made the Homebrew zsh selectable; this is what makes it
    // tellable-apart from /bin/zsh in the picker.
    const [brew, sys] = finaliseLabels([shell('/opt/homebrew/bin/zsh', true), shell('/bin/zsh')])
    expect(brew.label).toBe('zsh — /opt/homebrew/bin (default)')
    expect(sys.label).toBe('zsh — /bin')
  })

  it('leaves an unambiguous name alone', () => {
    const [zsh, bash] = finaliseLabels([shell('/bin/zsh', true), shell('/bin/bash')])
    expect(zsh.label).toBe('zsh (default)')
    expect(bash.label).toBe('bash')
  })

  it('marks the default shell, not whichever one is zsh', () => {
    // The rule this replaces was `name === 'zsh' ? 'zsh (default)' : name`,
    // which labelled the wrong row on any machine whose login shell is bash.
    const [bash, zsh] = finaliseLabels([shell('/bin/bash', true), shell('/bin/zsh')])
    expect(bash.label).toBe('bash (default)')
    expect(zsh.label).toBe('zsh')
  })
})

describe('sanitised environment', () => {
  const saved = { ...process.env }

  beforeEach(() => {
    for (const k of Object.keys(process.env)) delete process.env[k]
    Object.assign(process.env, saved)
  })

  afterEach(() => {
    for (const k of Object.keys(process.env)) delete process.env[k]
    Object.assign(process.env, saved)
  })

  it('strips every ELECTRON_ variable, not a hand-picked three', () => {
    process.env.ELECTRON_RUN_AS_NODE = '1'
    process.env.ELECTRON_NO_ATTACH_CONSOLE = '1'
    process.env.ELECTRON_RENDERER_URL = 'http://localhost:5173'
    process.env.ELECTRON_NO_ASAR = '1'
    const env = sanitisedEnv()
    expect(Object.keys(env).filter((k) => k.startsWith('ELECTRON_'))).toEqual([])
  })

  it('strips NODE_OPTIONS', () => {
    process.env.NODE_OPTIONS = '--require /tmp/evil.js'
    expect(sanitisedEnv().NODE_OPTIONS).toBeUndefined()
  })

  it('strips NODE_REPL_EXTERNAL_MODULE, which NODE_OPTIONS does not cover', () => {
    // Its own class of code execution: it loads an arbitrary module into every
    // `node` the user starts from the terminal, and it is not reachable
    // through NODE_OPTIONS at all.
    process.env.NODE_REPL_EXTERNAL_MODULE = '/tmp/evil.js'
    expect(sanitisedEnv().NODE_REPL_EXTERNAL_MODULE).toBeUndefined()
  })

  it('keeps the variables a shell actually needs', () => {
    process.env.PATH = '/usr/bin:/bin'
    process.env.HOME = '/home/tester'
    const env = sanitisedEnv()
    expect(env.PATH).toBe('/usr/bin:/bin')
    expect(env.HOME).toBe('/home/tester')
  })

  it('declares the terminal', () => {
    const env = sanitisedEnv()
    expect(env.TERM).toBe('xterm-256color')
    expect(env.COLORTERM).toBe('truecolor')
    expect(env.TERM_PROGRAM).toBe('ShellPilot')
    // Comes from app.getVersion(); the electron mock returns 0.0.0-test.
    expect(env.TERM_PROGRAM_VERSION).toBe('0.0.0-test')
  })

  it('defaults the locale only when the user has none', () => {
    delete process.env.LANG
    delete process.env.LC_ALL
    expect(sanitisedEnv().LANG).toBe('en_US.UTF-8')

    process.env.LANG = 'de_DE.UTF-8'
    expect(sanitisedEnv().LANG).toBe('de_DE.UTF-8')

    delete process.env.LANG
    process.env.LC_ALL = 'C'
    expect(sanitisedEnv().LANG).toBeUndefined()
  })

  it('never invents a value for an unset variable', () => {
    delete process.env.SHELLPILOT_NOT_SET
    expect('SHELLPILOT_NOT_SET' in sanitisedEnv()).toBe(false)
  })
})

describe('the app puts nothing secret into its own environment', () => {
  it('makes no process.env assignments outside the dev renderer URL', async () => {
    // sanitisedEnv() forwards the parent environment wholesale, so it is only
    // safe as long as ShellPilot never parks a credential, a vault key or the
    // MCP pairing token in process.env. Nothing enforces that but this.
    const files = ['src/main/index.ts']
    const assignments: string[] = []
    for (const rel of files) {
      const src = await readFile(new URL(`../${rel}`, import.meta.url), 'utf8')
      for (const m of src.matchAll(/process\.env(?:\.(\w+)|\['(\w+)'\])\s*=[^=]/g)) {
        assignments.push(m[1] ?? m[2])
      }
    }
    expect(assignments).toEqual([])
  })
})

describe('shell list and lookup', () => {
  it('gives every discovered shell a distinct id', async () => {
    const shells = await listShells(true)
    expect(new Set(shells.map((s) => s.id)).size).toBe(shells.length)
  })

  it('marks at most one shell as the default', async () => {
    const shells = await listShells()
    expect(shells.filter((s) => s.isDefault).length).toBeLessThanOrEqual(1)
  })

  it('labels the default, and only the default, as "(default)"', async () => {
    for (const s of await listShells()) {
      expect(s.label.endsWith(' (default)')).toBe(s.isDefault === true)
    }
  })

  it('returns absolute paths only', async () => {
    for (const s of await listShells()) {
      expect(s.path.length).toBeGreaterThan(1)
      expect(/^([/]|[A-Za-z]:\\)/.test(s.path)).toBe(true)
    }
  })

  it('finds a shell by its exact id', async () => {
    const shells = await listShells()
    if (shells.length === 0) return
    await expect(findShell(shells[0].id)).resolves.toEqual(shells[0])
  })

  it('returns null for an unknown id rather than falling back to the default', async () => {
    // The fallback this replaces made shellId non-enforcing: any unknown or
    // attacker-chosen id spawned the user's default shell and reported
    // `ready`. The picker chooses the default explicitly instead.
    const shells = await listShells()
    expect(shells.some((s) => s.isDefault)).toBe(shells.length > 0)
    await expect(findShell('no-such-shell-id')).resolves.toBeNull()
  })

  it.skipIf(process.platform !== 'darwin')('offers a login zsh on macOS', async () => {
    const shells = await listShells(true)
    const zsh = shells.find((s) => s.path.endsWith('/zsh'))
    expect(zsh).toBeDefined()
    expect(zsh?.args).toEqual(['-l'])
    expect(zsh?.kind).toBe('posix')
  })
})
