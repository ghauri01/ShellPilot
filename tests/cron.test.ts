import { describe, it, expect } from 'vitest'
import {
  parseCrontab,
  parseSystemdTimers,
  parseCronCollection,
  describeSchedule,
  CRON_COLLECT_COMMAND
} from '../src/shared/cron'

// Read-only first, deliberately: cron has more traps than it looks and every
// one is a silent misread rather than an error. Writing on top of a parser that
// has not been proven against real files is how a scheduler eats a job.

describe('the user field, which is the trap', () => {
  it('does not invent a user in a personal crontab', () => {
    // `0 3 * * * /usr/bin/backup` — parsed as a system crontab this reports
    // the user as "/usr/bin/backup" and shifts the command left by a word.
    const r = parseCrontab('0 3 * * * /usr/bin/backup --all', 'crontab -l', 'user-crontab', false)
    expect(r.entries[0]).toMatchObject({ user: null, command: '/usr/bin/backup --all' })
  })

  it('reads the user in a system crontab', () => {
    const r = parseCrontab('0 3 * * * root /usr/bin/backup --all', '/etc/crontab', 'system-crontab', true)
    expect(r.entries[0]).toMatchObject({ user: 'root', command: '/usr/bin/backup --all' })
  })
})

describe('lines that are not jobs', () => {
  it('skips comments and blanks', () => {
    expect(parseCrontab('# a note\n\n  \n', 'f', 'user-crontab', false).entries).toEqual([])
  })

  it('skips environment assignments', () => {
    // MAILTO="" and PATH=... are legal crontab lines carrying no schedule.
    // Parsed as jobs they produce a "job" with an empty command.
    const r = parseCrontab('MAILTO=""\nPATH=/usr/bin:/bin\n0 1 * * * /x', 'f', 'user-crontab', false)
    expect(r.entries).toHaveLength(1)
    expect(r.entries[0].command).toBe('/x')
  })

  it('keeps a malformed line rather than dropping it', () => {
    // A job silently missing from this view is a scheduled command nobody
    // knows about, which is worse than an ugly row.
    const r = parseCrontab('this is not a crontab line', 'f', 'user-crontab', false)
    expect(r.entries).toEqual([])
    expect(r.unparsed).toEqual([{ origin: 'f', line: 'this is not a crontab line' }])
  })

  it('handles @reboot and friends, with and without a user field', () => {
    const u = parseCrontab('@reboot /usr/bin/start', 'f', 'user-crontab', false)
    expect(u.entries[0]).toMatchObject({ schedule: '@reboot', user: null, command: '/usr/bin/start' })
    const s = parseCrontab('@daily backupuser /usr/bin/run', 'f', 'system-crontab', true)
    expect(s.entries[0]).toMatchObject({ user: 'backupuser', command: '/usr/bin/run' })
  })
})

describe('saying when it runs', () => {
  it('describes the common shapes', () => {
    expect(describeSchedule('0 3 * * *')).toBe('at 03:00 every day')
    expect(describeSchedule('*/5 * * * *')).toBe('every 5 minutes')
    expect(describeSchedule('* * * * *')).toBe('every minute')
    expect(describeSchedule('30 * * * *')).toBe('at 30 minutes past every hour')
    expect(describeSchedule('0 4 * * 1')).toBe('at 04:00 every Monday')
    expect(describeSchedule('@daily')).toBe('at midnight every day')
  })

  it('declines to describe what it is not sure of', () => {
    // A wrong sentence about when a job runs is worse than none: someone reads
    // "every day at 3am", does not check, and it has been running every minute
    // for a month.
    expect(describeSchedule('0 0 1-7 * 1#2')).toBeNull()
    expect(describeSchedule('not a schedule')).toBeNull()
  })

  it('never throws on junk', () => {
    for (const s of ['', '   ', '@nope', '1 2 3', '* * * * * * *']) {
      expect(() => describeSchedule(s)).not.toThrow()
    }
  })
})

describe('systemd timers', () => {
  const sample = [
    'NEXT                         LEFT     LAST                         PASSED    UNIT                         ACTIVATES',
    'Tue 2026-09-02 06:00:00 UTC  5h left  Mon 2026-09-01 06:00:00 UTC  18h ago   logrotate.timer              logrotate.service',
    'n/a                          n/a      Mon 2026-09-01 00:00:00 UTC  1 day ago certbot.timer                certbot.service',
    '',
    '2 timers listed.'
  ].join('\n')

  it('reads the unit and what it activates', () => {
    const r = parseSystemdTimers(sample)
    expect(r.entries.map((e) => e.origin)).toEqual(['logrotate.timer', 'certbot.timer'])
    expect(r.entries[0].command).toBe('logrotate.service')
  })

  it('carries next and last run, and treats n/a as absent', () => {
    const r = parseSystemdTimers(sample)
    expect(r.entries[0].nextRun).toMatch(/2026-09-02/)
    expect(r.entries[1].nextRun).toBeUndefined()
    expect(r.entries[1].lastRun).toMatch(/2026-09-01/)
  })

  it('ignores the header and the footer', () => {
    expect(parseSystemdTimers(sample).entries).toHaveLength(2)
  })

  it('does not describe a timer schedule it has not read', () => {
    // The calendar spec lives in the unit file, not in this table. Claiming a
    // description here would be inventing one.
    expect(parseSystemdTimers(sample).entries[0].description).toBeNull()
  })
})

describe('collecting from one host', () => {
  const output = [
    '===SHELLPILOT-USER===',
    '0 2 * * * /home/me/backup.sh',
    '===SHELLPILOT-SYSTEM===',
    '17 * * * * root cd / && run-parts --report /etc/cron.hourly',
    '===SHELLPILOT-CROND===',
    '#FILE:/etc/cron.d/certbot',
    '0 */12 * * * root test -x /usr/bin/certbot && certbot -q renew',
    '#FILE:/etc/cron.d/sysstat',
    '5-55/10 * * * * sysstat /usr/lib/sysstat/debian-sa1 1 1',
    '===SHELLPILOT-TIMERS===',
    'NEXT  LEFT  LAST  PASSED  UNIT  ACTIVATES',
    'Tue 2026-09-02 06:00:00 UTC  5h left  Mon 2026-09-01 06:00:00 UTC  18h ago   logrotate.timer  logrotate.service'
  ].join('\n')

  it('attributes each section to the right format', () => {
    const r = parseCronCollection(output)
    const user = r.entries.find((e) => e.kind === 'user-crontab')
    const system = r.entries.find((e) => e.kind === 'system-crontab')
    // The user crontab has no user field; the system one does. Getting this
    // backwards is a plausible-looking lie rather than an error.
    expect(user).toMatchObject({ user: null, command: '/home/me/backup.sh' })
    expect(system?.user).toBe('root')
  })

  it('attributes each cron.d entry to its own file', () => {
    // An entry filed under the wrong path is an entry nobody can find again.
    const r = parseCronCollection(output)
    const crond = r.entries.filter((e) => e.kind === 'cron.d')
    expect(crond.map((e) => e.origin)).toEqual(['/etc/cron.d/certbot', '/etc/cron.d/sysstat'])
    expect(crond[1].user).toBe('sysstat')
  })

  it('picks up systemd timers from the same collection', () => {
    expect(parseCronCollection(output).entries.some((e) => e.kind === 'systemd-timer')).toBe(true)
  })

  it('survives a host with nothing scheduled', () => {
    const empty = ['===SHELLPILOT-USER===', '===SHELLPILOT-SYSTEM===', '===SHELLPILOT-CROND===', '===SHELLPILOT-TIMERS==='].join('\n')
    expect(parseCronCollection(empty)).toEqual({ entries: [], unparsed: [] })
  })

  it('survives output with sections missing entirely', () => {
    // A host without systemctl produces no timer section at all.
    expect(() => parseCronCollection('===SHELLPILOT-USER===\n0 1 * * * /x')).not.toThrow()
    expect(parseCronCollection('===SHELLPILOT-USER===\n0 1 * * * /x').entries).toHaveLength(1)
  })
})

describe('the collector command', () => {
  it('never fails the whole collection for one missing source', () => {
    // No /etc/cron.d, or a user with no crontab, is the normal case.
    // Each collected source carries its own guard, so a host with no
    // /etc/cron.d or a user with no crontab still returns the other sections.
    const guarded = CRON_COLLECT_COMMAND.split('; echo').filter((s) => /crontab|cat|for f|systemctl/.test(s))
    expect(guarded.length).toBeGreaterThanOrEqual(4)
    for (const s of guarded) expect(s, s).toMatch(/\|\| true/)
  })

  it('is read-only', () => {
    // The whole premise of shipping this before any editing.
    // `2>/dev/null` is the only redirect allowed; anything writing to a real
    // path, removing a crontab, or touching unit state fails this.
    expect(CRON_COLLECT_COMMAND).not.toMatch(/crontab\s+-r/)
    expect(CRON_COLLECT_COMMAND).not.toMatch(/\b(rm|tee|mv|cp|chmod|chown)\b/)
    expect(CRON_COLLECT_COMMAND).not.toMatch(/systemctl\s+(start|stop|enable|disable|mask)/)
    const redirects = CRON_COLLECT_COMMAND.match(/>+\s*\S+/g) ?? []
    for (const r of redirects) expect(r, r).toMatch(/\/dev\/null/)
  })
})
