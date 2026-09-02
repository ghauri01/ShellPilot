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

// ---------------------------------------------------------------------------
// Everything below is checked against output shapes copied from real hosts
// rather than invented ones. Every case here failed before the parser was
// changed; the comment on each says what the real input was.
// ---------------------------------------------------------------------------

describe('Debian /etc/crontab, as shipped', () => {
  // Straight out of a stock bookworm image. The separators between the fields
  // are TABS, and the run-parts lines are the point of the file.
  const DEBIAN_CRONTAB = [
    '# /etc/crontab: system-wide crontab',
    '# Unlike any other crontab you don\'t have to run the `crontab\'',
    '# command to install the new version when you edit this file',
    '# and files in /etc/cron.d. These files also have username fields,',
    '# that none of the other crontabs do.',
    '',
    'SHELL=/bin/sh',
    'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin',
    '',
    '# Example of job definition:',
    '# .---------------- minute (0 - 59)',
    '# |  .------------- hour (0 - 23)',
    '# *  *  *  *  * user-name  command to be executed',
    '17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly',
    '25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }',
    '47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }',
    '52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }',
    '#'
  ].join('\n')

  it('reads every job in it and invents none', () => {
    const r = parseCrontab(DEBIAN_CRONTAB, '/etc/crontab', 'system-crontab', true)
    expect(r.entries).toHaveLength(4)
    expect(r.unparsed).toEqual([])
    expect(r.entries.every((e) => e.user === 'root')).toBe(true)
  })

  it('reads a tab-separated schedule as a schedule', () => {
    const r = parseCrontab(DEBIAN_CRONTAB, '/etc/crontab', 'system-crontab', true)
    expect(r.entries[0].schedule).toBe('17 * * * *')
    expect(r.entries[0].description).toBe('at 17 minutes past every hour')
  })

  it('does not treat the commented example line as a job', () => {
    // `# *  *  *  *  * user-name  command to be executed` is five fields and a
    // command; only the leading `#` says it is not a job.
    const r = parseCrontab(DEBIAN_CRONTAB, '/etc/crontab', 'system-crontab', true)
    expect(r.entries.some((e) => e.command.includes('command to be executed'))).toBe(false)
  })
})

describe('the command, byte for byte', () => {
  it('keeps the spacing inside a command instead of collapsing it', () => {
    // `f.slice(5).join(' ')` rewrote every run of whitespace as one space, so
    // the reported command was not the command on disk. It matters most where
    // the spacing is inside quotes: `psql -c "select  1"` and `psql -c
    // "select 1"` are the same query, but `grep -c "a  b"` is not `grep -c
    // "a b"`, and a job whose displayed command differs from the real one is
    // exactly the misread this module exists to prevent.
    const line = '30 4 * * *\troot\t/usr/bin/rsync -a  --exclude "a  b"   /src/ /dst/'
    const r = parseCrontab(line, '/etc/crontab', 'system-crontab', true)
    expect(r.entries[0].command).toBe('/usr/bin/rsync -a  --exclude "a  b"   /src/ /dst/')
  })

  it('keeps a tab inside a command', () => {
    const r = parseCrontab('0 3 * * * /usr/bin/awk -F\t\'{print $1}\' /var/log/x', 'f', 'user-crontab', false)
    expect(r.entries[0].command).toContain('\t')
  })

  it('leaves a trailing "# comment" in the command, because cron does', () => {
    // `#` only starts a comment at the start of a line. `0 3 * * * /x # nightly`
    // really does run a shell command ending in `# nightly` — the shell drops
    // it, cron does not. Stripping it here would show a command that is not
    // the one being run, and would be wrong the moment the `#` is quoted.
    const r = parseCrontab('0 3 * * * /x # nightly', 'f', 'user-crontab', false)
    expect(r.entries[0].command).toBe('/x # nightly')
  })
})

describe('the percent sign, which is not part of the command', () => {
  it('unescapes \\% into a literal percent', () => {
    // `date +\%Y\%m\%d` is in a large fraction of real crontabs. What cron runs
    // is `date +%Y%m%d`; reporting the backslashes shows a command that does
    // not exist.
    const r = parseCrontab(
      '0 3 * * * /usr/bin/mysqldump db > /backup/db-$(date +\\%Y\\%m\\%d).sql',
      'f',
      'user-crontab',
      false
    )
    expect(r.entries[0].command).toBe('/usr/bin/mysqldump db > /backup/db-$(date +%Y%m%d).sql')
    expect(r.entries[0].input).toBeUndefined()
  })

  it('stops the command at the first unescaped percent and keeps the rest as stdin', () => {
    // Cron replaces an unescaped `%` with a newline and feeds everything after
    // the first one to the command on stdin. Shown as one long command it reads
    // as though `Subject:` were an argument.
    const r = parseCrontab(
      '0 7 * * * /usr/bin/mail -s "report" root%Subject: nightly%body line one%body line two',
      'f',
      'user-crontab',
      false
    )
    expect(r.entries[0].command).toBe('/usr/bin/mail -s "report" root')
    expect(r.entries[0].input).toBe('Subject: nightly\nbody line one\nbody line two')
  })

  it('refuses a line whose command is entirely stdin', () => {
    expect(parseCrontab('0 3 * * * %only stdin', 'f', 'user-crontab', false).entries).toEqual([])
  })
})

describe('field syntax that real crontabs use', () => {
  it('accepts a step inside a range, in any field', () => {
    // /etc/cron.d/sysstat ships `5-55/10`; monitoring agents ship `0-30/5`.
    for (const s of ['0-30/5 * * * *', '5-55/10 * * * *', '0 0-23/2 * * *', '0 0 1-28/7 * *']) {
      expect(parseCrontab(`${s} /x`, 'f', 'user-crontab', false).unparsed, s).toEqual([])
    }
  })

  it('accepts */n in every field position', () => {
    for (const s of ['*/2 * * * *', '0 */2 * * *', '0 0 */2 * *', '0 0 1 */2 *', '0 0 * * */2']) {
      expect(parseCrontab(`${s} /x`, 'f', 'user-crontab', false).unparsed, s).toEqual([])
    }
  })

  it('accepts named months and days in the fields that take names', () => {
    // certbot, logwatch and half of /etc/cron.d use these.
    for (const s of ['0 3 * JAN *', '0 3 * * mon', '0 3 * * Mon-Fri', '0 3 * * sun', '0 3 * jan-mar *']) {
      expect(parseCrontab(`${s} /x`, 'f', 'user-crontab', false).unparsed, s).toEqual([])
    }
  })

  it('describes named days rather than giving up on them', () => {
    expect(describeSchedule('0 3 * * Mon-Fri')).toBe('minute 0, hour 3, on Monday to Friday')
    expect(describeSchedule('0 3 * JAN *')).toBe('minute 0, hour 3, month January')
  })

  it('does not accept a name in a field that has no names', () => {
    // Minute, hour and day-of-month are numeric only. Accepting words there is
    // how `this is not a crontab line` became a job with a six-word schedule.
    expect(parseCrontab('JAN 3 * * * /x', 'f', 'user-crontab', false).entries).toEqual([])
    expect(parseCrontab('0 MON * * * /x', 'f', 'user-crontab', false).entries).toEqual([])
  })

  it('does not accept a three-letter word that is not a month or a day', () => {
    expect(parseCrontab('0 3 * FOO * /x', 'f', 'user-crontab', false).entries).toEqual([])
    expect(parseCrontab('0 3 * * XYZ /x', 'f', 'user-crontab', false).entries).toEqual([])
  })

  it('reads a cronie job whose syslog line is suppressed with a leading dash', () => {
    // cronie is the cron on every Red Hat derivative, and a leading `-`
    // suppresses the job's syslog line. It is a logging flag, not a broken
    // schedule, so the job is real and was being reported as unparsed.
    const r = parseCrontab('-*/5 * * * * root /usr/bin/collect', '/etc/cron.d/x', 'cron.d', true)
    expect(r.unparsed).toEqual([])
    expect(r.entries[0]).toMatchObject({ schedule: '*/5 * * * *', user: 'root', command: '/usr/bin/collect' })
  })

  it('does not spend seconds backtracking over a long line', () => {
    // A field is validated against the first five words of every line of every
    // file collected, including lines that are not cron at all. The regex this
    // replaced was O(n^2) on a failing field: 20k characters took 6.5 seconds.
    const line = `${'1,'.repeat(20000)}x * * * * /x`
    const t = Date.now()
    expect(parseCrontab(line, 'f', 'user-crontab', false).entries).toEqual([])
    expect(Date.now() - t).toBeLessThan(500)
  })
})

describe('@specials', () => {
  it('refuses a special that no cron implements', () => {
    // vixie and cronie implement exactly eight. `@every_minute` is not one of
    // them, so cron rejects the line and the job never runs. Listing it as
    // scheduled is the same lie as dropping it — it belongs in `unparsed`,
    // where the panel counts it as a line it did not understand.
    const r = parseCrontab('@every_minute /usr/bin/x', 'f', 'user-crontab', false)
    expect(r.entries).toEqual([])
    expect(r.unparsed).toEqual([{ origin: 'f', line: '@every_minute /usr/bin/x' }])
  })

  it('refuses @reboot with no command', () => {
    const r = parseCrontab('@reboot', 'f', 'user-crontab', false)
    expect(r.entries).toEqual([])
    expect(r.unparsed).toHaveLength(1)
  })

  it('refuses @reboot with a user and no command in a system crontab', () => {
    const r = parseCrontab('@reboot root', '/etc/crontab', 'system-crontab', true)
    expect(r.entries).toEqual([])
    expect(r.unparsed).toHaveLength(1)
  })

  it('still takes the eight that are real, in any case', () => {
    for (const s of ['@reboot', '@YEARLY', '@Annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly']) {
      const r = parseCrontab(`${s} /x`, 'f', 'user-crontab', false)
      expect(r.entries, s).toHaveLength(1)
    }
  })
})

describe('systemctl list-timers, with real column widths', () => {
  // systemd pads each column to its widest cell — and the widest cell is
  // followed by exactly ONE space. `1 week 2 days left` is the widest LEFT
  // value here, so LEFT runs straight into LAST. Splitting on runs of two or
  // more spaces then shifts every date column by one.
  const WIDE = [
    'NEXT                        LEFT                LAST                        PASSED       UNIT                         ACTIVATES',
    'Wed 2026-09-09 06:00:00 UTC 1 week 2 days left Mon 2026-09-01 06:00:00 UTC 18h ago      apt-daily.timer              apt-daily.service',
    'Tue 2026-09-02 06:00:00 UTC 5h left            Mon 2026-09-01 06:00:00 UTC 18h ago      logrotate.timer              logrotate.service',
    '',
    '2 timers listed.'
  ].join('\n')

  it('does not report the PASSED column as the last run', () => {
    // The bug: lastRun came back as "18h ago" — a plausible string in the
    // wrong field, which is the worst kind of wrong.
    const r = parseSystemdTimers(WIDE)
    const apt = r.entries.find((e) => e.origin === 'apt-daily.timer')
    expect(apt?.lastRun).toBe('Mon 2026-09-01 06:00:00 UTC')
    expect(apt?.nextRun).toBe('Wed 2026-09-09 06:00:00 UTC')
  })

  it('reads the neighbouring rows the same way', () => {
    const r = parseSystemdTimers(WIDE)
    expect(r.entries.map((e) => e.origin)).toEqual(['apt-daily.timer', 'logrotate.timer'])
    expect(r.entries[1].lastRun).toBe('Mon 2026-09-01 06:00:00 UTC')
    expect(r.entries[1].command).toBe('logrotate.service')
  })

  it('reads a --all listing where systemd 250+ writes "-" for no next elapse', () => {
    // `--all` exists to show exactly these, and they are the timers most worth
    // seeing: loaded, inactive, never going to fire.
    const ALL = [
      'NEXT                        LEFT     LAST                        PASSED   UNIT                          ACTIVATES',
      '-                           -        Mon 2026-09-01 10:00:00 UTC 8h ago   systemd-tmpfiles-clean.timer  systemd-tmpfiles-clean.service',
      '-                           -        -                           -        fstrim.timer                  fstrim.service',
      '',
      '2 timers listed.'
    ].join('\n')
    const r = parseSystemdTimers(ALL)
    expect(r.entries).toHaveLength(2)
    expect(r.entries[0].nextRun).toBeUndefined()
    expect(r.entries[0].lastRun).toBe('Mon 2026-09-01 10:00:00 UTC')
    expect(r.entries[1].nextRun).toBeUndefined()
    expect(r.entries[1].lastRun).toBeUndefined()
  })

  it('reads a timer that has never run', () => {
    const line =
      'Tue 2026-09-02 00:00:00 UTC 10h left n/a                         n/a      certbot.timer certbot.service'
    const r = parseSystemdTimers(line)
    expect(r.entries[0].nextRun).toBe('Tue 2026-09-02 00:00:00 UTC')
    expect(r.entries[0].lastRun).toBeUndefined()
  })

  it('ignores the "Pass --all" footer systemd prints without it', () => {
    const out = [
      'NEXT LEFT LAST PASSED UNIT ACTIVATES',
      'Tue 2026-09-02 06:00:00 UTC 5h left Mon 2026-09-01 06:00:00 UTC 18h ago logrotate.timer logrotate.service',
      '',
      '1 timers listed.',
      'Pass --all to see loaded but inactive timers, too.'
    ].join('\n')
    const r = parseSystemdTimers(out)
    expect(r.entries).toHaveLength(1)
    expect(r.unparsed).toEqual([])
  })

  it('keeps a non-UTC timezone with the timestamp', () => {
    const line = 'Tue 2026-09-02 08:00:00 CEST 5h left Mon 2026-09-01 08:00:00 CEST 18h ago x.timer x.service'
    expect(parseSystemdTimers(line).entries[0].nextRun).toBe('Tue 2026-09-02 08:00:00 CEST')
  })
})

describe('output that did not come back as clean LF', () => {
  it('finds every section when the transport hands back CRLF', () => {
    // Missing the markers is not a degraded read, it is an empty one: a host
    // with nothing scheduled and a host we failed to parse look identical from
    // the panel, and the second is the one worth knowing about.
    const out = [
      '===SHELLPILOT-USER===',
      '0 2 * * * /home/me/backup.sh',
      '===SHELLPILOT-SYSTEM===',
      '17 * * * * root cd / && run-parts --report /etc/cron.hourly',
      '===SHELLPILOT-CROND===',
      '#FILE:/etc/cron.d/certbot',
      '0 */12 * * * root certbot -q renew',
      '===SHELLPILOT-TIMERS===',
      'NEXT LEFT LAST PASSED UNIT ACTIVATES',
      'Tue 2026-09-02 06:00:00 UTC 5h left Mon 2026-09-01 06:00:00 UTC 18h ago logrotate.timer logrotate.service'
    ].join('\r\n')
    const r = parseCronCollection(out)
    expect(r.entries.map((e) => e.kind).sort()).toEqual([
      'cron.d',
      'system-crontab',
      'systemd-timer',
      'user-crontab'
    ])
  })

  it('does not leave a carriage return inside a command', () => {
    const r = parseCrontab('0 2 * * * /home/me/backup.sh --all\r\n', 'f', 'user-crontab', false)
    expect(r.entries[0].command).toBe('/home/me/backup.sh --all')
  })
})

describe('the cron.d collector, on files that do not end in a newline', () => {
  it('separates the files even so', () => {
    // Plenty of packaged /etc/cron.d files have no final newline. `cat a`
    // followed by the marker for b then glues them: a's last job grows a
    // `#FILE:` tail on its command, and every job in b is filed under a — where
    // nobody looking at b will ever find it.
    //
    // The collector now prints its own newline after each file, so this is what
    // the parser receives.
    expect(CRON_COLLECT_COMMAND).toMatch(/cat "\$f"; printf "\\n"/)
  })

  it('files each entry under the file it came from', () => {
    const out = [
      '===SHELLPILOT-CROND===',
      '#FILE:/etc/cron.d/a',
      '0 1 * * * root /a',
      '',
      '#FILE:/etc/cron.d/b',
      '0 2 * * * root /b',
      ''
    ].join('\n')
    const r = parseCronCollection(out)
    expect(r.entries.map((e) => [e.origin, e.command])).toEqual([
      ['/etc/cron.d/a', '/a'],
      ['/etc/cron.d/b', '/b']
    ])
  })
})

describe('describing lists, which real crontabs are full of', () => {
  it('names the unit once for a list of values', () => {
    expect(describeSchedule('0,15,30,45 * * * *')).toBe('minute 0, 15, 30, 45')
    expect(describeSchedule('0 3 * * 1,3,5')).toBe('minute 0, hour 3, on Monday, Wednesday, Friday')
    expect(describeSchedule('0 3 * jan,jul *')).toBe('minute 0, hour 3, month January, July')
  })

  it('describes a step inside a range without pretending it is a plain range', () => {
    // /etc/cron.d/sysstat's schedule. "minute 5 to 55" would be wrong: it runs
    // every ten minutes in that window, not continuously through it.
    expect(describeSchedule('5-55/10 * * * *')).toBe('every 10 minutes from 5 to 55')
  })

  it('declines N/S, whose end depends on which field it is in', () => {
    expect(describeSchedule('10/15 * * * *')).toBeNull()
  })

  it('reads day-of-week 7 as Sunday, as cron does', () => {
    expect(describeSchedule('47 6 * * 7')).toBe('at 06:47 every Sunday')
  })
})
