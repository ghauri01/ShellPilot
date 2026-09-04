import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  assessCommand,
  classifyBroadcastResult,
  confirmationFor,
  planBroadcast,
  summariseBroadcast,
  TYPE_ABOVE_HOSTS,
  approvalFor,
  verifyApproval,
  type BroadcastHostResult,
  type CommandApproval
} from '../src/shared/broadcast'

// The approval model, settled before the executor was written.
//
// Broadcast is not dangerous because it runs a command — the user can already
// run anything on any one host. It is dangerous because a mistake is
// simultaneous. `rm -rf /var/log` on one box is a bad evening; on fifteen it is
// the evening plus every log you would have used to understand it.
//
// So both inputs count and neither dominates: the command can be the danger, or
// the host count can be.

const targets = (n: number): { serverId: string; serverName: string }[] =>
  Array.from({ length: n }, (_, i) => ({ serverId: `s${i}`, serverName: `host-${i}` }))

describe('how dangerous a command reads', () => {
  it('treats an ordinary command as ordinary', () => {
    expect(assessCommand('uptime').risk).toBe('ordinary')
    expect(assessCommand('systemctl status nginx').risk).toBe('ordinary')
  })

  it('flags recursive delete', () => {
    const a = assessCommand('rm -rf /var/log/old')
    expect(a.risk).toBe('destructive')
    expect(a.reasons.join(' ')).toMatch(/deletes files/)
  })

  it('flags stopping or restarting the machine', () => {
    expect(assessCommand('shutdown -h now').risk).toBe('destructive')
    expect(assessCommand('reboot').risk).toBe('destructive')
  })

  it('flags writing to a device', () => {
    expect(assessCommand('dd if=/dev/zero of=/dev/sda').risk).toBe('destructive')
    expect(assessCommand('mkfs.ext4 /dev/sdb1').risk).toBe('destructive')
  })

  it('flags stopping a service as destructive but restarting as elevated', () => {
    // Different blast radius: a stopped service stays down.
    expect(assessCommand('systemctl stop nginx').risk).toBe('destructive')
    expect(assessCommand('systemctl restart nginx').risk).toBe('elevated')
  })

  it('treats sudo as elevated, not destructive', () => {
    // Running as root is not itself destruction, and calling it that would
    // make the strongest warning routine.
    expect(assessCommand('sudo systemctl status nginx').risk).toBe('elevated')
  })

  it('flags package changes', () => {
    expect(assessCommand('apt-get install nginx').risk).toBe('elevated')
  })

  it('explains itself, so the dialog can say why', () => {
    expect(assessCommand('rm -rf /tmp/x').reasons.length).toBeGreaterThan(0)
  })

  it('still catches a dangerous verb after a pipe or semicolon', () => {
    // Anchoring to command position must not become "anchoring to position
    // zero" — chained commands are exactly how these get typed.
    expect(assessCommand('cd /tmp && rm -rf build').risk).toBe('destructive')
    expect(assessCommand('echo hi; reboot').risk).toBe('destructive')
    expect(assessCommand('systemctl stop nginx | tee log').risk).toBe('destructive')
  })

  it('catches it behind sudo and behind an env prefix', () => {
    expect(assessCommand('sudo reboot').risk).toBe('destructive')
    expect(assessCommand('DEBIAN_FRONTEND=noninteractive sudo shutdown -h now').risk).toBe('destructive')
  })

  it('does not flag a harmless command that merely contains a scary word', () => {
    // "the rm in `charm`" — a classifier that cries wolf teaches click-through.
    expect(assessCommand('echo charming').risk).toBe('ordinary')
    expect(assessCommand('grep reboot /var/log/syslog').risk).toBe('ordinary')
  })
})

describe('what the user has to do before it runs', () => {
  it('just runs an ordinary command on a single server', () => {
    // Nagging on the safe case is exactly how people learn to click through
    // the dangerous one.
    expect(confirmationFor('ordinary', 1)).toEqual({ kind: 'none' })
  })

  it('asks to confirm as soon as it is more than one server', () => {
    expect(confirmationFor('ordinary', 2).kind).toBe('confirm')
  })

  it('requires typing once the server count is large', () => {
    expect(confirmationFor('ordinary', TYPE_ABOVE_HOSTS + 1).kind).toBe('type-to-confirm')
  })

  it('requires typing for a destructive command even on one server', () => {
    // The command is the danger here, not the count.
    expect(confirmationFor('destructive', 1)).toEqual({ kind: 'type-to-confirm', phrase: 'RUN' })
  })

  it('asks to confirm an elevated command on a couple of servers', () => {
    expect(confirmationFor('elevated', 2).kind).toBe('confirm')
  })

  it('never returns "none" for anything but an ordinary single server', () => {
    // The rule that matters most: nothing is safe by omission.
    for (const risk of ['ordinary', 'elevated', 'destructive'] as const) {
      for (const n of [0, 1, 2, 5, 6, 20]) {
        const c = confirmationFor(risk, n)
        if (c.kind === 'none') expect([risk, n]).toEqual(['ordinary', 1])
      }
    }
  })
})

describe('the plan handed to the dialog', () => {
  it('carries the command, the targets and the confirmation together', () => {
    const p = planBroadcast('rm -rf /tmp/x', targets(3))
    expect(p.risk).toBe('destructive')
    expect(p.targets).toHaveLength(3)
    expect(p.confirmation.kind).toBe('type-to-confirm')
    expect(p.reasons.length).toBeGreaterThan(0)
  })

  it('still asks for confirmation when nothing is selected', () => {
    // A zero-target run is a mistake worth catching rather than a no-op to
    // wave through.
    expect(planBroadcast('uptime', []).confirmation.kind).toBe('confirm')
  })
})

// Real commands, typed the way people actually type them. Each of these read as
// `ordinary` — no confirmation at all on a single host — because the pattern
// matched one spelling of the command and not the one in front of it.
describe('spellings the classifier used to miss', () => {
  it('flags a recursive delete written with long options', () => {
    expect(assessCommand('rm --recursive --force /var/log/old').risk).toBe('destructive')
  })

  it('flags a bulk delete reached through find or xargs', () => {
    // Neither puts `rm` at a command start, which is where the anchored rule
    // looks — and these are how a bulk delete is actually written.
    expect(assessCommand("find /srv -name '*.bak' -exec rm -rf {} +").risk).toBe('destructive')
    expect(assessCommand('find /srv -name "*.bak" | xargs rm -f').risk).toBe('destructive')
    expect(assessCommand("find /var/log -name '*.gz' -delete").risk).toBe('destructive')
  })

  it("flags systemd's own spelling of stopping the machine", () => {
    // `systemctl` sits at the command start, so the reboot rule never saw it.
    expect(assessCommand('systemctl poweroff').risk).toBe('destructive')
    expect(assessCommand('sudo systemctl reboot').risk).toBe('destructive')
  })

  it('flags a firewall flush written with the short flag', () => {
    // `\b-F\b` never matched ` -F`: there is no word boundary between a space
    // and a dash, so the most common spelling was the unguarded one.
    expect(assessCommand('iptables -F').risk).toBe('destructive')
    expect(assessCommand('sudo iptables -F INPUT').risk).toBe('destructive')
  })

  it('flags a recursive chmod or chown whose flag comes after the mode', () => {
    expect(assessCommand('chmod 777 -R /srv').risk).toBe('destructive')
    expect(assessCommand('chown --recursive deploy /srv').risk).toBe('destructive')
    expect(assessCommand('chmod -Rv 755 /srv').risk).toBe('destructive')
  })

  it('flags SIGKILL sent with pkill or -s', () => {
    expect(assessCommand('pkill -9 nginx').risk).toBe('destructive')
    expect(assessCommand('kill -s KILL 4211').risk).toBe('destructive')
  })

  it('flags wiping the crontab, which is one key from editing it', () => {
    expect(assessCommand('crontab -r').risk).toBe('destructive')
    expect(assessCommand('crontab -l').risk).toBe('ordinary')
  })

  it('flags stopping a service the SysV way', () => {
    expect(assessCommand('service nginx stop').risk).toBe('destructive')
    expect(assessCommand('service nginx restart').risk).toBe('elevated')
  })

  it('flags destroying a volume or a pool', () => {
    expect(assessCommand('lvremove /dev/vg0/data').risk).toBe('destructive')
    expect(assessCommand('zfs destroy tank/backups').risk).toBe('destructive')
  })

  it('sees root reached through a pipe, not only at the start of the line', () => {
    expect(assessCommand('curl -sL https://example.test/i.sh | sudo bash').risk).toBe('elevated')
  })

  it("sees docker's noun-verb spellings", () => {
    // `docker system prune` and `docker volume rm` are how these are written
    // now; the verb-only rule matched neither.
    expect(assessCommand('docker system prune -af --volumes').risk).toBe('elevated')
    expect(assessCommand('docker volume rm pgdata').risk).toBe('elevated')
    expect(assessCommand('docker compose down').risk).toBe('elevated')
  })

  it('flags package removals spelled purge or autoremove', () => {
    expect(assessCommand('apt-get purge nginx').risk).toBe('elevated')
    expect(assessCommand('apt autoremove').risk).toBe('elevated')
  })

  // -----------------------------------------------------------------------
  // sudo WITH FLAGS, which is the spelling this codebase itself uses.
  //
  // The prefix admitted `sudo ` and `doas ` and nothing else — no options. So
  // `sudo -n reboot` fell out of every destructive rule and landed on the
  // `runs as root` rule instead, which is `elevated`: one confirm click on one
  // host, where a bare `reboot` demands a typed phrase. Strictly weaker
  // confirmation for strictly more privilege.
  //
  // And `-n` is not an exotic spelling. It is the ONLY escalation that cannot
  // prompt for a password, which is why SUDO_PROBE in src/shared/docker.ts,
  // the docker sudo failover and src/shared/cron.ts all use it. The spelling
  // the app prefers was the spelling the guard missed.
  // -----------------------------------------------------------------------
  it('flags a machine-stopping verb behind sudo with flags', () => {
    for (const c of [
      'sudo -n reboot',
      'sudo --non-interactive reboot',
      'sudo -u root reboot',
      'sudo -H shutdown -h now',
      'doas -n reboot',
      // Bundled short flags, an attached value, a long flag with `=`, an
      // end-of-options `--`, and a quoted value with a space in it.
      'sudo -nH poweroff',
      'sudo -uroot reboot',
      'sudo --user=root halt',
      'sudo -- reboot',
      "sudo -p 'password for %p: ' reboot",
      // The env prefix still has to work in front of the flags.
      'DEBIAN_FRONTEND=noninteractive sudo -n shutdown -h now',
      // And it still has to work after a chain, not only at position zero.
      'apt-get -y upgrade && sudo -n reboot'
    ]) {
      expect(assessCommand(c).risk, c).toBe('destructive')
    }
  })

  it('flags the rest of the destructive set behind a flagged sudo, not just reboot', () => {
    // Every hand-rolled rule carried its own copy of the flagless prefix, so
    // the hole was the whole set. `sudo -n rm -rf /var/log` taking a single
    // confirm click on one host is a worse hole than the reboot one.
    for (const c of [
      'sudo -n rm -rf /var/log',
      'sudo -u root rm --recursive --force /srv/old',
      'sudo -n systemctl stop nginx',
      'sudo -n systemctl reboot',
      'sudo -n service nginx stop',
      'sudo -n iptables -F',
      'sudo -n crontab -r',
      'sudo -n dd if=/dev/zero of=/dev/sda',
      'sudo -n mkfs.ext4 /dev/sdb1',
      'sudo -n chmod -R 777 /srv',
      'sudo -u root chown --recursive deploy /srv',
      'sudo -n pkill -9 nginx',
      'sudo -n userdel deploy',
      'sudo -n lvremove /dev/vg0/data',
      'sudo -n zfs destroy tank/backups',
      'sudo -n truncate -s 0 /var/log/syslog',
      "sudo -n find /var/log -name '*.gz' -delete",
      // The two rules that read a sudo which is NOT at a command start.
      "find /srv -name '*.bak' -exec sudo -n rm -rf {} +",
      'find /srv -type f | xargs sudo -n rm -f'
    ]) {
      expect(assessCommand(c).risk, c).toBe('destructive')
    }
  })

  it('gives the elevated rules the same reading, so the reason is still said', () => {
    // These already read `elevated` before the fix — but only via the blanket
    // `runs as root` rule, so the dialog said "runs as root" and never said
    // WHAT it was about to do. The reason is the half of the model the user
    // actually reads.
    const why = (c: string): string[] => assessCommand(c).reasons
    expect(why('sudo -n apt-get install nginx')).toContain('changes installed packages')
    expect(why('sudo -n systemctl restart nginx')).toContain('restarts a service')
    expect(why('sudo -n service nginx reload')).toContain('restarts a service')
    expect(why('sudo -u root docker system prune -af')).toContain('removes or stops containers')
  })
})

describe('and still not crying wolf', () => {
  it('leaves everyday read-only commands alone', () => {
    // The half of the model that matters most: a guard that fires on `df -h`
    // is a guard people learn to click through, and it is then not there for
    // the one that meant it.
    for (const c of [
      'uptime',
      'df -h',
      'ps aux | grep nginx',
      'ls -la /var/log',
      'journalctl -u nginx -n 50',
      'systemctl status nginx',
      'grep -r timeout /etc/nginx',
      "find /var/log -name '*.log' -mtime +7",
      'docker ps -a',
      'apt list --installed',
      'tail -f /var/log/syslog',
      'cat /etc/hostname',
      'echo charming',
      'grep reboot /var/log/syslog',
      // A filename that happens to end in a capital R is not a recursive flag.
      'chmod 644 /srv/foo-baR',
      // The word `sudo` in an argument is not a command running as root, and
      // `sudoers` is not `sudo` — there is no word boundary inside it.
      'echo sudo reboot',
      'ls /etc/sudoers.d',
      'cat /etc/sudoers.d/90-reboot',
      'grep -r sudo /etc/pam.d'
    ]) {
      expect(assessCommand(c).risk, c).toBe('ordinary')
    }
  })

  // -----------------------------------------------------------------------
  // The half of the sudo-flag fix that matters more than the other half.
  //
  // Widening the prefix to admit option arguments is one careless character
  // away from admitting the COMMAND as an option argument — and then
  // `sudo -u deploy grep reboot /var/log/syslog` reads as "stops the machine".
  // A guard that fires on a read-only grep is a guard people learn to click
  // through, and it is then not there for the `reboot` that meant it.
  //
  // These are all `elevated`, because they genuinely do run as root. What none
  // of them may be is `destructive`: the destructive verb in each one is an
  // ARGUMENT, not a command.
  // -----------------------------------------------------------------------
  it('does not read a verb in a flagged sudo’s arguments as a command', () => {
    for (const c of [
      'sudo -u deploy grep reboot /var/log/syslog',
      'sudo -n cat reboot.txt',
      'sudo cat /var/log/reboot.log',
      'sudo -u root tail -n 50 /var/log/shutdown.log',
      'sudo -n grep -r reboot /etc',
      'sudo -n test -f /run/reboot-required',
      'sudo -n stat /sbin/reboot',
      'sudo -n ls /etc/systemd/system/reboot.target.wants',
      'sudo -n journalctl -u nginx | grep -i shutdown',
      'sudo -n systemctl status reboot-guard',
      // `-u deploy` must consume `deploy` as the flag's value and then STOP.
      // A prefix that swallowed any token after any flag would read the `rm`
      // here as a command.
      'sudo -u deploy ls -la /srv/rm-backups',
      'sudo -n head -n 100 /var/log/mkfs.log',
      'sudo -n diff /etc/crontab /etc/crontab.bak'
    ]) {
      const a = assessCommand(c)
      expect(a.risk, c).toBe('elevated')
      expect(a.reasons, c).toEqual(['runs as root'])
    }
  })

  it('cannot be made to hang by a long line of flags', () => {
    // Not a theoretical hardening. The first version of the widened prefix
    // spelled the value-taking flags inline, which made `sudo -u -u -u …`
    // parse exponentially many ways over the same characters — twenty flags
    // did not finish. `assessCommand` runs on every keystroke in the broadcast
    // panel, so an input that wedges it wedges the window.
    for (const line of [
      `sudo ${'-u '.repeat(400)}x`,
      `sudo ${'-u a '.repeat(400)}x`,
      `sudo ${'-uuuu a '.repeat(400)}x`,
      `sudo ${'--user root '.repeat(400)}x`,
      `sudo ${'-nHE '.repeat(400)}x`
    ]) {
      const started = Date.now()
      expect(assessCommand(line).risk).toBe('elevated')
      expect(Date.now() - started, line.slice(0, 40)).toBeLessThan(250)
    }
  })

  it('still refuses to widen the anchor itself', () => {
    // The option loop hangs off `sudo`/`doas` and nothing else. A bare flag,
    // or a flag behind some other command, is not a licence to go looking for
    // a verb further down the line.
    for (const c of [
      'ssh -n web01 uptime',
      'nice -n 10 tar cf backup.tar /srv',
      'timeout -k 5 30 curl https://example.test/reboot',
      'ansible -m shell -a uptime web'
    ]) {
      expect(assessCommand(c).risk, c).toBe('ordinary')
    }
  })
})

// ---------------------------------------------------------------------------
// Fifteen hosts, made scannable.
//
// The per-host list is the record and stays complete — merged output loses
// which machine said what, which is the only question anyone asks afterwards.
// But a list is not an answer, and at fifteen rows nobody reads it top to
// bottom. The summary is the line that says whether they need to.
// ---------------------------------------------------------------------------

const host = (over: Partial<BroadcastHostResult>): BroadcastHostResult => ({
  serverId: over.serverName ?? 'id',
  serverName: 'h',
  state: 'ok',
  ...over
})

describe('summarising a partial failure', () => {
  it('counts every category, and they add up', () => {
    const rows: BroadcastHostResult[] = [
      host({ exitCode: 0, outcome: 'ok' }),
      host({ exitCode: 0, outcome: 'ok' }),
      host({ exitCode: 1, outcome: 'nonzero' }),
      host({ exitCode: 127, outcome: 'missing-command' }),
      host({ exitCode: 127, outcome: 'missing-command' }),
      host({ state: 'failed', outcome: 'timeout', error: 'Command timed out after 60000ms' }),
      host({ state: 'skipped', outcome: 'cancelled' }),
      host({ state: 'running' })
    ]
    const s = summariseBroadcast(rows)
    expect(s.total).toBe(8)
    expect(s.running).toBe(1)
    expect(s.counts).toMatchObject({
      ok: 2,
      nonzero: 1,
      'missing-command': 2,
      timeout: 1,
      cancelled: 1,
      'permission-denied': 0,
      unreachable: 0
    })
    const finished = Object.values(s.counts).reduce((a, b) => a + b, 0)
    expect(finished + s.running).toBe(s.total)
  })

  it('does not count a server that has not finished as an answer', () => {
    // A category for "we do not know yet" would be counted in the summary as
    // though it were a result.
    expect(classifyBroadcastResult(host({ state: 'pending' }))).toBeNull()
    expect(classifyBroadcastResult(host({ state: 'running' }))).toBeNull()
    expect(summariseBroadcast([host({ state: 'pending' })]).counts.ok).toBe(0)
  })

  it('falls back to classifying a result that carries no outcome', () => {
    // The runner sets it, but a result that has been through an older main
    // process has not got one, and a summary that silently dropped those rows
    // would under-report the fan-out.
    const s = summariseBroadcast([host({ exitCode: 127, stderr: 'bash: docker: command not found' })])
    expect(s.counts['missing-command']).toBe(1)
  })
})

describe('the decision not to escalate on a fan-out', () => {
  it('is written down where the next person will look for it', () => {
    // Docker retries a refused read as root and this does not, which is a
    // difference somebody will want to undo. The reasoning has to be next to
    // the approval model it would otherwise invert, not in a commit message.
    const src = readFileSync(resolve(__dirname, '../src/shared/broadcast.ts'), 'utf8')
    expect(src).toMatch(/Why there is no sudo retry here/)
  })

  it('leaves the escalation to the classifier that already gates it', () => {
    // The alternative to retrying is not doing nothing: the user types `sudo`
    // themselves, and that goes through the model rather than around it.
    expect(assessCommand('sudo systemctl restart nginx').risk).toBe('elevated')
    expect(confirmationFor('elevated', TYPE_ABOVE_HOSTS + 1)).toEqual({
      kind: 'type-to-confirm',
      phrase: 'RUN'
    })
  })
})

// ===========================================================================
// B3: the plan stops being a value in a useMemo and becomes a record
// ===========================================================================
//
// Before B3, `BroadcastPanel` computed a plan, used it to gate a dialog, and
// threw it away. `broadcast:run` took a run id, a command and a target list,
// and main had no idea whether anybody had agreed to any of it. Everything
// below is about closing that: one record type, one verifier, and both surfaces
// — broadcast and job — calling them rather than growing a second model each.

describe('the approval record, shared with the job engine', () => {
  const two = targets(2)
  const mint = (command: string, t = two, phrase: string | null = null): CommandApproval =>
    approvalFor({
      surface: 'broadcast',
      commands: [command],
      targets: t,
      plan: planBroadcast(command, t),
      phrase,
      confirmedAt: 1_700_000_000_000
    })

  const check = (a: unknown, command: string, t = two): ReturnType<typeof verifyApproval> =>
    verifyApproval(a, { commands: [command], targets: t }, planBroadcast(command, t))

  it('accepts a record that still matches the run it came with', () => {
    expect(check(mint('uptime'), 'uptime')).toEqual({ ok: true })
  })

  it('refuses a run with no record at all', () => {
    const v = check(undefined, 'uptime')
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.reason).toMatch(/never written down/i)
  })

  it('refuses a command edited under the record', () => {
    const v = check(mint('uptime'), 'rm -rf /var/log')
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.reason).toMatch(/approved as `uptime` and is now `rm -rf \/var\/log`/)
  })

  it('refuses a server added after the record was minted', () => {
    const v = check(mint('uptime', targets(2)), 'uptime', targets(3))
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.reason).toMatch(/host-2 was not in the target list that was confirmed/)
  })

  it('refuses when the record was graded by a laxer classifier', () => {
    // The disagreement that comparing a request to itself can never see: same
    // command, same hosts, a risk grade that has since tightened.
    const stale = { ...mint('rm -rf /srv'), risk: 'ordinary' as const, confirmation: { kind: 'none' as const }, phrase: null }
    expect(planBroadcast('rm -rf /srv', two).risk, 'or this proves nothing').toBe('destructive')
    const v = check(stale, 'rm -rf /srv')
    expect(v.ok).toBe(false)
    expect(v.ok === false && v.reason).toMatch(/approved as `ordinary` and now classifies as `destructive`/)
  })

  it('demands the phrase the model asked for, not merely that the model asked', () => {
    const command = 'rm -rf /srv'
    expect(planBroadcast(command, two).confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'RUN' })
    // The dialog demanded RUN and nobody typed it.
    const unsigned = check(mint(command, two, null), command)
    expect(unsigned.ok).toBe(false)
    expect(unsigned.ok === false && unsigned.reason).toMatch(/no typed phrase at all/)
    expect(check(mint(command, two, 'RUN'), command)).toEqual({ ok: true })
  })
})

describe('where the broadcast approval is enforced', () => {
  // Source assertions, in the style of the closure walk in
  // tests/jobsNotExposed.test.ts: the handler lives in main/index.ts, which
  // cannot be constructed in a unit test, and the property being asserted is
  // that the wiring exists at all.
  const main = readFileSync(resolve(__dirname, '../src/main/index.ts'), 'utf8')
  const panel = readFileSync(
    resolve(__dirname, '../src/renderer/src/components/monitor/BroadcastPanel.tsx'),
    'utf8'
  )

  it('main re-derives the plan and refuses before the runner is reached', () => {
    const handler = main.slice(main.indexOf("ipcMain.handle('broadcast:run'"))
    const body = handler.slice(0, handler.indexOf('\n})'))
    // EACH INDEX IS PROVED TO EXIST BEFORE IT IS ORDERED. `indexOf` returns -1
    // for a string that is not there, and -1 is less than every real index — so
    // an ordering assertion on its own passes most loudly against the very bug
    // it was written to catch: a handler with the throw deleted. That failure
    // mode is not hypothetical here, it is what the first version of this test
    // did when the refusal was mutated out.
    const at = (needle: string): number => {
      const i = body.indexOf(needle)
      expect(i, `the broadcast:run handler no longer contains ${needle}`).toBeGreaterThanOrEqual(0)
      return i
    }
    expect(body, 'main must re-derive rather than trust the request').toContain('verifyApproval(')
    const run = at('broadcast.run(req)')
    expect(at('verifyApproval(')).toBeLessThan(run)
    expect(at('planBroadcast(')).toBeLessThan(run)
    // The refusal has to be a THROW, before the runner. A logged disagreement
    // that still runs the command is not a refusal.
    expect(at('throw new Error')).toBeLessThan(run)
    expect(at('!verdict.ok')).toBeLessThan(run)
  })

  it('main writes the decision to the job approval log, granted or refused', () => {
    const handler = main.slice(main.indexOf("ipcMain.handle('broadcast:run'"))
    const body = handler.slice(0, handler.indexOf('\n})'))
    expect(body).toContain("event: 'refused'")
    expect(body).toContain("event: 'granted'")
    // And the writer is the job approval log, NOT the AI audit log — the
    // argument is in approvalLog.ts and in docs/AI-SECURITY.md.
    expect(body).toContain('recordJobApproval(')
    expect(body).not.toContain('recordAudit(')
  })

  it('the panel mints the record from the plan it showed and the phrase that was typed', () => {
    expect(panel).toContain('approvalFor({')
    expect(panel).toMatch(/surface: 'broadcast'/)
    // Minted from the plan and the phrase state, not re-derived at send time:
    // what is recorded has to be what was on screen.
    expect(panel).toMatch(/phrase: plan\.confirmation\.kind === 'type-to-confirm' \? phrase\.trim\(\) : null/)
    expect(panel).toMatch(/^\s+approval,$/m)
  })

  it('does not grow a second approval model beside the shared one', () => {
    // The whole point of B3. If a future change re-implements the check in
    // main rather than calling the shared one, this is where it shows up.
    const shared = readFileSync(resolve(__dirname, '../src/shared/broadcast.ts'), 'utf8')
    expect(shared.match(/export function verifyApproval/g)).toHaveLength(1)
    expect(main).not.toMatch(/function verifyApproval/)
    const jobs = readFileSync(resolve(__dirname, '../src/shared/jobs.ts'), 'utf8')
    // jobs.ts adapts it, it does not restate it.
    expect(jobs).toContain('return verifyApproval(')
    expect(jobs).not.toMatch(/export function verifyApproval\s*\(/)
  })
})
