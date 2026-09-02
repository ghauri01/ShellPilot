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
  type BroadcastHostResult
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
  it('just runs an ordinary command on a single host', () => {
    // Nagging on the safe case is exactly how people learn to click through
    // the dangerous one.
    expect(confirmationFor('ordinary', 1)).toEqual({ kind: 'none' })
  })

  it('asks to confirm as soon as it is more than one host', () => {
    expect(confirmationFor('ordinary', 2).kind).toBe('confirm')
  })

  it('requires typing once the host count is large', () => {
    expect(confirmationFor('ordinary', TYPE_ABOVE_HOSTS + 1).kind).toBe('type-to-confirm')
  })

  it('requires typing for a destructive command even on one host', () => {
    // The command is the danger here, not the count.
    expect(confirmationFor('destructive', 1)).toEqual({ kind: 'type-to-confirm', phrase: 'RUN' })
  })

  it('asks to confirm an elevated command on a couple of hosts', () => {
    expect(confirmationFor('elevated', 2).kind).toBe('confirm')
  })

  it('never returns "none" for anything but an ordinary single host', () => {
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
      'chmod 644 /srv/foo-baR'
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

  it('does not count a host that has not finished as an answer', () => {
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
