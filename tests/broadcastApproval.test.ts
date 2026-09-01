import { describe, it, expect } from 'vitest'
import {
  assessCommand,
  confirmationFor,
  planBroadcast,
  TYPE_ABOVE_HOSTS
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
