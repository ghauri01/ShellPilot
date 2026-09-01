import { describe, it, expect } from 'vitest'
import { describeServices, describeListeners } from '../src/main/services/mcpServer'
import type { ServiceUnit, PortListener } from '../src/shared/ssh'

// The Fleet Monitor collects failed units and listening ports on every sample.
// get_server_metrics used to discard both, so an agent asked "which units failed
// on that host" reached for `execute_command "systemctl --failed"` instead —
// escalating from the serverMetrics capability to terminal, opening a shell that
// was not needed, and re-deriving something already parsed a moment earlier.
//
// The property worth protecting here is the null-vs-empty distinction: telling
// an agent "nothing is failing" when the truth is "nobody could look" is how it
// reports a host healthy that nobody has actually checked.

const unit = (name: string, active: string, sub: string, description = ''): ServiceUnit => ({
  name,
  active,
  sub,
  description
})

const listener = (port: number, extra: Partial<PortListener> = {}): PortListener => ({
  proto: 'tcp',
  address: '*',
  port,
  ...extra
})

describe('failed units', () => {
  it('says unknown when systemd is not on the host', () => {
    // null means the probe could not run at all — a container without systemd.
    const out = describeServices(null)
    expect(out).toMatch(/unknown/i)
    expect(out).toMatch(/not available/i)
    // Must not read as a clean bill of health.
    expect(out).not.toMatch(/\bnone\b/i)
  })

  it('says none when systemd ran and found nothing failing', () => {
    const out = describeServices([unit('ssh.service', 'active', 'running')])
    expect(out).toMatch(/none/i)
    expect(out).not.toMatch(/unknown/i)
  })

  it('names each failed unit with its description', () => {
    const out = describeServices([
      unit('ssh.service', 'active', 'running'),
      unit('postfix@-.service', 'failed', 'failed', 'Postfix Mail Transport Agent (instance -)'),
      unit('uwsgi.service', 'failed', 'failed', 'uWSGI Service')
    ])
    expect(out).toContain('postfix@-.service')
    expect(out).toContain('Postfix Mail Transport Agent (instance -)')
    expect(out).toContain('uwsgi.service')
    expect(out).toContain('2 of 3')
  })

  it('catches a unit failed in sub state only', () => {
    // `active=active, sub=failed` happens; counting only active==='failed'
    // would report the host clean.
    const out = describeServices([unit('worker.service', 'active', 'failed', 'Worker')])
    expect(out).toContain('worker.service')
    expect(out).not.toMatch(/: none/i)
  })
})

describe('listening ports', () => {
  it('says unknown when neither ss nor netstat exists', () => {
    const out = describeListeners(null, null)
    expect(out).toMatch(/unknown/i)
    expect(out).not.toMatch(/\bnone\b/i)
  })

  it('says none when the probe ran and found nothing', () => {
    expect(describeListeners([], 'ss')).toMatch(/none/i)
  })

  it('reports the probe that produced the list', () => {
    // Which probe ran explains why the owner column may be empty.
    expect(describeListeners([listener(22, { process: 'sshd', pid: 900 })], 'ss')).toContain('via ss')
    expect(describeListeners([listener(22)], 'netstat')).toContain('via netstat')
  })

  it('names the owning process and pid when the probe could see them', () => {
    const out = describeListeners([listener(5432, { process: 'postgres', pid: 1234 })], 'ss')
    expect(out).toContain('tcp/5432')
    expect(out).toContain('postgres')
    expect(out).toContain('1234')
  })

  it('says the owner is hidden rather than leaving a blank', () => {
    // An unprivileged probe sees the socket but not whose it is. A blank there
    // reads as "no process", which is a different and wrong claim.
    const out = describeListeners([listener(9100)], 'netstat')
    expect(out).toMatch(/not visible/i)
  })

  it('caps a long list and says how many it dropped', () => {
    // Never truncate silently: an agent that cannot see a port must not
    // conclude the port is closed.
    const many = Array.from({ length: 75 }, (_, i) => listener(4000 + i))
    const out = describeListeners(many, 'ss')
    expect(out).toContain('(75, via ss)')
    expect(out).toMatch(/35 more not shown/)
    expect(out).toMatch(/capped at 40/)
  })

  it('does not mention a cap when everything fits', () => {
    const out = describeListeners([listener(80), listener(443)], 'ss')
    expect(out).not.toMatch(/not shown|capped/)
  })
})
