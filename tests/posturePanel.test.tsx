// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { PosturePanel } from '../src/renderer/src/components/monitor/PosturePanel'
import { POSTURE_STATUS_MARKER, parsePosture } from '../src/shared/posture'
import { parseHostFacts } from '../src/shared/hostFacts'
import type { HostPosture } from '../src/shared/posture'
import type { HostFacts } from '../src/shared/hostFacts'
import type { Server } from '../src/renderer/src/types'

// The posture table — roadmap item 24, renderer half.
//
// Every test here is about ONE thing: a cell whose check could not run must
// never be readable as a cell whose check passed. That is not a presentation
// preference. src/shared/posture.ts goes to real trouble to keep `denied`,
// `absent`, `no-tool`, `unsupported`, `partial` and "never collected" apart on
// the way in, and all of it is thrown away by one `?? '—'` in a renderer.
//
// The two failures worth naming, because they are the ones a naive table
// produces on its own:
//
//   * A host whose firewall was refused has no rule count, and "0 rules"
//     is what a `?? 0` puts on screen.
//   * A host whose sshd_config could not be read has zero WEAK directives,
//     and "nothing weak" is what counting them produces. It is a clean bill
//     of health for a configuration nobody read.

function server(id: string, name: string): Server {
  return {
    id,
    workspaceId: 'ws-default',
    folderId: null,
    name,
    host: `${id}.example.internal`,
    port: 22,
    username: 'ops',
    auth: 'key',
    status: 'online',
    tags: [],
    favorite: false,
    os: 'linux',
    route: [],
    vpnProfileId: null
  }
}

const NOW = 1_800_000_000_000
const collected = (lines: string[]): HostPosture => parsePosture(lines.join('\n'), NOW)

interface Held {
  posture?: HostPosture
  facts?: HostFacts
  error?: string
}

function mount(held: Record<string, Held>, servers: Server[]): void {
  stubBridge({
    fleet: {
      sampleNow: async (): Promise<void> => undefined,
      posture: async (id: string) => ({
        posture: held[id]?.posture,
        at: held[id]?.posture ? NOW - 60_000 : undefined,
        error: held[id]?.error,
        intervalMs: 3_600_000
      }),
      facts: async (id: string) => ({ facts: held[id]?.facts, at: NOW - 60_000, intervalMs: 3_600_000 })
    }
  })
  render(<PosturePanel servers={servers} />)
}

/** The text of one cell, found by the row's host name and the column id rather
 *  than by position — the columns move, the meaning does not. */
const cell = (host: string, col: string): string =>
  screen.getByText((_, el) => el?.getAttribute('data-host') === host && el?.getAttribute('data-col') === col)
    .textContent ?? ''

describe('a check that could not run is never shown as a check that passed', () => {
  it('shows a refused firewall as not permitted, never as a rule count', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V fw-tool ufw',
            'V fw-backend-status denied',
            POSTURE_STATUS_MARKER,
            'firewall denied - ufw status needs root on this host',
            'mandatory-access absent - neither is installed',
            'sshd-hardening ok - files',
            'failed-logins denied - needs root'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'firewall')).toBe('not permitted'))
    // The three spellings a naive table produces, none of which may appear.
    expect(cell('web-1', 'firewall')).not.toMatch(/\b0\b/)
    expect(cell('web-1', 'firewall')).not.toBe('—')
    expect(cell('web-1', 'firewall')).not.toBe('')
  })

  it('shows a host with no firewall tooling as cannot-be-answered, not as open', async () => {
    mount(
      {
        a: {
          posture: collected([
            POSTURE_STATUS_MARKER,
            'firewall unsupported - this host has none of ufw, firewalld, nft or iptables installed',
            'mandatory-access absent - neither is installed',
            'sshd-hardening absent - no sshd_config',
            'failed-logins no-tool - no lastb'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'firewall')).toBe('cannot be answered'))
  })

  it('shows an unread sshd config as unknown, NEVER as "nothing weak"', async () => {
    // THE failure this panel exists to prevent. A host whose sshd_config could
    // not be read has zero weak directives, and counting them produces a clean
    // bill of health for a configuration nobody read.
    mount(
      {
        a: {
          posture: collected([
            POSTURE_STATUS_MARKER,
            'firewall unsupported - nothing installed',
            'mandatory-access absent - neither is installed',
            'sshd-hardening denied - /etc/ssh exists and this account cannot enter it',
            'failed-logins denied - needs root'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'sshd')).toBe('not permitted'))
    expect(cell('web-1', 'sshd')).not.toMatch(/nothing weak|hardened|ok/i)
  })

  it('does not call a partly-read sshd config clean either', async () => {
    // Two directives read and neither weak, six not read at all. "nothing weak"
    // on its own would be true and misleading; the count of what was not read
    // has to travel with it.
    mount(
      {
        a: {
          posture: collected([
            'V sshd-src files',
            'D PasswordAuthentication no',
            'D PubkeyAuthentication yes',
            POSTURE_STATUS_MARKER,
            'firewall unsupported - nothing installed',
            'mandatory-access absent - neither is installed',
            'sshd-hardening ok - files',
            'failed-logins denied - needs root'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'sshd')).toContain('not read'))
    expect(cell('web-1', 'sshd')).toContain('6')
  })

  it('names the weak directives rather than scoring them', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V sshd-src effective',
            'D permitrootlogin yes',
            'D passwordauthentication yes',
            'D pubkeyauthentication yes',
            'D x11forwarding no',
            'D permitemptypasswords no',
            'D maxauthtries 3',
            'D allowusers ops',
            'D allowgroups ssh-users',
            POSTURE_STATUS_MARKER,
            'firewall unsupported - nothing installed',
            'mandatory-access absent - neither is installed',
            'sshd-hardening ok root sshd -T',
            'failed-logins denied - needs root'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'sshd')).toContain('PermitRootLogin'))
    expect(cell('web-1', 'sshd')).toContain('PasswordAuthentication')
    expect(cell('web-1', 'sshd')).toContain('2 weak')
  })

  it('shows a host that was never collected as not collected, not as clear', async () => {
    mount({}, [server('a', 'web-1'), server('b', 'web-2')])
    // With nothing collected anywhere the panel shows its empty state rather
    // than a table of blanks.
    await waitFor(() => expect(screen.getByText(/No security posture has been collected yet/)).toBeTruthy())
  })

  it('keeps an uncollected host visible beside a collected one, and says which is which', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V fw-tool ufw',
            'V fw-active active',
            'V fw-rules 3',
            'V fw-backend-status ok',
            POSTURE_STATUS_MARKER,
            'firewall ok - ufw status verbose',
            'mandatory-access absent - neither is installed',
            'sshd-hardening ok - files',
            'failed-logins denied - needs root'
          ])
        }
      },
      [server('a', 'web-1'), server('b', 'web-2')]
    )
    await waitFor(() => expect(cell('web-1', 'firewall')).toContain('3 rules'))
    // The host nobody has looked at is on the table saying so, not missing from
    // it and not sharing web-1's reading.
    expect(cell('web-2', 'firewall')).toBe('not collected')
    expect(cell('web-2', 'sshd')).toBe('not collected')
  })
})

describe('the security update count comes from the inventory probe', () => {
  const posture = (): HostPosture =>
    collected([
      POSTURE_STATUS_MARKER,
      'firewall unsupported - nothing installed',
      'mandatory-access absent - neither is installed',
      'sshd-hardening absent - no sshd_config',
      'failed-logins no-tool - no lastb'
    ])

  it('shows an unsupported count as cannot-be-answered, never as zero', async () => {
    // An Arch host can NEVER report one. Rendering that as 0 during a CVE week
    // is the precise failure item C exists to prevent, and this panel must not
    // undo it on the way to the screen.
    mount(
      {
        a: {
          posture: posture(),
          facts: parseHostFacts(
            [
              'V pkg pacman',
              '===SHELLPILOT-FACTS===',
              'package-manager ok -',
              'security-updates unsupported - "Arch Linux has no security update channel"'
            ].join('\n'),
            NOW
          )
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'updates')).toBe('cannot be answered'))
  })

  it('shows a real zero as a real zero', async () => {
    mount(
      {
        a: {
          posture: posture(),
          facts: parseHostFacts(
            [
              'V pkg apt',
              'V security 0',
              '===SHELLPILOT-FACTS===',
              'package-manager ok -',
              'security-updates ok - apt-check'
            ].join('\n'),
            NOW
          )
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'updates')).toBe('0'))
  })

  it('shows a host with no inventory at all as unknown rather than zero', async () => {
    mount({ a: { posture: posture() } }, [server('a', 'web-1')])
    await waitFor(() => expect(cell('web-1', 'updates')).toBe('unknown'))
  })
})

describe('the sshd detail', () => {
  it('lists every directive in the baseline, including the ones nobody read', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V sshd-src files',
            'V sshd-match 1',
            'D PermitRootLogin yes',
            POSTURE_STATUS_MARKER,
            'firewall unsupported - nothing installed',
            'mandatory-access absent - neither is installed',
            'sshd-hardening ok - files',
            'failed-logins denied - needs root'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(screen.getByTitle(/every directive in the hardening baseline/)).toBeTruthy())
    await userEvent.click(screen.getByTitle(/every directive in the hardening baseline/))

    const detail = await screen.findByText(
      (_, el) => el?.getAttribute('data-sshd-detail') === 'web-1'
    )
    // All eight rows, not just the one that was read — an absent directive is
    // a row saying "not read", never a row that is missing.
    for (const d of [
      'PermitRootLogin',
      'PasswordAuthentication',
      'PubkeyAuthentication',
      'X11Forwarding',
      'PermitEmptyPasswords',
      'MaxAuthTries',
      'AllowUsers',
      'AllowGroups'
    ]) {
      expect(detail.querySelector(`[data-directive="${d}"]`), d).toBeTruthy()
    }
    expect(detail.querySelector('[data-directive="AllowUsers"]')?.textContent).toContain('not read')
    // And the reading is flagged as coming from files rather than from sshd,
    // plus the Match block that makes the global values conditional.
    expect(detail.textContent).toContain('Read from configuration files')
    expect(detail.textContent).toContain('conditional')
  })
})
