// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { PosturePanel } from '../src/renderer/src/components/monitor/PosturePanel'
import { OOM_WINDOW_HOURS, POSTURE_STATUS_MARKER, parsePosture } from '../src/shared/posture'
import { CERT_EXPIRED, CERT_FAR, CERT_SOON } from './postureCertificateFixtures'
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
            'firewall denied - ufw status needs root on this server',
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

  it('shows a server with no firewall tooling as cannot-be-answered, not as open', async () => {
    mount(
      {
        a: {
          posture: collected([
            POSTURE_STATUS_MARKER,
            'firewall unsupported - this server has none of ufw, firewalld, nft or iptables installed',
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

  it('shows a server that was never collected as not collected, not as clear', async () => {
    mount({}, [server('a', 'web-1'), server('b', 'web-2')])
    // With nothing collected anywhere the panel shows its empty state rather
    // than a table of blanks.
    await waitFor(() => expect(screen.getByText(/No security posture has been collected yet/)).toBeTruthy())
  })

  it('keeps an uncollected server visible beside a collected one, and says which is which', async () => {
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

  it('shows a server with no inventory at all as unknown rather than zero', async () => {
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

describe('the firewall rules — roadmap item 31', () => {
  const RULES = [
    'V fw-tool ufw',
    'V fw-active active',
    'V fw-rules 3',
    'V fw-rule-collection on',
    'V fw-rule-lines-front 3',
    'R front 22/tcp ALLOW IN Anywhere',
    'R front 443/tcp ALLOW IN Anywhere',
    'R front 3306/tcp ALLOW IN Anywhere',
    POSTURE_STATUS_MARKER,
    'firewall ok - ufw status verbose'
  ]

  const openRules = async (): Promise<HTMLElement> => {
    await waitFor(() => expect(screen.getByTitle(/rule lines this server/i)).toBeTruthy())
    await userEvent.click(screen.getByTitle(/rule lines this server/i))
    return screen.findByText((_, el) => el?.getAttribute('data-rules-detail') === 'web-1')
  }

  it('answers the question the count cannot: what is open, and to whom', async () => {
    mount({ a: { posture: collected(RULES) } }, [server('a', 'web-1')])
    const detail = await openRules()
    expect(detail.textContent).toContain('3306/tcp ALLOW IN Anywhere')
    // Marked as the host's words, not ShellPilot's. The line above is text
    // written by whoever configured that machine.
    expect(detail.textContent).toContain('Reported by the server')
    // And where it came from, named, so a reader can go and check it.
    expect(detail.textContent).toContain('ufw status verbose')
  })

  it('says nobody asked for them rather than showing a server with no rules', async () => {
    // The capability ungranted. The cell still reads "ufw · 3 rules"; the
    // detail must NOT read as a host whose rule list is empty.
    mount(
      {
        a: {
          posture: collected([
            'V fw-tool ufw',
            'V fw-active active',
            'V fw-rules 3',
            POSTURE_STATUS_MARKER,
            'firewall ok - ufw status verbose'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    const detail = await openRules()
    expect(detail.textContent).toContain('were not collected')
    expect(detail.textContent).toContain('Firewall rules')
    expect(detail.textContent).not.toMatch(/no rules|none/i)
  })

  it('states a truncation instead of showing a prefix as the whole list', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V fw-tool ufw',
            'V fw-rule-collection on',
            'V fw-rule-lines-front 60',
            ...Array.from({ length: 40 }, (_, i) => `R front ${i + 1}/tcp ALLOW IN Anywhere`),
            POSTURE_STATUS_MARKER,
            'firewall ok - ufw status verbose'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    const detail = await openRules()
    expect(detail.textContent).toContain('40 of 60')
  })

  it('says the ruleset was refused rather than listing nothing', async () => {
    // Granted, and the read that would have produced the lines was refused.
    // An empty list here would render as "this host allows nothing in".
    mount(
      {
        a: {
          posture: collected([
            'V fw-tool ufw',
            'V fw-active yes',
            'V fw-rule-collection on',
            POSTURE_STATUS_MARKER,
            'firewall partial - ufw status needs root on this server'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    const detail = await openRules()
    expect(detail.textContent).toContain('could not be read')
    expect(detail.textContent).toContain('needs root on this server')
    expect(detail.textContent).not.toMatch(/no rules|nothing is allowed/i)
  })
})

// ---------------------------------------------------------------------------
// The two cells item 19b deferred
//
// Same rule as every cell above, and for these two it is the ENTIRE reason
// they were held back: a zero read from a kernel ring buffer and an empty list
// from a certificate directory nobody could enter are the two most convincing
// clean bills of health this panel could print, and neither is one.
// ---------------------------------------------------------------------------

describe('the OOM cell never turns an unread kernel log into a quiet server', () => {
  it('shows a restricted dmesg as not permitted, never as no kills', async () => {
    mount(
      {
        a: {
          posture: collected([
            POSTURE_STATUS_MARKER,
            'oom-kills denied - dmesg is installed and the kernel refused it'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'oom')).toBe('not permitted'))
    // The spellings a naive table produces, none of which may appear.
    expect(cell('web-1', 'oom')).not.toMatch(/\bnone\b/i)
    expect(cell('web-1', 'oom')).not.toMatch(/\b0\b/)
    expect(cell('web-1', 'oom')).not.toBe('—')
  })

  it('shows a ring-buffer zero as an unbounded window, not as a clean day', async () => {
    // The line the whole kind was deferred over. dmesg read fine and held no
    // kill; that is not a statement about the last twenty-four hours, and the
    // cell must not let it be read as one.
    mount(
      {
        a: {
          posture: collected([
            'V oom-tool dmesg',
            'V oom-count 0',
            'V oom-procs 0',
            'V oom-window the kernel ring buffer which reaches back only as far as it has not been overwritten',
            POSTURE_STATUS_MARKER,
            'oom-kills partial - dmesg. The ring buffer is not a time window'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'oom')).toBe('none seen · window unbounded'))
    expect(cell('web-1', 'oom')).not.toBe(`none in ${OOM_WINDOW_HOURS}h`)
  })

  it('shows a journal zero as the real reading it is', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V oom-tool journal',
            'V oom-count 0',
            'V oom-procs 0',
            `V oom-window the last ${OOM_WINDOW_HOURS} hours of the kernel journal`,
            POSTURE_STATUS_MARKER,
            'oom-kills ok - journalctl -k'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'oom')).toBe(`none in ${OOM_WINDOW_HOURS}h`))
  })

  it('counts kills and the names they wore', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V oom-tool journal',
            'V oom-count 3',
            'V oom-procs 2',
            `V oom-window the last ${OOM_WINDOW_HOURS} hours of the kernel journal`,
            POSTURE_STATUS_MARKER,
            'oom-kills ok - journalctl -k'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'oom')).toBe('3 killed · 2 names'))
  })
})

describe('the certificate cell never turns an unread directory into a server with none', () => {
  it('shows a refused certificate directory as refused, never as none found', async () => {
    // /etc/letsencrypt is 0700 root on Debian, so this is the common case and
    // "none found" is the answer a naive table gives for it.
    mount(
      {
        a: {
          posture: collected([
            'V cert-searched 1',
            'V cert-refused 1',
            POSTURE_STATUS_MARKER,
            'certificates denied - every certificate directory present refused to be entered'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'certs')).toBe('1 directory refused'))
    expect(cell('web-1', 'certs')).not.toMatch(/none/i)
    expect(cell('web-1', 'certs')).not.toMatch(/\bok\b/i)
  })

  it('shows a certificate that would not parse as unread, never as valid', async () => {
    mount(
      {
        a: {
          posture: collected([
            'C AAAA /etc/nginx/broken.pem',
            'V cert-searched 1',
            'V cert-refused 0',
            POSTURE_STATUS_MARKER,
            'certificates ok - read every directory'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'certs')).toBe('1 could not be read'))
    expect(cell('web-1', 'certs')).not.toMatch(/left/)
  })

  it('shows an expired certificate differently from one expiring soon', async () => {
    mount(
      {
        a: {
          posture: collected([
            `C ${CERT_EXPIRED} /etc/nginx/old.pem`,
            'V cert-searched 1',
            'V cert-refused 0',
            POSTURE_STATUS_MARKER,
            'certificates ok - read every directory'
          ])
        },
        b: {
          posture: collected([
            `C ${CERT_SOON} /etc/nginx/soon.pem`,
            'V cert-searched 1',
            'V cert-refused 0',
            POSTURE_STATUS_MARKER,
            'certificates ok - read every directory'
          ])
        }
      },
      [server('a', 'web-1'), server('b', 'web-2')]
    )
    // 27 and not 26: `daysRemaining` is floored, so a certificate that expired
    // 26 days and 8 hours before this file's NOW is -27. The literal is written
    // out rather than computed, which is what makes that visible.
    await waitFor(() => expect(cell('web-1', 'certs')).toBe('EXPIRED 27d ago'))
    expect(cell('web-2', 'certs')).toBe('17d left')
  })

  it('says how much it could not read beside the number it did read', async () => {
    // "45 days" beside a silently skipped /etc/letsencrypt is worse than no
    // number at all: it is a number that may not be the worst one on the host.
    mount(
      {
        a: {
          posture: collected([
            `C ${CERT_FAR} /etc/nginx/good.pem`,
            'V cert-searched 1',
            'V cert-refused 2',
            POSTURE_STATUS_MARKER,
            'certificates partial - some directories refused to be entered'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'certs')).toBe('502d left · 2 not read'))
  })

  it('shows a clean search that found nothing as a reading, not as a gap', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V cert-searched 1',
            'V cert-refused 0',
            POSTURE_STATUS_MARKER,
            'certificates ok - read every directory'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'certs')).toBe('none found'))
  })

  it('shows a server with none of the directories as absent, having checked', async () => {
    mount(
      {
        a: {
          posture: collected([
            'V cert-searched 0',
            'V cert-refused 0',
            POSTURE_STATUS_MARKER,
            'certificates absent - none of the directories is present'
          ])
        }
      },
      [server('a', 'web-1')]
    )
    await waitFor(() => expect(cell('web-1', 'certs')).toBe('no certificate directories'))
  })
})
