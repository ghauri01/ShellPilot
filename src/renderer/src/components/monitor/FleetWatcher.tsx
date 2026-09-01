import { useEffect, useMemo } from 'react'
import { useApp, useWorkspaceServers } from '../../store/app'
import { useFleet } from '../../store/fleet'
import { checkResourceAlerts, checkUnitAlerts } from '../../store/alerts'
import { bridgeOn } from '../../lib/bridge'
import { sshHopsFor } from '../../lib/ssh'
import type { FleetTarget } from '../../../../shared/fleet'
import type { Server } from '../../types'

// Mounted once at the app root, for the same reason ApprovalWatcher is: the
// thing it watches for does not wait until you are looking at the right tab.
//
// Sampling used to be owned by mounted ServerMonitorCards, so leaving the
// monitor stopped it and the estate's state was known only while somebody was
// watching. This component owns none of the sampling — main does — but it is
// what tells main WHICH servers to watch, and what receives the results.

// Servers are described here exactly as a terminal session describes them.
// Secrets are deliberately absent: main resolves them per sweep, so a target
// configured while the vault was locked starts working the moment it is
// unlocked, with no reconfigure.
function toTarget(s: Server): FleetTarget {
  return {
    serverId: s.id,
    serverName: s.name,
    cfg: {
      // SshConnectConfig is the terminal-connect shape, so it carries a
      // sessionId and a window size that a metrics exec has no use for. The
      // foreground metrics hook fills them in the same way; the values are
      // inert here, and inventing a narrower type for one caller would mean
      // metricsSample took two shapes.
      sessionId: `fleet-${s.id}`,
      cols: 80,
      rows: 24,
      serverId: s.id,
      host: s.host,
      port: s.port,
      username: s.username,
      auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
      hops: sshHopsFor(s)
    }
  }
}

export function FleetWatcher(): null {
  const servers = useWorkspaceServers()
  const enabled = useApp((s) => s.settings.fleetSamplingEnabled)
  const intervalMs = useApp((s) => s.settings.fleetSamplingIntervalMs)
  const report = useFleet((s) => s.report)

  // Demo servers have nothing to sample, and an offline one is a connection
  // attempt per sweep that will not succeed — main reports the failure rather
  // than hiding it, but there is no reason to generate it every interval.
  const targets = useMemo(
    () => servers.filter((s) => s.demo === false).map(toTarget),
    [servers]
  )

  // Results arrive whether or not anything is on screen, so the subscription
  // is separate from the configuration below and is never torn down by a
  // settings change.
  useEffect(() => {
    const off = bridgeOn('fleet.onSample', window.shellpilot?.fleet?.onSample, (e) => {
      if (!e.host) return
      report(e.serverId, e.host)
      // Thresholds live in the renderer because that is where the settings
      // and the toast surface are. Before this, they were evaluated inside
      // the monitor's own poll — so an alert could only fire while the user
      // was already looking at the screen that would have shown the problem.
      const name = servers.find((s) => s.id === e.serverId)?.name ?? e.serverId
      checkResourceAlerts(e.serverId, name, e.host.cpu, e.host.memPct)
      // The reason the feature exists. A failed unit does not move a CPU or
      // memory graph, so thresholds would never have caught the case this was
      // built for. `null` stays null: "systemd was not visible" is not "nothing
      // is failing", and flattening it would post a false all-clear.
      checkUnitAlerts(
        e.serverId,
        name,
        e.host.services === null
          ? null
          : e.host.services.filter((u) => u.active === 'failed' || u.sub === 'failed').map((u) => u.name)
      )
    })
    return () => off?.()
    // `servers` is read only to name a server in an alert; re-subscribing on
    // every server edit would drop events during the gap.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report])

  // Reconfigure whenever what should be watched changes. Main treats this as
  // the complete desired state, so removing a server here stops sampling it.
  useEffect(() => {
    void window.shellpilot?.fleet?.configure({ enabled, intervalMs, targets })
  }, [enabled, intervalMs, targets])

  return null
}
