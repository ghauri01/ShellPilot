import { useEffect, useMemo, useRef } from 'react'
import { useApp, useWorkspaceServers } from '../../store/app'
import { useFleet } from '../../store/fleet'
import { useFleetStatus } from '../../store/fleetStatus'
import { checkResourceAlerts, checkUnitAlerts } from '../../store/alerts'
import { bridgeHas, bridgeOn } from '../../lib/bridge'
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
  // Read through a ref inside the subscription. The handler is registered once
  // on purpose -- resubscribing on every server edit would drop events during
  // the gap -- but that means a plain closure over `servers` goes stale, and a
  // server added after mount would alert under its raw UUID instead of the
  // name its owner chose.
  const serversRef = useRef(servers)
  serversRef.current = servers
  const enabled = useApp((s) => s.settings.fleetSamplingEnabled)
  const intervalMs = useApp((s) => s.settings.fleetSamplingIntervalMs)
  const webhookEnabled = useApp((s) => s.settings.webhookAlertsEnabled)
  const webhookOnResolved = useApp((s) => s.settings.webhookNotifyOnResolved)
  const report = useFleet((s) => s.report)
  const reportError = useFleet((s) => s.reportError)

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
      if (!e.host) {
        // Recorded, not dropped. A host refusing SSH for six hours used to be
        // indistinguishable from one that is fine, because this returned here.
        if (e.error) reportError(e.serverId, e.error, e.at)
        return
      }
      // The sampler's own timestamp, not arrival time: a sweep that took 40s
        // to reach this host was taken 40s ago, and search reports the age.
        report(e.serverId, e.host, e.at)
      // Thresholds live in the renderer because that is where the settings
      // and the toast surface are. Before this, they were evaluated inside
      // the monitor's own poll — so an alert could only fire while the user
      // was already looking at the screen that would have shown the problem.
      const name = serversRef.current.find((s) => s.id === e.serverId)?.name ?? e.serverId
      // `null`, not 0, when df reported nothing: a failed probe yields diskPct
      // 0, and passing that would resolve a disk alert on a host that is still
      // full — a false all-clear manufactured out of a measurement failure.
      checkResourceAlerts(
        e.serverId,
        name,
        e.host.cpu,
        e.host.memPct,
        e.host.diskTotal > 0 ? e.host.diskPct : null
      )
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
  }, [report, reportError])

  // Reconfigure whenever what should be watched changes. Main treats this as
  // the complete desired state, so removing a server here stops sampling it.
  useEffect(() => {
    void window.shellpilot?.fleet?.configure({ enabled, intervalMs, targets })
  }, [enabled, intervalMs, targets])

  // Push webhook settings to main on mount, not only when the toggle moves.
  //
  // The service holds them in memory; the persisted copy lives here. Without
  // this effect the only thing that ever told main they were on was the
  // settings switch, so a restart silently disabled a feature whose whole job
  // is noticing failures while nobody is looking at the app.
  useEffect(() => {
    void window.shellpilot?.webhook?.configure({
      enabled: webhookEnabled,
      notifyOnResolved: webhookOnResolved
    })
  }, [webhookEnabled, webhookOnResolved])

  // Poll the sampler's real state app-wide, not only while Settings is open.
  //
  // This is what makes the status-bar chip possible. Before it, `fleet.status()`
  // was called from exactly one file — the Settings pane — so background
  // checking could be paused for hours and the only place that said so was a
  // screen nobody had reason to open.
  //
  // Ten seconds because these numbers move on the order of a sweep, and a vault
  // unlocked in another window should clear the warning without the user
  // wondering whether it is stuck. Cheap: one IPC call to main, no connection.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'status')) return
    let live = true
    const read = (): void => {
      void window.shellpilot?.fleet?.status().then((s) => {
        if (live && s) useFleetStatus.getState().setStatus(s)
      })
    }
    read()
    const t = setInterval(read, 10_000)
    return () => {
      live = false
      clearInterval(t)
    }
  }, [])

  return null
}
