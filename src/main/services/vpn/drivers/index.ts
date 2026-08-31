import type { VpnKind } from '../../../../shared/vpn'
import type { VpnDriver } from '../driver'
import { frpDriver } from './frp'
import { openvpnDriver } from './openvpn'
import { wireguardDriver } from './wireguard'

// The registry the manager dispatches through.
//
// The point of this file is that `manager.ts` never branches on kind. Lifecycle,
// backoff, status coalescing, secret resolution, dependency teardown and the
// IPC surface are written once; everything protocol-specific lives behind
// `VpnDriver`. When a fourth engine turns up it should touch this file, a new
// drivers/*.ts, and nothing else.
const DRIVERS: Record<VpnKind, VpnDriver> = {
  wireguard: wireguardDriver as VpnDriver,
  openvpn: openvpnDriver as VpnDriver,
  frp: frpDriver as VpnDriver
}

export function driverFor(kind: VpnKind): VpnDriver {
  return DRIVERS[kind]
}

export function allDrivers(): VpnDriver[] {
  return Object.values(DRIVERS)
}
