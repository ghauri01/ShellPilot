import type { VpnImportResultInternal, VpnKind } from '../../../../shared/vpn'
import { parseFrpConfig } from './frpImport'
import { parseOvpn } from './ovpn'
import { parseWgConf } from './wgConf'

// One entry point for the import handler, so the rule that a user-supplied file
// is never handed to an engine lives in one place per protocol and the caller
// only ever sees a typed result.

export { parseWgConf, hostHasIpv6, PENDING_VAULT_ENTRY } from './wgConf'
export type { WgParseOptions, WgRejectRule } from './wgConf'
export { WG_REJECT_RULES } from './wgConf'

export {
  parseOvpn,
  emitOvpnConfig,
  ovpnArgs,
  escapeOvpnValue,
  ovpnRejectRuleFor,
  OVPN_REJECT_RULES,
  OVPN_PULL_FILTER_REJECTS
} from './ovpn'
export type { OvpnArgOptions, OvpnParseOptions, OvpnRejectRule } from './ovpn'

export { parseFrpConfig, isLegacyIni, parseTomlSubset, FRP_REJECT_RULES } from './frpImport'
export type { FrpRejectRule, TomlTable, TomlValue } from './frpImport'

export interface VpnParseOptions {
  /** The folder the profile was imported from. OpenVPN path-form `ca`/`cert`/
   *  `key` directives are read only from inside it (E37); without it they are
   *  rejected rather than resolved against the process working directory. */
  baseDir?: string
  /** Overridable so the E16 IPv6 warning is testable. */
  hostHasIpv6?: boolean
}

export function parseVpnConfig(
  kind: VpnKind,
  text: string,
  opts: VpnParseOptions = {}
): VpnImportResultInternal {
  switch (kind) {
    case 'wireguard':
      return parseWgConf(text, { hostHasIpv6: opts.hostHasIpv6 })
    case 'openvpn':
      return parseOvpn(text, opts.baseDir, { hostHasIpv6: opts.hostHasIpv6 })
    case 'frp':
      return parseFrpConfig(text)
  }
}

/** Best guess at which parser a file wants, from its name and its first lines.
 *  Only a guess: the import UI still names the kind, and a wrong guess produces
 *  a parse failure rather than a mis-parse, because each parser only accepts
 *  its own shape. */
export function detectVpnKind(text: string, fileName?: string): VpnKind | null {
  const ext = fileName ? /\.([A-Za-z0-9]+)$/.exec(fileName)?.[1]?.toLowerCase() : undefined
  if (ext === 'ovpn') return 'openvpn'
  if (ext === 'toml') return 'frp'

  if (/^[ \t]*\[Interface\][ \t]*$/im.test(text)) return 'wireguard'
  if (/^[ \t]*\[common\][ \t]*$/im.test(text)) return 'frp'
  if (/^[ \t]*serverAddr[ \t]*=/m.test(text) || /^[ \t]*\[\[proxies\]\][ \t]*$/im.test(text)) return 'frp'
  if (/^[ \t]*(client|remote|<ca>)\b/im.test(text)) return 'openvpn'
  return null
}
