import { useEffect } from 'react'
import { useApp } from '../../store/app'
import { toast } from '../../store/toast'
import { bridgeOn } from '../../lib/bridge'

interface CreateRequest {
  workspaceId: string
  name: string
  host: string
  port: number
  username: string
  auth: 'password' | 'key' | 'agent'
  password?: string
  keyPath?: string
  passphrase?: string
  os?: string
}

// Mounted once at the app root, like ApprovalWatcher. The add_server MCP tool
// has already resolved the workspace, checked the access group and taken the
// user's approval by the time this runs — the work left here is the part only
// the renderer can do, because it owns the connection list and the persistence
// that follows from changing it.
export function AgentServerWatcher(): null {
  useEffect(() => {
    const api = window.shellpilot?.aiMcp
    const off = bridgeOn('aiMcp.onCreateServerRequest', api?.onCreateServerRequest, ({ id, request }) => {
      void (async () => {
        const req = request as unknown as CreateRequest
        try {
          const serverId = useApp.getState().addServer({
            workspaceId: req.workspaceId,
            name: req.name,
            host: req.host,
            port: req.port,
            username: req.username,
            auth: req.auth,
            os: req.os ?? 'Linux'
          })

          // Same shape AddServerModal writes: credentials go to OS secure
          // storage keyed by server id, never into the connection list itself.
          const secret =
            req.auth === 'password'
              ? { password: req.password }
              : req.auth === 'key'
                ? { keyPath: req.keyPath, passphrase: req.passphrase || undefined }
                : null
          if (secret && (secret.password || secret.keyPath)) {
            const ok = await window.shellpilot?.secrets.set(serverId, JSON.stringify(secret))
            if (ok === false) {
              // The server row is useless without the credential the agent
              // supplied, and half-adding it would leave the user to guess what
              // went wrong, so undo rather than report success.
              useApp.getState().deleteServer(serverId)
              api?.replyCreateServer?.(id, {
                ok: false,
                error: 'OS secure storage is unavailable, so the credential could not be saved.'
              })
              return
            }
          }

          toast(`${req.name} added by an AI agent`, 'ok')
          api?.replyCreateServer?.(id, { ok: true, serverId })
        } catch (err) {
          api?.replyCreateServer?.(id, {
            ok: false,
            error: err instanceof Error ? err.message : String(err)
          })
        }
      })()
    })
    return () => off?.()
  }, [])

  return null
}
