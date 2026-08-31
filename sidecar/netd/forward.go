package main

import (
	"context"
	"net"
)

// A plain local forward: everything that arrives on the host listener goes to
// one fixed host:port inside the tunnel. Deliberately the same shape as
// openEphemeralForward in src/main/services/tunnel.ts, so src/main/services/
// db.ts can consume either without knowing which kind of tunnel it got.
//
// The target host is dialled through Tunnel.dial, which means a hostname
// target is resolved by the tunnel's DNS servers, not the host's.
func serveForward(ctx context.Context, t *Tunnel, c net.Conn, host string, port int) {
	upstream, err := t.dial(ctx, host, port)
	if err != nil {
		t.out.Log("warn", t.id, "forward to "+hostPort(host, port)+": "+redact(err.Error()))
		return
	}
	defer upstream.Close()
	relay(ctx, c, upstream)
}
