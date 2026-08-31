package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// A minimal SOCKS5 server (RFC 1928), CONNECT only.
//
// UDP ASSOCIATE and BIND are deliberately absent. BIND needs an inbound
// listener inside the tunnel, which nothing in ShellPilot asks for, and UDP
// ASSOCIATE needs a UDP relay whose lifetime is tied to the TCP control
// connection — real work for a feature no database driver or SSH client uses.
// Both answer 0x07 "command not supported", which every client understands.

const (
	socksVersion = 0x05

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess            = 0x00
	repGeneralFailure     = 0x01
	repNetworkUnreachable = 0x03
	repHostUnreachable    = 0x04
	repConnRefused        = 0x05
	repCmdNotSupported    = 0x07
	repAtypNotSupported   = 0x08

	authNone         = 0x00
	authNoAcceptable = 0xFF

	// A client that opens a connection and then says nothing must not hold a
	// goroutine forever. Applies to negotiation only; cleared before relay.
	socksNegotiateTimeout = 30 * time.Second
)

func serveSocks5(ctx context.Context, t *Tunnel, c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(socksNegotiateTimeout))

	host, port, err := socksNegotiate(c)
	if err != nil {
		// Nothing useful to tell the client past the reply already sent.
		return
	}

	upstream, derr := t.dial(ctx, host, port)
	if derr != nil {
		_ = writeSocksReply(c, socksReplyCode(derr), netip.AddrPort{})
		t.out.Log("warn", t.id, "socks5: "+redact(derr.Error()))
		return
	}
	defer upstream.Close()

	// BND.ADDR/BND.PORT: the tunnel-side local address of the new connection.
	// Most clients ignore it, but reporting the real one costs nothing and is
	// what the RFC asks for.
	var bnd netip.AddrPort
	if ta, ok := upstream.LocalAddr().(*net.TCPAddr); ok {
		if a, ok2 := netip.AddrFromSlice(ta.IP); ok2 {
			bnd = netip.AddrPortFrom(a.Unmap(), uint16(ta.Port))
		}
	}
	if err := writeSocksReply(c, repSuccess, bnd); err != nil {
		return
	}

	// Negotiation is over; the relay manages its own lifetime via ctx.
	_ = c.SetDeadline(time.Time{})
	relay(ctx, c, upstream)
}

// socksNegotiate runs the greeting and the request, writing a failure reply
// itself when it can. It returns the requested destination as host (which may
// be a domain name — resolution happens inside the tunnel, never here) and
// port.
func socksNegotiate(c net.Conn) (string, int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != socksVersion {
		return "", 0, errors.New("not a SOCKS5 greeting")
	}
	// nmethods is a single byte, so this read is bounded at 255 by the wire
	// format itself.
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", 0, err
	}
	ok := false
	for _, m := range methods {
		if m == authNone {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = c.Write([]byte{socksVersion, authNoAcceptable})
		return "", 0, errors.New("client offered no acceptable auth method")
	}
	if _, err := c.Write([]byte{socksVersion, authNone}); err != nil {
		return "", 0, err
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", 0, err
	}
	if req[0] != socksVersion {
		return "", 0, errors.New("bad SOCKS5 request version")
	}
	if req[1] != cmdConnect {
		_ = writeSocksReply(c, repCmdNotSupported, netip.AddrPort{})
		return "", 0, errors.New("only CONNECT is supported")
	}

	var host string
	switch req[3] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(b).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return "", 0, err
		}
		// Left as a name on purpose. Tunnel.dial resolves it with
		// tnet.LookupContextHost, i.e. over the tunnel. Resolving it here
		// with the host resolver would leak every hostname the user visits.
		host = string(name)
	default:
		_ = writeSocksReply(c, repAtypNotSupported, netip.AddrPort{})
		return "", 0, errors.New("unsupported address type")
	}

	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(p[:]))
	if host == "" || port == 0 {
		_ = writeSocksReply(c, repGeneralFailure, netip.AddrPort{})
		return "", 0, errors.New("empty destination")
	}
	return host, port, nil
}

func writeSocksReply(c net.Conn, code byte, bnd netip.AddrPort) error {
	buf := make([]byte, 0, 22)
	buf = append(buf, socksVersion, code, 0x00)
	switch {
	case bnd.Addr().Is4():
		b := bnd.Addr().As4()
		buf = append(buf, atypIPv4)
		buf = append(buf, b[:]...)
	case bnd.Addr().Is6():
		b := bnd.Addr().As16()
		buf = append(buf, atypIPv6)
		buf = append(buf, b[:]...)
	default:
		buf = append(buf, atypIPv4, 0, 0, 0, 0)
	}
	buf = append(buf, byte(bnd.Port()>>8), byte(bnd.Port()))
	_, err := c.Write(buf)
	return err
}

// socksReplyCode maps our dial failure onto the closest RFC 1928 reply, so a
// client shows "host unreachable" rather than a blanket "general failure" and
// the user has some idea which half broke.
func socksReplyCode(err error) byte {
	var ce *codedError
	if errors.As(err, &ce) {
		switch ce.code {
		case ErrDNSFailure:
			return repHostUnreachable
		case ErrNetworkUnreachable:
			// netstack surfaces a refusal as a plain connect error; the
			// string is the only signal available.
			if strings.Contains(strings.ToLower(err.Error()), "refused") {
				return repConnRefused
			}
			return repNetworkUnreachable
		}
	}
	return repGeneralFailure
}

// hostPort is a small helper shared with the HTTP proxy.
func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
