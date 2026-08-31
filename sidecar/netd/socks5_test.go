package main

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// connPair returns two connected TCP endpoints over loopback.
//
// net.Pipe would be lighter but it is synchronous and unbuffered, so a client
// that writes a request while the server writes a reply deadlocks — which is
// a property of net.Pipe, not of the code under test. Real sockets have
// kernel buffers and behave like the ones netd actually serves.
func connPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()
	client, err = net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	t.Cleanup(func() { client.Close(); a.c.Close() })
	return client, a.c
}

// negotiate drives socksNegotiate against a scripted client and returns what
// it decided plus whatever it wrote back.
func negotiate(t *testing.T, client func(net.Conn)) (host string, port int, err error, reply []byte) {
	t.Helper()
	a, b := connPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		client(a)
	}()
	host, port, err = socksNegotiate(b)
	<-done

	// Shut the two sides down in an order that cannot destroy the reply.
	//
	// socksNegotiate returns as soon as it has decided, which for a rejected
	// command means the rest of the request — six bytes of address and port —
	// is still sitting unread in the server's receive queue. close(2) on a
	// socket with unread data sends RST rather than FIN, and an RST makes the
	// peer's kernel discard whatever it had already buffered: the very reply
	// this function exists to return. It is timing-dependent (the client is
	// racing the close to drain its buffer), which is why it showed up as an
	// occasional empty `reply` on a loaded machine and never on an idle one.
	//
	// So: the client half-closes, the server drains to EOF, and only then does
	// the server close — a clean FIN with nothing left to discard.
	if ca, ok := a.(*net.TCPConn); ok {
		_ = ca.CloseWrite()
	}
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, b)
	_ = b.Close()

	_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, a)
	return host, port, err, buf.Bytes()
}

func TestSocksNegotiateDomainStaysUnresolved(t *testing.T) {
	// The whole point of requirement 6: a domain-type request must reach
	// Tunnel.dial as a NAME, so it is resolved by the tunnel's DNS servers.
	// Resolving here would leak every hostname to the host resolver.
	host, port, err, _ := negotiate(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x01, 0x00})
		var ack [2]byte
		io.ReadFull(c, ack[:])
		name := "db.internal.example"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(name))}
		req = append(req, name...)
		req = append(req, 0x14, 0x51) // 5201
		c.Write(req)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "db.internal.example" {
		t.Fatalf("host = %q, want the domain name verbatim", host)
	}
	if port != 5201 {
		t.Fatalf("port = %d, want 5201", port)
	}
}

func TestSocksNegotiateIPv4AndIPv6(t *testing.T) {
	host, port, err, _ := negotiate(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x01, 0x00})
		var ack [2]byte
		io.ReadFull(c, ack[:])
		c.Write([]byte{0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50})
	})
	if err != nil || host != "10.0.0.1" || port != 80 {
		t.Fatalf("ipv4: %q %d %v", host, port, err)
	}

	host, port, err, _ = negotiate(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x02, 0x00, 0x02}) // offers no-auth and gssapi
		var ack [2]byte
		io.ReadFull(c, ack[:])
		req := []byte{0x05, 0x01, 0x00, 0x04}
		a := netip.MustParseAddr("fd00::2").As16()
		req = append(req, a[:]...)
		req = append(req, 0x01, 0xbb) // 443
		c.Write(req)
	})
	if err != nil || host != "fd00::2" || port != 443 {
		t.Fatalf("ipv6: %q %d %v", host, port, err)
	}
}

func TestSocksNegotiateRejectsNonConnect(t *testing.T) {
	// UDP ASSOCIATE (0x03) and BIND (0x02) are not implemented; the client
	// must be told so in the protocol's own vocabulary rather than by a
	// dropped connection.
	for _, cmd := range []byte{0x02, 0x03} {
		_, _, err, reply := negotiate(t, func(c net.Conn) {
			c.Write([]byte{0x05, 0x01, 0x00})
			var ack [2]byte
			io.ReadFull(c, ack[:])
			c.Write([]byte{0x05, cmd, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50})
		})
		if err == nil {
			t.Fatalf("cmd %#x was accepted", cmd)
		}
		if len(reply) < 2 || reply[1] != repCmdNotSupported {
			t.Fatalf("cmd %#x: reply = %#v, want REP=0x07", cmd, reply)
		}
	}
}

func TestSocksNegotiateRejectsAuthOnlyClient(t *testing.T) {
	_, _, err, reply := negotiate(t, func(c net.Conn) {
		// Offers username/password only. netd has no credential to check
		// against, so 0xFF is the correct answer.
		c.Write([]byte{0x05, 0x01, 0x02})
	})
	if err == nil {
		t.Fatal("expected the negotiation to fail")
	}
	if len(reply) < 2 || reply[0] != socksVersion || reply[1] != authNoAcceptable {
		t.Fatalf("reply = %#v, want 05 FF", reply)
	}
}

func TestSocksNegotiateRejectsWrongVersion(t *testing.T) {
	// SOCKS4 clients reach a SOCKS5 port surprisingly often.
	_, _, err, _ := negotiate(t, func(c net.Conn) {
		c.Write([]byte{0x04, 0x01, 0x00, 0x50, 10, 0, 0, 1, 0x00})
	})
	if err == nil {
		t.Fatal("a SOCKS4 greeting must be rejected")
	}
}

func TestSocksNegotiateRejectsUnknownAddressType(t *testing.T) {
	_, _, err, reply := negotiate(t, func(c net.Conn) {
		c.Write([]byte{0x05, 0x01, 0x00})
		var ack [2]byte
		io.ReadFull(c, ack[:])
		c.Write([]byte{0x05, 0x01, 0x00, 0x09, 0, 0})
	})
	if err == nil {
		t.Fatal("expected rejection")
	}
	if len(reply) < 2 || reply[1] != repAtypNotSupported {
		t.Fatalf("reply = %#v, want REP=0x08", reply)
	}
}

func TestWriteSocksReplyShapes(t *testing.T) {
	check := func(bnd netip.AddrPort, wantLen int, wantAtyp byte) {
		t.Helper()
		a, b := net.Pipe()
		go func() { writeSocksReply(a, repSuccess, bnd); a.Close() }()
		got, _ := io.ReadAll(b)
		if len(got) != wantLen {
			t.Fatalf("reply len = %d, want %d (%#v)", len(got), wantLen, got)
		}
		if got[0] != socksVersion || got[1] != repSuccess || got[3] != wantAtyp {
			t.Fatalf("reply = %#v", got)
		}
	}
	// VER REP RSV ATYP + 4 addr + 2 port
	check(netip.MustParseAddrPort("10.0.0.2:1080"), 10, atypIPv4)
	// VER REP RSV ATYP + 16 addr + 2 port
	check(netip.MustParseAddrPort("[fd00::2]:1080"), 22, atypIPv6)
	// An unset bind address still has to be a well-formed reply.
	check(netip.AddrPort{}, 10, atypIPv4)
}

func TestSocksReplyCodeMapping(t *testing.T) {
	if got := socksReplyCode(codedf(ErrDNSFailure, "no such host")); got != repHostUnreachable {
		t.Errorf("dns-failure -> %#x, want %#x", got, repHostUnreachable)
	}
	if got := socksReplyCode(codedf(ErrNetworkUnreachable, "no route")); got != repNetworkUnreachable {
		t.Errorf("network-unreachable -> %#x, want %#x", got, repNetworkUnreachable)
	}
	if got := socksReplyCode(codedf(ErrNetworkUnreachable, "connection refused")); got != repConnRefused {
		t.Errorf("refused -> %#x, want %#x", got, repConnRefused)
	}
	if got := socksReplyCode(errString("mystery")); got != repGeneralFailure {
		t.Errorf("unknown -> %#x, want %#x", got, repGeneralFailure)
	}
}
