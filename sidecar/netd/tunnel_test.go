package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/dns/dnsmessage"
)

// This file stands up two real userspace WireGuard devices in-process and
// makes them talk over loopback UDP. It is slower than a fixture test and
// worth it: the UAPI builder, the netstack wiring, the listeners and the
// teardown path only ever fail together, and none of the mistakes that matter
// here (a key in the wrong encoding, a missing replace_allowed_ips, a relay
// that never ends) are visible from a unit test.

const (
	serverIP = "10.7.0.1"
	clientIP = "10.7.0.2"
	echoPort = 8080
)

// genKeypair produces a Curve25519 keypair in the base64 form the protocol
// takes. Not a security-critical generator — these keys live for one test.
func genKeypair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Standard X25519 clamping, the same the WireGuard implementation applies.
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub)
}

// freeUDPPort asks the OS for a port and gives it straight back. Racy in
// principle; in practice nothing else claims it inside one test binary.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe udp port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// discardWriter is a Writer whose output goes nowhere. Protocol framing is
// asserted in protocol_test.go; here the events are noise.
func discardWriter() *Writer { return NewWriter(io.Discard) }

type testPair struct {
	server *Tunnel
	client *Tunnel
}

// newTestPair brings up a two-node tunnel: a "server" node listening on a
// loopback UDP port with an echo service and a DNS responder inside its
// netstack, and a "client" node whose peer endpoint points at it.
func newTestPair(t *testing.T, listeners []ListenerIn) *testPair {
	t.Helper()
	if testing.Short() {
		t.Skip("stands up two WireGuard devices; skipped under -short")
	}

	serverPriv, serverPub := genKeypair(t)
	clientPriv, clientPub := genKeypair(t)
	port := freeUDPPort(t)

	// The server has no endpoint for its peer: it learns the client's source
	// address from the first handshake, which is how a real WireGuard server
	// behaves for roaming clients.
	srv, err := newTunnel(context.Background(), discardWriter(), &UpParams{
		TunnelID: "test-server",
		Iface: IfaceParams{
			PrivateKey: serverPriv,
			Addresses:  []string{serverIP + "/32"},
			ListenPort: port,
			MTU:        1420,
		},
		Peers: []PeerParams{{PublicKey: clientPub, AllowedIPs: []string{clientIP + "/32"}}},
	})
	if err != nil {
		t.Fatalf("server tunnel: %v", err)
	}
	t.Cleanup(srv.closeAll)

	startEchoService(t, srv)
	startDNSService(t, srv)

	cli, err := newTunnel(context.Background(), discardWriter(), &UpParams{
		TunnelID: "test-client",
		Iface: IfaceParams{
			PrivateKey: clientPriv,
			Addresses:  []string{clientIP + "/32"},
			// The DNS server lives inside the tunnel. Anything the listeners
			// resolve must go through it, never the host resolver.
			DNS: []string{serverIP},
			MTU: 1420,
		},
		Peers: []PeerParams{{
			PublicKey:           serverPub,
			Endpoint:            fmt.Sprintf("127.0.0.1:%d", port),
			AllowedIPs:          []string{"10.7.0.0/24"},
			PersistentKeepalive: 1,
		}},
		Listeners: listeners,
	})
	if err != nil {
		t.Fatalf("client tunnel: %v", err)
	}
	t.Cleanup(cli.closeAll)

	for _, l := range listeners {
		if _, err := cli.addListener(l); err != nil {
			t.Fatalf("listener %s: %v", l.Kind, err)
		}
	}
	return &testPair{server: srv, client: cli}
}

// startEchoService runs an uppercase-echo TCP server inside the server node's
// netstack, i.e. only reachable through the tunnel.
func startEchoService(t *testing.T, srv *Tunnel) {
	t.Helper()
	ln, err := srv.tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(serverIP), Port: echoPort})
	if err != nil {
		t.Fatalf("listen inside the tunnel: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write([]byte(strings.ToUpper(string(buf[:n]))))
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
}

// startDNSService answers A queries for echo.test with the server's tunnel
// address. It exists so the test can prove that a hostname handed to SOCKS5
// is resolved over the tunnel: if resolution fell back to the host resolver,
// echo.test would not exist and the dial would fail.
func startDNSService(t *testing.T, srv *Tunnel) {
	t.Helper()
	pc, err := srv.tnet.ListenUDP(&net.UDPAddr{IP: net.ParseIP(serverIP), Port: 53})
	if err != nil {
		t.Fatalf("listen dns inside the tunnel: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, err := answerDNS(buf[:n])
			if err != nil || resp == nil {
				continue
			}
			_, _ = pc.WriteTo(resp, from)
		}
	}()
}

func answerDNS(q []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(q)
	if err != nil {
		return nil, err
	}
	question, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, Authoritative: true, RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	// Only A is answered. An empty NOERROR for AAAA is a perfectly ordinary
	// response for a v4-only name.
	if question.Type == dnsmessage.TypeA && strings.HasPrefix(question.Name.String(), "echo.test.") {
		_ = b.AResource(
			dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: [4]byte{10, 7, 0, 1}},
		)
	}
	return b.Finish()
}

// waitHandshake blocks until the two nodes have completed a handshake.
func waitHandshake(t *testing.T, tun *Tunnel) *StatsResult {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		s, err := tun.stats()
		if err == nil && s.LastHandshakeUnixSec > 0 {
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no handshake within 20s")
	return nil
}

func TestTunnelHandshakeAndStats(t *testing.T) {
	p := newTestPair(t, nil)
	s := waitHandshake(t, p.client)

	// E63: an absolute unix second, not an age. The parent computes the age
	// against its own monotonic base so a clock jump cannot produce nonsense.
	drift := time.Now().Unix() - s.LastHandshakeUnixSec
	if drift < 0 || drift > 60 {
		t.Fatalf("handshake=%d looks like an age, not an absolute unix second (drift %ds)",
			s.LastHandshakeUnixSec, drift)
	}
	if s.Peers != 1 {
		t.Errorf("peers = %d, want 1", s.Peers)
	}
	if s.AssignedIP != clientIP {
		t.Errorf("assignedIp = %q, want %q", s.AssignedIP, clientIP)
	}
	if s.RemoteEndpoint == "" {
		t.Error("remoteEndpoint is empty after a handshake")
	}
	if s.TxBytes == 0 {
		t.Error("txBytes is 0 after a handshake")
	}
	if s.SampledAt == 0 {
		t.Error("sampledAt is unset")
	}
}

func TestTunnelForwardListener(t *testing.T) {
	p := newTestPair(t, []ListenerIn{{
		Kind: "forward", BindHost: "127.0.0.1", BindPort: 0,
		TargetHost: serverIP, TargetPort: echoPort,
	}})
	waitHandshake(t, p.client)

	lns := p.client.listenerList()
	if len(lns) != 1 {
		t.Fatalf("got %d listeners", len(lns))
	}
	// bindPort 0 must resolve to the real port in the reported listener.
	if lns[0].BindPort == 0 {
		t.Fatal("bindPort 0 was echoed back as 0 instead of the bound port")
	}
	if lns[0].TargetHost != serverIP || lns[0].TargetPort != echoPort {
		t.Fatalf("listener target = %s:%d", lns[0].TargetHost, lns[0].TargetPort)
	}

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", lns[0].BindPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the forward: %v", err)
	}
	defer c.Close()
	assertEcho(t, c, "hello through the tunnel")
}

func TestTunnelSocks5ListenerWithIPTarget(t *testing.T) {
	p := newTestPair(t, []ListenerIn{{Kind: "socks5", BindPort: 0}})
	waitHandshake(t, p.client)

	lns := p.client.listenerList()
	// Default bind host is loopback when the caller does not say otherwise.
	if lns[0].BindHost != "127.0.0.1" {
		t.Fatalf("bindHost = %q, want the 127.0.0.1 default", lns[0].BindHost)
	}

	c := socksConnect(t, lns[0].BindPort, atypIPv4, serverIP, echoPort)
	defer c.Close()
	assertEcho(t, c, "socks by address")
}

// The important one for requirement 6: the SOCKS5 client sends a NAME, and
// the only resolver that knows that name lives inside the tunnel. If netd
// resolved it on the host, this test could not pass — and in production the
// hostname would have leaked in cleartext.
func TestTunnelSocks5ResolvesDomainInsideTheTunnel(t *testing.T) {
	p := newTestPair(t, []ListenerIn{{Kind: "socks5", BindPort: 0}})
	waitHandshake(t, p.client)

	// Sanity: the host resolver must NOT know this name, or the test proves
	// nothing.
	if addrs, err := net.LookupHost("echo.test"); err == nil && len(addrs) > 0 {
		t.Skipf("the host resolver answers echo.test (%v); cannot prove tunnel-side resolution here", addrs)
	}

	lns := p.client.listenerList()
	c := socksConnect(t, lns[0].BindPort, atypDomain, "echo.test", echoPort)
	defer c.Close()
	assertEcho(t, c, "socks by name")
}

func TestTunnelHTTPConnectListener(t *testing.T) {
	p := newTestPair(t, []ListenerIn{{Kind: "http", BindPort: 0}})
	waitHandshake(t, p.client)

	lns := p.client.listenerList()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", lns[0].BindPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the http proxy: %v", err)
	}
	defer c.Close()

	fmt.Fprintf(c, "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", serverIP, echoPort, serverIP)
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status = %q", status)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	assertEchoReader(t, c, br, "http connect")
}

func TestTunnelHTTPConnectRefusesNonConnect(t *testing.T) {
	p := newTestPair(t, []ListenerIn{{Kind: "http", BindPort: 0}})
	lns := p.client.listenerList()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", lns[0].BindPort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(line, "501") {
		t.Fatalf("status = %q, want 501", line)
	}
}

func TestTunnelForwardOpenAndClose(t *testing.T) {
	p := newTestPair(t, nil)
	waitHandshake(t, p.client)

	res, err := p.client.openForward("fwd-1", "", 0, serverIP, echoPort)
	if err != nil {
		t.Fatalf("openForward: %v", err)
	}
	if res.ListenPort == 0 {
		t.Fatal("openForward returned port 0")
	}
	if res.BindHost != "127.0.0.1" {
		t.Fatalf("bindHost = %q, want the loopback default", res.BindHost)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", res.ListenPort)
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	assertEcho(t, c, "ephemeral forward")
	c.Close()

	if !p.client.closeForward("fwd-1") {
		t.Fatal("closeForward did not find the forward")
	}
	if p.client.closeForward("fwd-1") {
		t.Fatal("closeForward found the forward twice")
	}
	// The listener is gone, so a new connection must be refused.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c2, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			return
		}
		c2.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the port is still accepting after closeForward")
}

// E24: the message must name the port, because "port in use" without the
// number is a support ticket.
func TestBindPortInUseIsClassified(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	_, err = bindLocal("127.0.0.1", port)
	if err == nil {
		t.Fatal("expected the second bind to fail")
	}
	var ce *codedError
	if !asCoded(err, &ce) || ce.code != ErrPortInUse {
		t.Fatalf("want port-in-use, got %v", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(port)) {
		t.Fatalf("message does not name the port: %v", err)
	}
}

// E25: a non-loopback bind host is allowed but reported back verbatim, so the
// TypeScript side can warn that the proxy is reachable from the LAN. Silently
// rewriting it to 127.0.0.1 would be worse: the user would think the setting
// took effect.
func TestBindHostIsEchoedVerbatim(t *testing.T) {
	p := newTestPair(t, nil)
	out, err := p.client.addListener(ListenerIn{Kind: "socks5", BindHost: "0.0.0.0", BindPort: 0})
	if err != nil {
		t.Fatalf("bind 0.0.0.0: %v", err)
	}
	if out.BindHost != "0.0.0.0" {
		t.Fatalf("bindHost = %q, want it reported back as asked", out.BindHost)
	}
	if out.BindPort == 0 {
		t.Fatal("bindPort 0 was not resolved to the actual port")
	}
}

// The teardown contract: when closeAll returns, the ports are free and no
// goroutine is still relaying. A wg.down immediately followed by a wg.up on
// the same ports has to work.
func TestCloseAllReleasesPortsAndConnections(t *testing.T) {
	p := newTestPair(t, []ListenerIn{{Kind: "forward", BindPort: 0, TargetHost: serverIP, TargetPort: echoPort}})
	waitHandshake(t, p.client)

	lns := p.client.listenerList()
	port := lns[0].BindPort

	// Hold a live relayed connection open across the teardown. Without the
	// cancellable relay this is exactly the goroutine that leaks.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	assertEcho(t, c, "still open")

	done := make(chan struct{})
	go func() { p.client.closeAll(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("closeAll did not return; a goroutine is stuck")
	}

	// The relayed connection must have been closed from our side.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the relayed connection survived closeAll")
	}
	c.Close()

	// And the port must be rebindable straight away.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("port %d was not released: %v", port, err)
	}
	ln.Close()

	// Idempotent: shutdown, SIGTERM and stdin EOF all race to call this.
	p.client.closeAll()
}

// The parent learns about state from unsolicited wg.state events, so the
// first one has to actually fire — seeding t.state to "starting" would make
// setState treat it as "no change" and swallow it.
func TestTunnelEmitsInitialStartingState(t *testing.T) {
	var w syncBuf
	out := NewWriter(&w)

	priv, _ := genKeypair(t)
	_, pub := genKeypair(t)
	tun, err := newTunnel(context.Background(), out, &UpParams{
		TunnelID: "vpn-state",
		Iface:    IfaceParams{PrivateKey: priv, Addresses: []string{"10.9.0.2/32"}},
		Peers:    []PeerParams{{PublicKey: pub, Endpoint: "127.0.0.1:1", AllowedIPs: []string{"10.9.0.0/24"}}},
	})
	if err != nil {
		t.Fatalf("newTunnel: %v", err)
	}
	defer tun.closeAll()

	tun.setState("starting", "", "", "")
	if !strings.Contains(w.String(), `"state":"starting"`) {
		t.Fatalf("no starting event was emitted:\n%s", w.String())
	}

	// A repeat of the same state is suppressed: the parent coalesces status
	// pushes at 1 Hz and an identical event every poll is pure noise.
	before := len(strings.Split(w.String(), "\n"))
	tun.setState("starting", "", "", "")
	if after := len(strings.Split(w.String(), "\n")); after != before {
		t.Fatal("an unchanged state was emitted again")
	}
}

func TestTunnelStatsAfterCloseIsAnError(t *testing.T) {
	p := newTestPair(t, nil)
	p.client.closeAll()
	if _, err := p.client.stats(); err == nil {
		t.Fatal("stats on a closed tunnel should fail rather than return zeros")
	}
}

// ------------------------------------------------------------- helpers

func asCoded(err error, target **codedError) bool {
	for err != nil {
		if ce, ok := err.(*codedError); ok {
			*target = ce
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// socksConnect performs a full SOCKS5 CONNECT against a local listener and
// returns the connection positioned at the start of the tunnelled stream.
func socksConnect(t *testing.T, port int, atyp byte, host string, dstPort int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var ack [2]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if ack[0] != 0x05 || ack[1] != 0x00 {
		t.Fatalf("greeting reply = %#v", ack)
	}

	req := []byte{0x05, 0x01, 0x00, atyp}
	switch atyp {
	case atypIPv4:
		ip := net.ParseIP(host).To4()
		req = append(req, ip...)
	case atypDomain:
		req = append(req, byte(len(host)))
		req = append(req, host...)
	default:
		t.Fatalf("unsupported atyp in the test helper: %#x", atyp)
	}
	req = append(req, byte(dstPort>>8), byte(dstPort))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("connect request: %v", err)
	}

	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if head[1] != repSuccess {
		t.Fatalf("SOCKS5 replied REP=%#x", head[1])
	}
	switch head[3] {
	case atypIPv4:
		io.ReadFull(c, make([]byte, 4+2))
	case atypIPv6:
		io.ReadFull(c, make([]byte, 16+2))
	default:
		t.Fatalf("reply atyp = %#x", head[3])
	}
	_ = c.SetDeadline(time.Time{})
	return c
}

func assertEcho(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	assertEchoReader(t, c, bufio.NewReader(c), msg)
}

func assertEchoReader(t *testing.T, c net.Conn, br *bufio.Reader, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got, want := string(buf), strings.ToUpper(msg); got != want {
		t.Fatalf("echo = %q, want %q", got, want)
	}
}

// A wg.up must never be able to put a key on the wire, whatever goes wrong.
// This drives the real dispatcher with a deliberately broken key and asserts
// on the bytes that would have reached the parent.
func TestWgUpFailureNeverEchoesTheKey(t *testing.T) {
	var out strings.Builder
	s := &Server{
		out:      NewWriter(&out),
		tunnels:  map[string]*Tunnel{},
		starting: map[string]bool{},
		forwards: map[string]string{},
		stopped:  make(chan struct{}),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.cancel()

	// 25 bytes: valid base64, wrong length, so keyToHex rejects it after
	// decoding — the path most likely to want to quote the input back.
	const badKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGA=="
	params, _ := json.Marshal(UpParams{
		TunnelID: "vpn-leak",
		Iface:    IfaceParams{PrivateKey: badKey, Addresses: []string{"10.0.0.2/32"}},
		Peers:    []PeerParams{{PublicKey: tvPubB64, Endpoint: "203.0.113.9:51820", AllowedIPs: []string{"0.0.0.0/0"}}},
	})
	s.dispatch(&Request{ID: "1", Method: "wg.up", Params: params})

	// Nothing on the pipe may carry the key — not the response, not a log
	// event the device emitted while it was being torn down.
	all := out.String()
	if strings.Contains(all, badKey) {
		t.Fatalf("the output echoed the private key: %s", all)
	}

	var resp *Response
	for _, line := range strings.Split(strings.TrimRight(all, "\n"), "\n") {
		var r Response
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("output line is not JSON: %v (%q)", err, line)
		}
		if r.ID == "1" {
			resp = &r
		}
	}
	if resp == nil {
		t.Fatalf("no response for the request:\n%s", all)
	}
	if resp.OK || resp.Error == nil || resp.Error.Code != ErrConfigInvalid {
		t.Fatalf("response = %+v", resp)
	}
}
