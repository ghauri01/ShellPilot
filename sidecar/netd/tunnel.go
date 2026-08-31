package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultMTU = 1420
	// Matches WG_HANDSHAKE_STALE_SEC in src/shared/vpn.ts. WireGuard rekeys
	// well inside this whenever anything is flowing, so a handshake older
	// than it means up-but-not-passing-traffic.
	handshakeStaleSec = 180
	// How long to wait for a first handshake before saying so. The parent
	// applies its own policy; this only drives the unsolicited state event.
	firstHandshakeGrace = 30 * time.Second
	dialTimeout         = 30 * time.Second
	// Every relay direction gets one of these and no more. A per-connection
	// fixed buffer is what keeps memory flat under load (E58).
	relayBufSize = 32 * 1024
)

// ------------------------------------------------------------- redaction

// A WireGuard key is 32 bytes. Base64 of that is 44 chars ending in one of a
// fixed final alphabet; hex is 64 chars. Private, public and preshared keys
// are indistinguishable by shape, so all three are scrubbed. Redacting a
// public key costs a support ticket; leaking a private one costs the tunnel.
var (
	// The 43rd character of a 32-byte base64 value encodes only the low nibble
	// of the last byte shifted left by two, so it is one of AEIMQUYcgkosw048.
	// The three digits are easy to omit and doing so leaves ~19% of real keys
	// unredacted, which is the whole point of this last line of defence.
	//
	// \b is deliberately not used: a base64 key can start with + or /, which
	// are not word characters, so after a space there is no word boundary and
	// the match silently fails for 2 keys in 64. Go has no lookbehind, so the
	// preceding character is captured and written back instead.
	reKeyB64 = regexp.MustCompile(`(^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)([^A-Za-z0-9+/=]|$)`)
	reKeyHex = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
)

const placeholder = "[redacted]"

// redact runs over every string that leaves this process: log events, error
// messages, event payloads. It is the last line of defence, not the first —
// the first is simply never putting a key in a string.
func redact(s string) string {
	// Repeated until it stops changing: adjacent keys share the single
	// character between them, so one pass consumes the separator and skips the
	// second key.
	for {
		next := reKeyB64.ReplaceAllString(s, "${1}"+placeholder+"${3}")
		if next == s {
			break
		}
		s = next
	}
	s = reKeyHex.ReplaceAllString(s, placeholder)
	return s
}

// ------------------------------------------------------------------ keys

// keyToHex converts a base64 WireGuard key to the lowercase hex the UAPI
// wants. The UAPI is hex-only; handing it base64 produces a confusing
// "invalid hex" from deep inside the device and no hint about why.
func keyToHex(b64 string, what string) (string, error) {
	t := strings.TrimSpace(b64)
	if t == "" {
		return "", codedf(ErrConfigInvalid, "%s is empty", what)
	}
	raw, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		// Deliberately does not echo the input: it might be the private key.
		return "", codedf(ErrConfigInvalid, "%s is not valid base64", what)
	}
	if len(raw) != 32 {
		return "", codedf(ErrConfigInvalid, "%s decodes to %d bytes, expected 32", what, len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// ------------------------------------------------------------------ uapi

// buildUAPI renders the cross-platform WireGuard configuration protocol
// string for dev.IpcSet. Pure: no I/O, no resolution, no clock. Endpoints
// must already be literal ip:port — resolveEndpoints does that beforehand so
// a DNS failure is reported as `dns-failure` rather than surfacing as an
// opaque device error.
func buildUAPI(p *UpParams) (string, error) {
	privHex, err := keyToHex(p.Iface.PrivateKey, "interface private key")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if p.Iface.ListenPort > 0 {
		if p.Iface.ListenPort > 65535 {
			return "", codedf(ErrConfigInvalid, "listenPort %d is out of range", p.Iface.ListenPort)
		}
		fmt.Fprintf(&b, "listen_port=%d\n", p.Iface.ListenPort)
	}
	// Always authoritative: netd owns the device, so a wg.up replaces rather
	// than merges. Merging would make a re-up with a removed peer a no-op.
	b.WriteString("replace_peers=true\n")

	if len(p.Peers) == 0 {
		return "", codedf(ErrConfigInvalid, "at least one peer is required")
	}
	for i, peer := range p.Peers {
		pubHex, err := keyToHex(peer.PublicKey, fmt.Sprintf("peers[%d].publicKey", i))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "public_key=%s\n", pubHex)
		if strings.TrimSpace(peer.PresharedKey) != "" {
			pskHex, err := keyToHex(peer.PresharedKey, fmt.Sprintf("peers[%d].presharedKey", i))
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
		}
		if ep := strings.TrimSpace(peer.Endpoint); ep != "" {
			if _, _, err := net.SplitHostPort(ep); err != nil {
				return "", codedf(ErrConfigInvalid, "peers[%d].endpoint %q is not host:port", i, ep)
			}
			fmt.Fprintf(&b, "endpoint=%s\n", ep)
		}
		if peer.PersistentKeepalive > 0 {
			if peer.PersistentKeepalive > 65535 {
				return "", codedf(ErrConfigInvalid, "peers[%d].persistentKeepalive %d is out of range", i, peer.PersistentKeepalive)
			}
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}
		// E17: 0.0.0.0/0 is not special-cased. In userspace there is no route
		// table to hijack — the prefix only tells the device which peer to
		// send a packet to, and a single-peer tunnel with /0 is the normal,
		// correct configuration.
		b.WriteString("replace_allowed_ips=true\n")
		for j, a := range peer.AllowedIPs {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(a))
			if err != nil {
				return "", codedf(ErrConfigInvalid, "peers[%d].allowedIps[%d] %q is not a CIDR", i, j, a)
			}
			fmt.Fprintf(&b, "allowed_ip=%s\n", pfx.String())
		}
	}
	return b.String(), nil
}

// ----------------------------------------------------------- ipcGet parse

type ipcSnapshot struct {
	ListenPort        int
	Peers             int
	RxBytes           int64
	TxBytes           int64
	LastHandshakeSec  int64
	LastHandshakeNsec int64
	// Endpoint of the peer with the newest handshake, falling back to the
	// first peer that has one at all.
	Endpoint string
}

// parseIPCGet reads the get-operation response. rx/tx are summed across peers
// (a multi-peer tunnel's traffic is the tunnel's traffic) and the newest
// handshake wins, because "is this tunnel alive" is answered by the best peer,
// not the worst.
//
// dev.IpcGet() does not append the `errno=` line — that is added by the UAPI
// socket handler — but the plan documents the response as errno-terminated
// and a fixture may well include it. Handle both.
func parseIPCGet(s string) (*ipcSnapshot, error) {
	snap := &ipcSnapshot{}
	var (
		inPeer       bool
		peerEndpoint string
		peerSec      int64
		peerNsec     int64
		bestSec      int64 = -1
		fallbackEP   string
	)
	flushPeer := func() {
		if !inPeer {
			return
		}
		snap.Peers++
		if peerSec > bestSec {
			bestSec = peerSec
			snap.LastHandshakeSec = peerSec
			snap.LastHandshakeNsec = peerNsec
			if peerEndpoint != "" {
				snap.Endpoint = peerEndpoint
			}
		}
		if fallbackEP == "" && peerEndpoint != "" {
			fallbackEP = peerEndpoint
		}
		peerEndpoint, peerSec, peerNsec = "", 0, 0
	}

	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "errno":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, codedf(ErrInternal, "device returned an unparseable errno %q", v)
			}
			if n != 0 {
				return nil, codedf(ErrInternal, "device get failed with errno %d", n)
			}
		case "listen_port":
			snap.ListenPort, _ = strconv.Atoi(v)
		case "public_key":
			// Starts a new peer block; everything after belongs to it.
			flushPeer()
			inPeer = true
		case "endpoint":
			if inPeer {
				peerEndpoint = v
			}
		case "last_handshake_time_sec":
			if inPeer {
				peerSec, _ = strconv.ParseInt(v, 10, 64)
			}
		case "last_handshake_time_nsec":
			if inPeer {
				peerNsec, _ = strconv.ParseInt(v, 10, 64)
			}
		case "rx_bytes":
			if inPeer {
				n, _ := strconv.ParseInt(v, 10, 64)
				snap.RxBytes += n
			}
		case "tx_bytes":
			if inPeer {
				n, _ := strconv.ParseInt(v, 10, 64)
				snap.TxBytes += n
			}
		}
	}
	flushPeer()
	if snap.Endpoint == "" {
		snap.Endpoint = fallbackEP
	}
	// A negative handshake would mean a corrupt device response; clamp rather
	// than hand the parent something it has to defend against (E63).
	if snap.LastHandshakeSec < 0 {
		snap.LastHandshakeSec = 0
		snap.LastHandshakeNsec = 0
	}
	return snap, nil
}

// ---------------------------------------------------------------- tunnel

type boundListener struct {
	out ListenerOut
	ln  net.Listener
	// Non-empty only for listeners created by wg.forward.open, which are
	// closeable individually as well as with the tunnel.
	forwardID string
}

// Tunnel owns one netstack device and every listener pointing into it.
// Everything it starts is parented to ctx, so cancel() plus wg.Wait() is a
// complete teardown with no goroutine left behind.
type Tunnel struct {
	id     string
	out    *Writer
	dev    *device.Device
	tundev tun.Device
	tnet   *netstack.Net

	assignedIP string
	// System mode only: the name the kernel gave the real TUN device. Empty
	// in userspace mode, where there is no interface.
	ifaceName string
	// The endpoint as configured, used in the handshake-timeout message.
	configuredEP string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	listeners []*boundListener
	state     string
	closed    bool

	upAt time.Time
}

// newTunnel brings up a userspace WireGuard device. It does not wait for a
// handshake: the caller gets its listeners immediately and learns about the
// handshake from `wg.state` events and wg.stats. Blocking wg.up on a
// handshake would make a captive-portal network (E22) look like a hang.
func newTunnel(parent context.Context, out *Writer, p *UpParams) (t *Tunnel, err error) {
	addrs, err := parseAddrs(p.Iface.Addresses)
	if err != nil {
		return nil, err
	}
	dnsAddrs, err := parseDNS(p.Iface.DNS)
	if err != nil {
		return nil, err
	}
	mtu := p.Iface.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 576 || mtu > 9000 {
		return nil, codedf(ErrConfigInvalid, "mtu %d is outside the supported 576-9000 range", mtu)
	}

	tundev, tnet, err := netstack.CreateNetTUN(addrs, dnsAddrs, mtu)
	if err != nil {
		return nil, wrapCoded(ErrInternal, err, "could not create the userspace network stack")
	}
	// Everything from here on is torn down through closeAll, which is
	// idempotent and closes the tun via the device. Closing tundev separately
	// on an error path would be a double close — netstack's Close closes an
	// internal channel unguarded and panics the second time.

	t = newTunnelShell(parent, out, p, tundev, tnet)
	if len(addrs) > 0 {
		t.assignedIP = addrs[0].String()
	}
	if err := t.startDevice(p); err != nil {
		t.closeAll()
		return nil, err
	}
	return t, nil
}

// newTunnelShell wraps an already-created tun device in the bookkeeping every
// tunnel needs, without starting anything.
//
// Split out so privileged.go's real-TUN path and the netstack path above share
// one definition of what a Tunnel is. `tnet` is nil for a real device: there
// is no in-process stack to dial through, which is also why system mode has no
// listeners.
func newTunnelShell(parent context.Context, out *Writer, p *UpParams, tundev tun.Device, tnet *netstack.Net) *Tunnel {
	ctx, cancel := context.WithCancel(parent)
	return &Tunnel{
		id:     p.TunnelID,
		out:    out,
		tundev: tundev,
		tnet:   tnet,
		ctx:    ctx,
		cancel: cancel,
		// Left empty on purpose so the first setState("starting") is a real
		// change and actually emits. Seeding it here would swallow the one
		// event that tells the parent the tunnel exists.
		state:        "",
		upAt:         time.Now(),
		configuredEP: firstEndpoint(p.Peers),
	}
}

// startDevice attaches wireguard-go to the tun, applies the UAPI and brings the
// device up. The caller closes the tunnel on failure; every error here is
// already coded.
func (t *Tunnel) startDevice(p *UpParams) error {
	t.dev = device.NewDevice(t.tundev, conn.NewDefaultBind(), deviceLogger(t.out, p.TunnelID, p.LogLevel))

	uapi, err := buildUAPI(p)
	if err != nil {
		return err
	}
	if e := t.dev.IpcSet(uapi); e != nil {
		// IpcSet errors name the failing key (`failed to set private_key`)
		// but never its value, and toWireError redacts on the way out anyway.
		return wrapCoded(ErrConfigInvalid, e, "the device rejected the configuration")
	}
	if e := t.dev.Up(); e != nil {
		return wrapCoded(ErrInternal, e, "could not bring the device up")
	}
	return nil
}

// deviceLogger routes wireguard-go's own logging into `log` events.
//
// Verbose output is off unless the caller asked for it: the device emits a
// line per worker goroutine at startup, which is 60-odd events per wg.up
// competing with the responses on the same pipe. Errors always get through —
// those are the ones that explain a failure.
//
// Every line is redacted on the way out by Writer.Log. The device already
// truncates peer keys to `peer(abcd…wxyz)`, but "already" is not a guarantee
// worth relying on for key material.
func deviceLogger(out *Writer, tunnelID, level string) *device.Logger {
	noop := func(string, ...interface{}) {}
	l := &device.Logger{Verbosef: noop, Errorf: noop}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "silent":
		return l
	case "debug", "verbose":
		l.Verbosef = func(f string, a ...interface{}) { out.Log("debug", tunnelID, fmt.Sprintf(f, a...)) }
	}
	l.Errorf = func(f string, a ...interface{}) { out.Log("error", tunnelID, fmt.Sprintf(f, a...)) }
	return l
}

func firstEndpoint(peers []PeerParams) string {
	for _, p := range peers {
		if strings.TrimSpace(p.Endpoint) != "" {
			return strings.TrimSpace(p.Endpoint)
		}
	}
	return ""
}

func parseAddrs(in []string) ([]netip.Addr, error) {
	if len(in) == 0 {
		return nil, codedf(ErrConfigInvalid, "at least one interface address is required")
	}
	out := make([]netip.Addr, 0, len(in))
	for i, s := range in {
		// Accept both CIDR and a bare address. netstack only wants the
		// address: there is no subnet to attach it to, because there is no
		// route table.
		t := strings.TrimSpace(s)
		if pfx, err := netip.ParsePrefix(t); err == nil {
			out = append(out, pfx.Addr())
			continue
		}
		a, err := netip.ParseAddr(t)
		if err != nil {
			return nil, codedf(ErrConfigInvalid, "addresses[%d] %q is not an IP or CIDR", i, s)
		}
		out = append(out, a)
	}
	return out, nil
}

func parseDNS(in []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(in))
	for i, s := range in {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, codedf(ErrConfigInvalid, "dns[%d] %q is not an IP address", i, s)
		}
		out = append(out, a)
	}
	return out, nil
}

// resolveEndpoints turns any hostname endpoint into ip:port before the UAPI
// sees it. This lookup uses the HOST resolver by design: the peer endpoint is
// on the far side of the tunnel's outside, so it cannot be resolved through
// the tunnel that has not been established yet. Doing it here rather than
// inside IpcSet buys a specific `dns-failure` instead of a generic device
// error, which is the difference between "check your DNS" and "something
// went wrong".
func resolveEndpoints(ctx context.Context, peers []PeerParams) ([]PeerParams, error) {
	out := make([]PeerParams, len(peers))
	copy(out, peers)
	var r net.Resolver
	for i := range out {
		ep := strings.TrimSpace(out[i].Endpoint)
		if ep == "" {
			continue
		}
		host, port, err := net.SplitHostPort(ep)
		if err != nil {
			return nil, codedf(ErrConfigInvalid, "peers[%d].endpoint %q is not host:port", i, ep)
		}
		if _, err := netip.ParseAddr(host); err == nil {
			out[i].Endpoint = net.JoinHostPort(host, port)
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ips, err := r.LookupNetIP(lctx, "ip", host)
		cancel()
		if err != nil || len(ips) == 0 {
			return nil, codedf(ErrDNSFailure, "could not resolve the peer endpoint %q", ep)
		}
		out[i].Endpoint = net.JoinHostPort(ips[0].Unmap().String(), port)
	}
	return out, nil
}

// ------------------------------------------------------------ tunnel i/o

// dial opens a TCP connection through the tunnel.
//
// Hostnames are resolved with tnet.LookupContextHost, which speaks DNS to the
// servers configured on the interface, over the tunnel. This is the whole
// point: a SOCKS5 client that hands us a domain name must not cause a lookup
// on the host resolver, because that lookup would travel in the clear and
// leak exactly the thing the tunnel exists to hide. net.Dial here would be a
// DNS leak, not a shortcut.
func (t *Tunnel) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if port <= 0 || port > 65535 {
		return nil, codedf(ErrConfigInvalid, "port %d is out of range", port)
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	if a, err := netip.ParseAddr(host); err == nil {
		return t.tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(a.Unmap(), uint16(port)))
	}
	ips, err := t.tnet.LookupContextHost(ctx, host)
	if err != nil {
		return nil, wrapCoded(ErrDNSFailure, err, "could not resolve %q inside the tunnel", host)
	}
	var last error
	for _, s := range ips {
		a, perr := netip.ParseAddr(s)
		if perr != nil {
			continue
		}
		c, derr := t.tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(a.Unmap(), uint16(port)))
		if derr == nil {
			return c, nil
		}
		last = derr
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("no usable address")
	}
	return nil, wrapCoded(ErrNetworkUnreachable, last, "could not connect to %s:%d through the tunnel", host, port)
}

type closeWriter interface{ CloseWrite() error }

// relay copies in both directions until either side finishes or ctx is
// cancelled, then guarantees both conns are closed.
//
// The cancel-and-close pair is what makes wg.down deterministic: without it a
// blocked io.Copy on a half-open connection keeps a goroutine (and the
// tunnel's WaitGroup) alive indefinitely. Buffers are fixed size, so a fast
// producer and a slow consumer cost 32 KiB per direction, not a growing
// backlog (E58).
func relay(ctx context.Context, a, b net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = a.Close()
		_ = b.Close()
		close(closed)
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, relayBufSize)
		_, _ = copyBuffer(dst, src, buf)
		// Half-close so the peer sees EOF on this direction while the other
		// direction drains. Without it, a protocol that expects a FIN (an
		// HTTP/1.0 response body, `git upload-pack`) hangs until a timeout.
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			cancel()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	cancel()
	<-closed
}

// copyBuffer is io.CopyBuffer with the ReadFrom/WriteTo fast paths skipped, so
// the fixed buffer is genuinely the only allocation. gonet.TCPConn implements
// WriterTo, and letting it take over would hand buffer sizing to netstack.
func copyBuffer(dst net.Conn, src net.Conn, buf []byte) (int64, error) {
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
			if nw != nr {
				return written, errors.New("short write")
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return written, nil
			}
			return written, rerr
		}
	}
}

// serve runs an accept loop parented to the tunnel. Both the loop and every
// connection it spawns are tracked on t.wg, so closeAll can wait them out.
func (t *Tunnel) serve(ln net.Listener, handle func(context.Context, net.Conn)) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		<-t.ctx.Done()
		_ = ln.Close()
	}()
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		var fails int
		for {
			c, err := ln.Accept()
			if err != nil {
				if t.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				// A transient accept failure (EMFILE under load) must not
				// kill the listener, but it must not spin either.
				fails++
				if fails > 20 {
					t.out.Log("error", t.id, "listener stopped after repeated accept failures: "+err.Error())
					return
				}
				select {
				case <-time.After(time.Duration(fails) * 20 * time.Millisecond):
				case <-t.ctx.Done():
					return
				}
				continue
			}
			fails = 0
			t.wg.Add(1)
			go func(c net.Conn) {
				defer t.wg.Done()
				defer c.Close()
				handle(t.ctx, c)
			}(c)
		}
	}()
}

// bindLocal opens the host-side listener. Port 0 is supported and the caller
// always learns the real port from the returned listener.
func bindLocal(host string, port int) (net.Listener, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	if port < 0 || port > 65535 {
		return nil, codedf(ErrConfigInvalid, "bindPort %d is out of range", port)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, classifyBindError(err, host, port)
	}
	return ln, nil
}

// classifyBindError maps the two failures a user can actually fix onto codes
// the TS side has "how to fix" copy for (E24, E26). The wording mirrors
// src/main/services/tunnel.ts:86-94 so the two subsystems do not disagree
// about what a busy port sounds like.
func classifyBindError(err error, host string, port int) error {
	var se *net.OpError
	msg := err.Error()
	if errors.As(err, &se) && se.Err != nil {
		msg = se.Err.Error()
	}
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "address already in use"),
		strings.Contains(low, "only one usage of each socket address"):
		return codedf(ErrPortInUse, "Port %d on %s is already in use.", port, host)
	case strings.Contains(low, "permission denied"),
		strings.Contains(low, "access permissions"):
		return codedf(ErrPermissionDenied,
			"Not allowed to bind port %d (ports below 1024 need elevated rights).", port)
	}
	return wrapCoded(ErrInternal, err, "could not bind %s:%d", host, port)
}

// addListener starts one configured listener and records it for teardown.
func (t *Tunnel) addListener(in ListenerIn) (ListenerOut, error) {
	bindHost := strings.TrimSpace(in.BindHost)
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	ln, err := bindLocal(bindHost, in.BindPort)
	if err != nil {
		return ListenerOut{}, err
	}
	actual := ln.Addr().(*net.TCPAddr).Port

	// E25: the bind host is echoed back exactly as asked, never normalised.
	// If the caller said 0.0.0.0, the TS side must see 0.0.0.0 so it can warn
	// that the proxy is reachable from the LAN.
	out := ListenerOut{Kind: in.Kind, BindHost: bindHost, BindPort: actual}

	switch in.Kind {
	case "socks5":
		t.serve(ln, func(ctx context.Context, c net.Conn) { serveSocks5(ctx, t, c) })
	case "http":
		t.serve(ln, func(ctx context.Context, c net.Conn) { serveHTTPConnect(ctx, t, c) })
	case "forward":
		host := strings.TrimSpace(in.TargetHost)
		if host == "" || in.TargetPort <= 0 || in.TargetPort > 65535 {
			_ = ln.Close()
			return ListenerOut{}, codedf(ErrConfigInvalid,
				"a forward listener needs a targetHost and a targetPort in 1-65535")
		}
		out.TargetHost, out.TargetPort = host, in.TargetPort
		t.serve(ln, func(ctx context.Context, c net.Conn) { serveForward(ctx, t, c, host, in.TargetPort) })
	default:
		_ = ln.Close()
		return ListenerOut{}, codedf(ErrUnsupported, "listener kind %q is not supported", in.Kind)
	}

	t.mu.Lock()
	t.listeners = append(t.listeners, &boundListener{out: out, ln: ln})
	t.mu.Unlock()
	return out, nil
}

// openForward is the ephemeral-forward path used by wg.forward.open. Same
// machinery as a configured `forward` listener, but individually closeable.
func (t *Tunnel) openForward(forwardID, bindHost string, bindPort int, host string, port int) (ForwardOpenResult, error) {
	if strings.TrimSpace(host) == "" || port <= 0 || port > 65535 {
		return ForwardOpenResult{}, codedf(ErrConfigInvalid, "a forward needs a host and a port in 1-65535")
	}
	if strings.TrimSpace(bindHost) == "" {
		bindHost = "127.0.0.1"
	}
	ln, err := bindLocal(bindHost, bindPort)
	if err != nil {
		return ForwardOpenResult{}, err
	}
	actual := ln.Addr().(*net.TCPAddr).Port
	t.serve(ln, func(ctx context.Context, c net.Conn) { serveForward(ctx, t, c, host, port) })

	t.mu.Lock()
	t.listeners = append(t.listeners, &boundListener{
		out: ListenerOut{
			Kind: "forward", BindHost: bindHost, BindPort: actual,
			TargetHost: host, TargetPort: port,
		},
		ln:        ln,
		forwardID: forwardID,
	})
	t.mu.Unlock()

	return ForwardOpenResult{ForwardID: forwardID, BindHost: bindHost, ListenPort: actual}, nil
}

// closeForward drops one ephemeral forward. Connections already relaying
// through it stay up until they end on their own or the tunnel goes down —
// closing the listener stops new connections, which is what "close the
// forward" means to the caller.
func (t *Tunnel) closeForward(forwardID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, bl := range t.listeners {
		if bl.forwardID == forwardID {
			_ = bl.ln.Close()
			t.listeners = append(t.listeners[:i], t.listeners[i+1:]...)
			return true
		}
	}
	return false
}

func (t *Tunnel) listenerList() []ListenerOut {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ListenerOut, 0, len(t.listeners))
	for _, bl := range t.listeners {
		out = append(out, bl.out)
	}
	return out
}

// stats samples the device.
func (t *Tunnel) stats() (*StatsResult, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, codedf(ErrConfigInvalid, "tunnel %q is not running", t.id)
	}
	raw, err := t.dev.IpcGet()
	if err != nil {
		return nil, wrapCoded(ErrInternal, err, "could not read device state")
	}
	snap, err := parseIPCGet(raw)
	if err != nil {
		return nil, err
	}
	return &StatsResult{
		TunnelID:             t.id,
		RxBytes:              snap.RxBytes,
		TxBytes:              snap.TxBytes,
		LastHandshakeUnixSec: snap.LastHandshakeSec,
		RemoteEndpoint:       snap.Endpoint,
		AssignedIP:           t.assignedIP,
		Peers:                snap.Peers,
		SampledAt:            time.Now().UnixMilli(),
	}, nil
}

// setState emits a wg.state event, but only on an actual change. The parent
// coalesces status pushes at 1 Hz; sending it an identical state every poll
// would be pure noise on the wire.
func (t *Tunnel) setState(state string, code string, msg string, endpoint string) {
	t.mu.Lock()
	if t.closed || t.state == state {
		t.mu.Unlock()
		return
	}
	t.state = state
	t.mu.Unlock()
	t.out.Emit("wg.state", &StateData{
		TunnelID:   t.id,
		State:      state,
		AssignedIP: t.assignedIP,
		Endpoint:   endpoint,
		ErrorCode:  code,
		Error:      msg,
	})
}

// monitor watches the handshake and reports the up/degraded/no-handshake
// distinction as it changes. The parent also polls wg.stats on its own
// cadence; this exists so a drop is noticed even when nobody is looking at
// the Tunnels view.
func (t *Tunnel) monitor() {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		// Fast while we are waiting for the first handshake, slow afterwards:
		// WireGuard rekeys no more often than every ~120 s, so polling
		// IpcGet at 1 Hz forever is waste (§5.4).
		interval := time.Second
		timeoutReported := false
		for {
			select {
			case <-t.ctx.Done():
				return
			case <-time.After(interval):
			}
			s, err := t.stats()
			if err != nil {
				continue
			}
			since := time.Since(t.upAt)
			if since > firstHandshakeGrace && interval == time.Second {
				interval = 5 * time.Second
			}
			switch {
			case s.LastHandshakeUnixSec == 0:
				if since >= firstHandshakeGrace && !timeoutReported {
					timeoutReported = true
					where := t.configuredEP
					port := ""
					if _, p, err := net.SplitHostPort(where); err == nil {
						port = p
					}
					t.setState("error", ErrHandshakeTimeout, fmt.Sprintf(
						"No response from %s. Check the endpoint address and that UDP :%s is not blocked.",
						where, port), s.RemoteEndpoint)
				}
			default:
				// E63: age is computed from the sample we just took, and the
				// absolute value goes to the parent so it can use its own
				// monotonic base. Never let it go negative.
				age := time.Now().Unix() - s.LastHandshakeUnixSec
				if age < 0 {
					age = 0
				}
				if age > handshakeStaleSec {
					t.setState("degraded", "", "", s.RemoteEndpoint)
				} else {
					timeoutReported = false
					t.setState("connected", "", "", s.RemoteEndpoint)
				}
			}
		}
	}()
}

// closeAll tears the tunnel down completely: listeners first so nothing new
// arrives, then the relays via ctx, then the device. It waits for every
// goroutine it started, which is what makes wg.down safe to follow with a
// wg.up on the same ports.
func (t *Tunnel) closeAll() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	lns := t.listeners
	t.listeners = nil
	t.mu.Unlock()

	for _, bl := range lns {
		_ = bl.ln.Close()
	}
	t.cancel()
	t.wg.Wait()

	if t.dev != nil {
		// Device.Close also closes the tun it was given.
		t.dev.Close()
	} else if t.tundev != nil {
		_ = t.tundev.Close()
	}
}
