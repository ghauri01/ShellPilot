package main

// System mode: one real TUN device, created by a process that is root for
// exactly as long as the tunnel lives.
//
// # Nothing is ever installed
//
// There is no setuid bit, no `setcap`, no launchd plist, no systemd unit, no
// Windows service and no privileged helper of any kind. ShellPilot asks the
// operating system for administrator rights once per launch (pkexec/sudo on
// Linux, UAC on Windows) and the rights die with the process. Deleting
// ShellPilot therefore leaves nothing behind that can still become root, which
// is the property an installed helper can never have: an installed helper is a
// permanent root-capable surface maintained by an app that may not even be on
// the machine any more. Do not add one. If a future change appears to need
// one, it needs a different design instead.
//
// # Why a socket rather than stdio
//
// The unprivileged path talks to the sidecar over the child's stdin/stdout.
// An elevated child does not have that: `osascript` on macOS hands the command
// to the security framework, which starts it detached, and Windows' UAC route
// goes through ShellExecute, which has no pipe to redirect. Only Linux's
// pkexec/sudo would keep a pipe. Rather than have three transports, the
// privileged process listens on a unix socket whose path the parent chose, and
// the parent connects to it.
//
// # Authentication is not optional
//
// A root process listening on a socket that anyone can connect to is worse
// than no feature at all: it would turn "run a tunnel" into "reconfigure this
// machine's networking" for every local account. Two things stand in the way,
// and both must hold:
//
//   - The socket lives in a 0700 directory and is itself 0600, so on POSIX no
//     other unprivileged user can even reach it.
//   - The first message on the connection must present a 32-byte nonce that
//     the parent generated and left in a 0600 file, whose path (never its
//     contents — argv is world-readable) was passed on the command line. Wrong
//     nonce, malformed first message, or no first message inside the timeout:
//     the process answers with `permission-denied` and exits non-zero.
//
// Exactly one connection is ever served. The listener is closed as soon as it
// is accepted, so there is no second client and no re-authentication to get
// wrong, and when that connection ends the process shuts down — which is also
// the orphan safety net, the socket equivalent of stdin EOF in userspace mode.
//
// On Windows the filesystem half of that is weaker: `os.Chmod` cannot express
// 0700 there and the socket inherits the directory's ACL. The nonce is
// therefore the load-bearing check on Windows, which is precisely why it
// exists rather than relying on file modes alone.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Exit codes. Distinct so the parent can tell "you asked for something this
// machine cannot do" from "someone tried to talk to a root process".
const (
	exitPrivilegedSetup = 3
	exitPrivilegedAuth  = 4
)

const (
	// 32 bytes, as the plan specifies (§6.1). Carried as 64 hex characters so
	// the file and the wire agree byte for byte with no encoding ambiguity.
	nonceLen = 32
	// How long the elevated process waits for its one client. The parent
	// connects as soon as the socket appears, so this only bounds the case
	// where the parent died between elevating and connecting — a root process
	// nobody is going to talk to must not sit there.
	controlAcceptTimeout = 60 * time.Second
	// How long the first message may take once connected.
	controlAuthTimeout = 10 * time.Second
	// The auth line is 64 hex characters plus framing. Anything larger is not
	// an auth request, and reading it unbounded would be a memory sink an
	// unauthenticated peer controls.
	maxAuthBytes = 4096
	// Unix socket paths are capped by the kernel — 104 bytes on macOS, 108 on
	// Linux — and the failure is an unhelpful "invalid argument" from bind(2).
	maxSocketPath = 100
	// Long enough for `ip`/`netsh` to answer, short enough that a wedged tool
	// cannot hold the tunnel's startup open forever.
	toolTimeout = 15 * time.Second
)

// ----------------------------------------------------------------- lifecycle

// runPrivileged is the whole of --privileged. It returns the process exit code
// and writes nothing to stdout: stdout belongs to the protocol, and in this
// mode the protocol is on the socket.
func runPrivileged(o *options) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "shellpilot-netd: %s\n", err.Error())
		return exitPrivilegedSetup
	}

	nonce, err := loadNonce(o.nonceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellpilot-netd: %s\n", err.Error())
		return exitPrivilegedSetup
	}

	ln, err := listenControl(o.socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellpilot-netd: %s\n", err.Error())
		return exitPrivilegedSetup
	}
	// The socket file is ours to remove: leaving one behind would make the
	// next launch fail to bind and look like a port conflict.
	defer func() { _ = os.Remove(o.socket) }()

	conn, err := acceptOne(ln, controlAcceptTimeout)
	// Closed either way, and closed before the connection is served: one
	// client, ever.
	_ = ln.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellpilot-netd: %s\n", err.Error())
		return exitPrivilegedSetup
	}
	defer conn.Close()

	br := bufio.NewReaderSize(conn, 64*1024)
	out := NewWriter(conn)
	if err := authenticate(conn, br, out, nonce); err != nil {
		// Never says which part was wrong and never echoes what was sent: the
		// only useful audience for a detailed answer here is someone probing.
		fmt.Fprintf(os.Stderr, "shellpilot-netd: %s\n", err.Error())
		return exitPrivilegedAuth
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := newServer(ctx, cancel, out)
	s.privileged = true

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			s.stop()
			// Unblocks readLoop, which is otherwise parked on a socket the
			// parent is not going to write to again.
			_ = conn.Close()
		case <-s.stopped:
		}
	}()

	s.readLoop(br)

	// The connection ended: either the parent asked for `shutdown`, or the
	// parent is gone. Closing the tunnels takes the TUN device with them, and
	// a TUN device that goes away takes every route bound to it with it — so
	// the kernel finishes the cleanup even if the parent never got to revert
	// its netstate snapshot.
	s.stop()
	return 0
}

// requireRoot fails early and legibly rather than letting the first syscall
// produce EPERM from somewhere deep in a library.
func requireRoot() error {
	if runtime.GOOS == "windows" {
		// Windows has no uid, and a token-elevation query would be a second,
		// worse answer to a question creating the adapter answers exactly:
		// without elevation Wintun fails with access-denied, which
		// classifyDeviceError turns into `permission-denied`.
		return nil
	}
	if os.Getuid() != 0 {
		return errors.New(
			"--privileged must run as root; ShellPilot elevates it once per launch and installs nothing")
	}
	return nil
}

// loadNonce reads the shared secret and immediately deletes the file. The
// nonce belongs to one launch; a copy that outlives the launch is a credential
// lying on disk.
func loadNonce(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the nonce file: %w", err)
	}
	_ = os.Remove(path)

	n, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(n) != nonceLen {
		// Deliberately does not quote the contents.
		return nil, fmt.Errorf("the nonce file must hold exactly %d hexadecimal characters", nonceLen*2)
	}
	return n, nil
}

// listenControl binds the control socket, tightening the directory and the
// socket itself on the way.
func listenControl(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("the socket path is %d bytes; the kernel limit is around %d", len(path), maxSocketPath)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("could not create the socket directory: %w", err)
	}
	// The parent creates this directory, so it usually exists already and
	// MkdirAll left its mode alone. Set it explicitly: the whole point is that
	// no other unprivileged account can traverse it.
	_ = os.Chmod(dir, 0o700)

	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			// Refusing to unlink something that is not a socket: this path is
			// attacker-influenced only if the run directory already is, but
			// "root unlinks whatever is at this path" is not a sentence worth
			// having in a privileged process.
			return nil, fmt.Errorf("%s already exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("could not listen on the control socket: %w", err)
	}
	// Best effort by design: on Windows this is close to a no-op and the nonce
	// is what stands between the socket and another local process.
	_ = os.Chmod(path, 0o600)
	return ln, nil
}

// acceptOne waits for the single client, with a deadline.
func acceptOne(ln net.Listener, within time.Duration) (net.Conn, error) {
	type deadliner interface{ SetDeadline(time.Time) error }
	if d, ok := ln.(deadliner); ok {
		_ = d.SetDeadline(time.Now().Add(within))
	}
	conn, err := ln.Accept()
	if err != nil {
		return nil, fmt.Errorf("no client connected within %s", within)
	}
	if d, ok := ln.(deadliner); ok {
		_ = d.SetDeadline(time.Time{})
	}
	return conn, nil
}

// authenticate consumes the first line and decides whether this connection may
// speak to a root process at all.
func authenticate(conn net.Conn, r *bufio.Reader, out *Writer, nonce []byte) error {
	_ = conn.SetReadDeadline(time.Now().Add(controlAuthTimeout))
	line, err := readLimitedLine(r, maxAuthBytes)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return errors.New("the client sent no usable authentication request")
	}

	deny := func(id string, why string) error {
		// One message, one code, whatever went wrong: an unauthenticated peer
		// learns nothing from the difference between "bad JSON" and "bad
		// nonce".
		out.Fail(id, codedf(ErrPermissionDenied, "authentication failed"))
		return errors.New(why)
	}

	var req Request
	if err := json.Unmarshal(bytes.TrimSpace(line), &req); err != nil {
		return deny("", "the first message was not a request")
	}
	if req.Method != "auth" {
		return deny(req.ID, "the first message was not an auth request")
	}
	var p AuthParams
	if len(req.Params) == 0 || json.Unmarshal(req.Params, &p) != nil {
		return deny(req.ID, "the auth request carried no usable params")
	}
	got, derr := hex.DecodeString(strings.TrimSpace(p.Nonce))
	// ConstantTimeCompare returns 0 for differing lengths, so a short or
	// unparseable nonce lands in the same branch as a wrong one.
	if derr != nil || subtle.ConstantTimeCompare(got, nonce) != 1 {
		return deny(req.ID, "the client presented the wrong nonce")
	}

	out.Respond(req.ID, &AuthResult{
		Authenticated: true,
		Privileged:    true,
		Version:       Version,
		BuildSha:      BuildSha,
	})
	return nil
}

// readLimitedLine reads one newline-terminated line, refusing anything longer
// than max. bufio.Reader.ReadBytes would happily buffer whatever an
// unauthenticated peer chose to send.
func readLimitedLine(r *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' {
			return buf, nil
		}
		buf = append(buf, b)
		if len(buf) > max {
			return nil, errors.New("the first line is too long to be an auth request")
		}
	}
}

// --------------------------------------------------------------- system tun

// newSystemTunnel is newTunnel's privileged twin: a real kernel interface
// instead of a gVisor stack. Everything after the device — the UAPI, the
// stats, the handshake monitor, the teardown — is the same code.
func newSystemTunnel(parent context.Context, out *Writer, p *UpParams) (*Tunnel, error) {
	prefixes, err := parseIfacePrefixes(p.Iface.Addresses)
	if err != nil {
		return nil, err
	}
	mtu, err := checkedMTU(p.Iface.MTU)
	if err != nil {
		return nil, err
	}
	requested, err := requestedIfaceName(p.IfaceName)
	if err != nil {
		return nil, err
	}

	dev, err := tun.CreateTUN(requested, mtu)
	if err != nil {
		return nil, classifyDeviceError(err, requested)
	}

	// The name the KERNEL chose, which on macOS is never the one that was
	// asked for (`utun` means "pick a number") and on Linux and Windows can
	// still differ. Routes and DNS are applied against this; assuming the
	// requested name is how system mode silently routes nothing.
	actual, nerr := dev.Name()
	if nerr != nil || strings.TrimSpace(actual) == "" {
		_ = dev.Close()
		return nil, wrapCoded(ErrInternal, nerr, "the tunnel interface did not report its name")
	}

	t := newTunnelShell(parent, out, p, dev, nil)
	t.ifaceName = actual
	if len(prefixes) > 0 {
		t.assignedIP = prefixes[0].Addr().String()
	}

	// wg-quick's order: configure WireGuard first, then give the interface an
	// address and bring the link up, so the device is already processing
	// packets by the time the kernel can hand it any.
	if err := t.startDevice(p); err != nil {
		t.closeAll()
		return nil, err
	}
	if err := configureInterface(actual, prefixes, mtu); err != nil {
		t.closeAll()
		return nil, err
	}
	return t, nil
}

// checkedMTU applies the same bounds newTunnel uses. Duplicated as a named
// helper rather than reached into, because the privileged path has no netstack
// to reject an absurd value later.
func checkedMTU(mtu int) (int, error) {
	if mtu == 0 {
		return defaultMTU, nil
	}
	if mtu < 576 || mtu > 9000 {
		return 0, codedf(ErrConfigInvalid, "mtu %d is outside the supported 576-9000 range", mtu)
	}
	return mtu, nil
}

// parseIfacePrefixes keeps the prefix length, which the userspace path throws
// away. A real interface needs it: `10.0.0.2/32` and `10.0.0.2/24` are
// different statements about what is on-link.
func parseIfacePrefixes(in []string) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, codedf(ErrConfigInvalid, "at least one interface address is required")
	}
	out := make([]netip.Prefix, 0, len(in))
	for i, s := range in {
		t := strings.TrimSpace(s)
		if pfx, err := netip.ParsePrefix(t); err == nil {
			out = append(out, netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()))
			continue
		}
		a, err := netip.ParseAddr(t)
		if err != nil {
			return nil, codedf(ErrConfigInvalid, "addresses[%d] %q is not an IP or CIDR", i, s)
		}
		// A bare address on a real interface means "just me": /32 or /128.
		// Guessing a wider prefix would put a whole subnet on-link on the
		// strength of a missing suffix.
		a = a.Unmap()
		bits := 32
		if a.Is6() {
			bits = 128
		}
		out = append(out, netip.PrefixFrom(a, bits))
	}
	return out, nil
}

// requestedIfaceName validates the name before it becomes an argument to a
// command running as root.
func requestedIfaceName(name string) (string, error) {
	return requestedIfaceNameFor(runtime.GOOS, name)
}

// requestedIfaceNameFor takes the OS as an argument so every platform's rules
// are checkable from any platform. Nothing else calls it with a GOOS that is
// not the running one.
func requestedIfaceNameFor(goos, name string) (string, error) {
	n := strings.TrimSpace(name)
	if goos == "darwin" {
		// The kernel allocates utun numbers; asking for a specific one races
		// every other utun user on the machine. "utun" means "give me the
		// next free one", and dev.Name() reports which that was.
		return "utun", nil
	}
	if n == "" {
		return "", codedf(ErrConfigInvalid, "ifaceName is required in system mode")
	}
	if goos == "windows" {
		// A Wintun adapter name is a display name — it shows up in ncpa.cpl —
		// so spaces are legitimate. Control characters and quotes are not.
		if len(n) > 128 || strings.ContainsAny(n, "\"\r\n\t/\\") {
			return "", codedf(ErrConfigInvalid, "ifaceName %q is not a usable adapter name", n)
		}
		return n, nil
	}
	// Linux: IFNAMSIZ is 16 including the terminator.
	if len(n) > 15 {
		return "", codedf(ErrConfigInvalid, "ifaceName %q is longer than the 15 characters Linux allows", n)
	}
	for _, r := range n {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return "", codedf(ErrConfigInvalid, "ifaceName %q contains characters an interface name cannot have", n)
		}
	}
	return n, nil
}

// classifyDeviceError maps the failures a user can actually do something about
// onto codes the TypeScript side has copy for.
func classifyDeviceError(err error, name string) error {
	return classifyDeviceErrorFor(runtime.GOOS, err, name)
}

// classifyDeviceErrorFor takes the OS as an argument for the same reason
// requestedIfaceNameFor does: the /dev/net/tun message (E06) is the one users
// are most likely to meet and the least likely platform to be developing on.
func classifyDeviceErrorFor(goos string, err error, name string) error {
	msg := strings.ToLower(err.Error())
	missing := errors.Is(err, os.ErrNotExist) ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "no such device")
	denied := errors.Is(err, os.ErrPermission) ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "access is denied")

	// E06. A container or a hardened kernel simply has no /dev/net/tun, and no
	// amount of elevation conjures one — so the answer names the file and
	// points at the mode that does not need it.
	if missing && goos == "linux" {
		return codedf(ErrPermissionDenied,
			"This machine has no /dev/net/tun, so a system-mode tunnel cannot be created on it. "+
				"Containers and some hardened kernels leave it out. "+
				"Switch this profile to userspace mode, which creates no interface at all.")
	}
	if strings.Contains(msg, "wintun") {
		// Wintun ships as a separate driver DLL that ShellPilot does not
		// bundle. Saying so beats "Error loading wintun.dll".
		return codedf(ErrUnsupported,
			"System mode on Windows needs wintun.dll, which this build of ShellPilot does not include. "+
				"Switch this profile to userspace mode, which needs no driver.")
	}
	if denied {
		return codedf(ErrPermissionDenied,
			"Not allowed to create the tunnel interface %q even with administrator rights.", name)
	}
	return wrapCoded(ErrInternal, err, "could not create the tunnel interface %q", name)
}

// ------------------------------------------------------- interface plumbing

// configureInterface gives the device its addresses and brings it up.
//
// This shells out to the operating system's own tools rather than driving
// netlink (Linux) or winipcfg (Windows) from Go, for three reasons. It adds no
// dependency, which keeps the sidecar a pure-Go CGO_ENABLED=0 cross-compile to
// six targets from one machine — the property that makes `scripts/
// build-sidecar.sh` work at all. It is the same mechanism the TypeScript
// routing and DNS managers already use (`ip route`, `netsh`, `scutil`), so
// there is one convention to audit rather than two. And the argument vectors
// are literal `exec` arguments with no shell anywhere, so the injection
// surface a command line usually brings is not present.
//
// The cost is a dependency on iproute2 / netsh being installed, which is
// reported as a coded error rather than a mystery.
func configureInterface(name string, addrs []netip.Prefix, mtu int) error {
	switch runtime.GOOS {
	case "linux":
		return configureLinux(name, addrs)
	case "darwin":
		return configureDarwin(name, addrs)
	case "windows":
		return configureWindows(name, addrs, mtu)
	default:
		return codedf(ErrUnsupported, "system mode is not implemented on %s", runtime.GOOS)
	}
}

// Linux: tun.CreateTUN has already set the MTU over netlink, so only the
// addresses and the link state are left.
func configureLinux(name string, addrs []netip.Prefix) error {
	ip, err := findTool("ip")
	if err != nil {
		return err
	}
	for _, a := range addrs {
		family := "-4"
		if a.Addr().Is6() {
			family = "-6"
		}
		if err := runTool(ip, family, "address", "add", a.String(), "dev", name); err != nil {
			return err
		}
	}
	return runTool(ip, "link", "set", "dev", name, "up")
}

// macOS. Present so the binary is whole, and NEVER REACHED from ShellPilot:
// the driver refuses system mode on darwin (E02) because there is no Developer
// ID, so there is no signed helper and `osascript` cannot carry the control
// channel. Treat this function as unverified.
func configureDarwin(name string, addrs []netip.Prefix) error {
	ifconfig, err := findTool("ifconfig")
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.Addr().Is6() {
			if err := runTool(ifconfig, name, "inet6", a.String(), "alias"); err != nil {
				return err
			}
			continue
		}
		// utun is point-to-point: BSD wants a destination as well as a source,
		// and for a /32 WireGuard address they are the same address.
		if err := runTool(ifconfig, name, "inet", a.String(), a.Addr().String(), "alias"); err != nil {
			return err
		}
	}
	return runTool(ifconfig, name, "up")
}

// Windows. Wintun records the MTU inside the userspace object only, so unlike
// Linux and macOS the interface MTU has to be set explicitly.
func configureWindows(name string, addrs []netip.Prefix, mtu int) error {
	netsh, err := findTool("netsh")
	if err != nil {
		return err
	}
	firstV4, firstV6 := true, true
	for _, a := range addrs {
		if a.Addr().Is6() {
			verb := "add"
			if firstV6 {
				verb, firstV6 = "set", false
			}
			if err := runTool(netsh, "interface", "ipv6", verb, "address",
				"interface="+name, "address="+a.String()); err != nil {
				return err
			}
			continue
		}
		verb := "add"
		if firstV4 {
			verb, firstV4 = "set", false
		}
		args := []string{"interface", "ipv4", verb, "address", "name=" + name,
			"address=" + a.Addr().String(), "mask=" + ipv4Mask(a.Bits())}
		if verb == "set" {
			args = append(args, "source=static")
		}
		if err := runTool(netsh, args...); err != nil {
			return err
		}
	}
	if !firstV4 {
		if err := runTool(netsh, "interface", "ipv4", "set", "subinterface", name,
			"mtu="+strconv.Itoa(mtu), "store=active"); err != nil {
			return err
		}
	}
	if !firstV6 {
		if err := runTool(netsh, "interface", "ipv6", "set", "subinterface", name,
			"mtu="+strconv.Itoa(mtu), "store=active"); err != nil {
			return err
		}
	}
	return nil
}

// ipv4Mask renders a prefix length as the dotted mask netsh insists on.
func ipv4Mask(bits int) string {
	if bits < 0 || bits > 32 {
		bits = 32
	}
	var m uint32
	if bits > 0 {
		m = ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}

// toolPaths pins where each tool may live. Resolved from this list rather than
// from PATH: this process is root, and inheriting a PATH from an elevation
// helper means an attacker-writable directory early in it would decide what
// "ip" means. Absolute, known locations, or nothing.
var toolPaths = map[string][]string{
	"ip":       {"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"},
	"ifconfig": {"/sbin/ifconfig", "/usr/sbin/ifconfig", "/bin/ifconfig", "/usr/bin/ifconfig"},
}

func findTool(name string) (string, error) {
	if name == "netsh" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		p := filepath.Join(root, "System32", "netsh.exe")
		if _, err := os.Stat(p); err != nil {
			return "", codedf(ErrUnsupported, "could not find netsh at %s", p)
		}
		return p, nil
	}
	for _, p := range toolPaths[name] {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", codedf(ErrUnsupported,
		"%q is not installed in any of the standard locations, so ShellPilot cannot configure a system interface on this machine.", name)
}

// runTool executes one configuration command with a fixed, minimal
// environment. There is no shell: args are passed as an argv, so nothing in a
// profile can become a command.
func runTool(path string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	if runtime.GOOS == "windows" {
		// netsh needs these to find its own helper DLLs.
		cmd.Env = []string{
			"SystemRoot=" + os.Getenv("SystemRoot"),
			"windir=" + os.Getenv("windir"),
		}
	} else {
		cmd.Env = []string{"PATH=/sbin:/usr/sbin:/bin:/usr/bin", "LC_ALL=C"}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return codedf(ErrInternal, "%s %s failed: %s",
			filepath.Base(path), strings.Join(args, " "), firstLine(detail))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
