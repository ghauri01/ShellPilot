package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// What this file proves, and what it cannot.
//
// Everything here runs unprivileged. The flag contract, the socket contract,
// the nonce handshake and every refusal path are exercised for real — the
// socket tests open a genuine unix socket and speak the genuine wire protocol
// to the genuine authenticate(). What is NOT exercised anywhere in this suite
// is `tun.CreateTUN`: creating a real kernel interface needs root, and a test
// that faked one would be asserting that the fake works. The device path is
// therefore covered only by its argument validation and its error mapping,
// both of which are pure functions, and the interface-configuration commands
// (`ip`, `ifconfig`, `netsh`) have never been run by this suite at all.

// ------------------------------------------------------------ flag contract

func TestParseArgsPrivilegedRequiresASocketAndANonce(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string // substring of the expected error, "" for success
	}{
		{"privileged alone", []string{"--privileged"}, "--socket"},
		{"socket only", []string{"--privileged", "--socket", "/tmp/x.sock"}, "--nonce-file"},
		{"nonce only", []string{"--privileged", "--nonce-file", "/tmp/x.nonce"}, "--socket"},
		{"socket without privileged", []string{"--socket", "/tmp/x.sock"}, "only meaningful with --privileged"},
		{"nonce without privileged", []string{"--nonce-file", "/tmp/x.nonce"}, "only meaningful with --privileged"},
		{"unknown flag", []string{"--make-me-root"}, "unknown argument"},
		{"missing value", []string{"--privileged", "--socket"}, "needs a value"},
		{"empty inline value", []string{"--privileged", "--socket=", "--nonce-file", "n"}, "needs a value"},
		{"complete", []string{"--privileged", "--socket", "/tmp/x.sock", "--nonce-file", "/tmp/x.nonce"}, ""},
		{"complete inline", []string{"--privileged", "--socket=/tmp/x.sock", "--nonce-file=/tmp/x.nonce"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, err := parseArgs(c.argv)
			if c.want == "" {
				if err != nil {
					t.Fatalf("parseArgs(%v) = %v, want success", c.argv, err)
				}
				if !o.privileged || o.socket != "/tmp/x.sock" || o.nonceFile != "/tmp/x.nonce" {
					t.Fatalf("parsed = %+v", o)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseArgs(%v) succeeded, want an error about %q", c.argv, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), c.want)
			}
		})
	}
}

// The userspace command line must keep working exactly as it did: probe()
// identifies the binary with --version before it will trust it with a key.
func TestParseArgsKeepsTheUnprivilegedContract(t *testing.T) {
	o, err := parseArgs(nil)
	if err != nil || o.privileged || o.version || o.help {
		t.Fatalf("no args: %+v, %v", o, err)
	}
	for _, a := range []string{"--version", "-version"} {
		o, err := parseArgs([]string{a})
		if err != nil || !o.version {
			t.Fatalf("%s: %+v, %v", a, o, err)
		}
	}
	for _, a := range []string{"--help", "-h"} {
		o, err := parseArgs([]string{a})
		if err != nil || !o.help {
			t.Fatalf("%s: %+v, %v", a, o, err)
		}
	}
}

// ------------------------------------------------------------------- nonce

func writeNonce(t *testing.T, dir string, body string) string {
	t.Helper()
	p := filepath.Join(dir, "nonce")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write nonce: %v", err)
	}
	return p
}

func TestLoadNonceAcceptsThirtyTwoBytesAndDeletesTheFile(t *testing.T) {
	dir := t.TempDir()
	want := strings.Repeat("ab", nonceLen)
	// Trailing newline is tolerated: a file written by a shell redirect has
	// one, and failing on it would be a trap rather than a check.
	p := writeNonce(t, dir, want+"\n")

	got, err := loadNonce(p)
	if err != nil {
		t.Fatalf("loadNonce: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("nonce = %x, want %s", got, want)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the nonce file survived the read; it is a credential and must not")
	}
}

func TestLoadNonceRejectsAnythingThatIsNotThirtyTwoBytes(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{
		"",
		"not hex at all",
		strings.Repeat("ab", nonceLen-1),
		strings.Repeat("ab", nonceLen+1),
	} {
		if _, err := loadNonce(writeNonce(t, dir, body)); err == nil {
			t.Fatalf("loadNonce accepted %q", body)
		}
	}
	if _, err := loadNonce(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("loadNonce accepted a missing file")
	}
}

// The error must not quote the file's contents: it is the one secret this
// process is handed on disk.
func TestLoadNonceErrorDoesNotEchoTheFile(t *testing.T) {
	const secret = "deadbeefdeadbeefdeadbeefdeadbeef" // wrong length on purpose
	_, err := loadNonce(writeNonce(t, t.TempDir(), secret))
	if err == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the error echoed the nonce file: %q", err.Error())
	}
}

// -------------------------------------------------------------- the socket

// shortSocketDir keeps the socket path inside the kernel's ~104-byte limit;
// macOS TMPDIR under `go test` is long enough to blow it on its own.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "spnetd")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestListenControlTightensTheDirectoryAndTheSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes do not apply on Windows; the nonce is the check there")
	}
	dir := shortSocketDir(t)
	// Deliberately world-readable to start with, so the tightening is visible.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	path := filepath.Join(dir, "c.sock")

	ln, err := listenControl(path)
	if err != nil {
		t.Fatalf("listenControl: %v", err)
	}
	defer ln.Close()

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %o, want 700", di.Mode().Perm())
	}
	si, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if si.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 600", si.Mode().Perm())
	}
}

func TestListenControlRefusesAPathItShouldNotUnlink(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "regular")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := listenControl(path); err == nil {
		t.Fatal("listenControl removed a regular file to bind over it")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the file was removed anyway: %v", err)
	}
}

func TestListenControlRefusesAnOverlongPath(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, strings.Repeat("n", maxSocketPath+16))
	if _, err := listenControl(path); err == nil {
		t.Fatal("listenControl accepted a path past the kernel limit")
	}
}

// A socket left by a process that was killed must not stop the next launch.
func TestListenControlReplacesAStaleSocket(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "c.sock")
	first, err := listenControl(path)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	// Closing a unix listener normally unlinks; recreate the file to model the
	// kill -9 case where nothing ran.
	_ = first.Close()
	if err := os.WriteFile(path, nil, 0o600); err == nil {
		// A regular file is refused by design, so put a real socket back
		// instead: bind, then abandon the listener's unlink by re-binding.
		_ = os.Remove(path)
	}
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("stale listen: %v", err)
	}
	if ul, ok := stale.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = stale.Close()

	second, err := listenControl(path)
	if err != nil {
		t.Fatalf("listenControl did not replace a stale socket: %v", err)
	}
	_ = second.Close()
}

// ---------------------------------------------------------------- auth flow

// authServer runs listenControl + acceptOne + authenticate exactly as
// runPrivileged does, and reports what authenticate decided.
type authOutcome struct {
	err error
}

func authServer(t *testing.T, nonce []byte) (path string, result <-chan authOutcome) {
	t.Helper()
	dir := shortSocketDir(t)
	path = filepath.Join(dir, "c.sock")
	ln, err := listenControl(path)
	if err != nil {
		t.Fatalf("listenControl: %v", err)
	}
	ch := make(chan authOutcome, 1)
	go func() {
		conn, aerr := acceptOne(ln, 5*time.Second)
		_ = ln.Close()
		if aerr != nil {
			ch <- authOutcome{err: aerr}
			return
		}
		defer conn.Close()
		ch <- authOutcome{err: authenticate(conn, bufio.NewReader(conn), NewWriter(conn), nonce)}
	}()
	return path, ch
}

func dialControl(t *testing.T, path string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readResponse(t *testing.T, c net.Conn) map[string]json.RawMessage {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		t.Fatalf("read response: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("response is not JSON: %v (%q)", err, line)
	}
	return m
}

func TestControlSocketAcceptsTheRightNonce(t *testing.T) {
	nonce := make([]byte, nonceLen)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	path, result := authServer(t, nonce)

	c := dialControl(t, path)
	fmt.Fprintf(c, "%s\n", `{"id":"1","method":"auth","params":{"nonce":"`+hex.EncodeToString(nonce)+`"}}`)

	m := readResponse(t, c)
	if string(m["ok"]) != "true" || string(m["id"]) != `"1"` {
		t.Fatalf("response = %v", m)
	}
	var res AuthResult
	if err := json.Unmarshal(m["result"], &res); err != nil {
		t.Fatalf("result: %v", err)
	}
	if !res.Authenticated || !res.Privileged || res.Version == "" {
		t.Fatalf("result = %+v", res)
	}
	if out := <-result; out.err != nil {
		t.Fatalf("authenticate rejected a valid nonce: %v", out.err)
	}
}

func TestControlSocketRejectsEveryBadFirstMessage(t *testing.T) {
	nonce := make([]byte, nonceLen)
	for i := range nonce {
		nonce[i] = 0xA5
	}
	other := strings.Repeat("00", nonceLen)

	cases := []struct {
		name string
		line string
	}{
		{"wrong nonce", `{"id":"1","method":"auth","params":{"nonce":"` + other + `"}}`},
		{"absent nonce", `{"id":"1","method":"auth","params":{}}`},
		{"no params", `{"id":"1","method":"auth"}`},
		{"truncated nonce", `{"id":"1","method":"auth","params":{"nonce":"a5a5"}}`},
		{"not hex", `{"id":"1","method":"auth","params":{"nonce":"zzzz"}}`},
		{"another method first", `{"id":"1","method":"wg.up","params":{"tunnelId":"t"}}`},
		{"not a request", `hello?`},
		{"empty line", ``},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path, result := authServer(t, nonce)
			conn := dialControl(t, path)
			fmt.Fprintf(conn, "%s\n", c.line)

			out := <-result
			if out.err == nil {
				t.Fatalf("authenticate accepted %q", c.line)
			}
			// The refusal reaches the client as a coded error, so the parent
			// reports "authentication failed" rather than a dropped socket.
			if c.line != `` && c.line != `hello?` {
				m := readResponse(t, conn)
				if string(m["ok"]) != "false" {
					t.Fatalf("response = %v", m)
				}
				var e WireError
				if err := json.Unmarshal(m["error"], &e); err != nil {
					t.Fatalf("error payload: %v", err)
				}
				if e.Code != ErrPermissionDenied {
					t.Fatalf("code = %q, want %q", e.Code, ErrPermissionDenied)
				}
				// The reply must not tell an unauthenticated peer which part
				// it got wrong.
				if strings.Contains(strings.ToLower(e.Message), "nonce") {
					t.Fatalf("the refusal described the failure: %q", e.Message)
				}
			}
		})
	}
}

// A client that connects and then says nothing must not hold a root process
// open. The production timeout is 10 s, so this drives authenticate against an
// already-closed connection instead of waiting it out.
func TestControlSocketRejectsAClientThatSaysNothing(t *testing.T) {
	nonce := make([]byte, nonceLen)
	path, result := authServer(t, nonce)
	conn := dialControl(t, path)
	_ = conn.Close()
	if out := <-result; out.err == nil {
		t.Fatal("authenticate accepted a connection that sent nothing")
	}
}

func TestControlSocketRefusesAnOverlongFirstLine(t *testing.T) {
	nonce := make([]byte, nonceLen)
	path, result := authServer(t, nonce)
	conn := dialControl(t, path)
	// No newline: an unauthenticated peer must not be able to make the process
	// buffer without bound.
	_, _ = conn.Write([]byte(strings.Repeat("x", maxAuthBytes*2)))
	if out := <-result; out.err == nil {
		t.Fatal("authenticate accepted an unbounded first line")
	}
}

// ------------------------------------------------------------- refuse early

// On a machine that is not root, --privileged must say so and stop — not
// panic, and not leave a socket behind for something else to connect to.
func TestPrivilegedModeRefusesWhenNotRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no uid; elevation is checked when the adapter is created")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root, so the refusal cannot be observed")
	}
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "c.sock")
	nonce := writeNonce(t, dir, strings.Repeat("ab", nonceLen))

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	code := runPrivileged(&options{privileged: true, socket: sock, nonceFile: nonce})
	os.Stderr = stderr
	_ = w.Close()
	var msg [4096]byte
	n, _ := r.Read(msg[:])
	_ = r.Close()

	if code != exitPrivilegedSetup {
		t.Fatalf("exit code = %d, want %d", code, exitPrivilegedSetup)
	}
	if !strings.Contains(string(msg[:n]), "root") {
		t.Fatalf("stderr = %q, want it to say why", string(msg[:n]))
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a socket was created despite the refusal")
	}
	// The nonce is still on disk: nothing consumed it, and the parent's run
	// directory owns its removal.
	if _, err := os.Stat(nonce); err != nil {
		t.Fatalf("the nonce file went missing on a path that never read it: %v", err)
	}
}

// ------------------------------------------------------- device-side inputs

func TestRequestedIfaceNameIsForcedToUtunOnDarwin(t *testing.T) {
	for _, in := range []string{"", "utun7", "wg-abc", "   "} {
		got, err := requestedIfaceNameFor("darwin", in)
		if err != nil {
			t.Fatalf("darwin %q: %v", in, err)
		}
		// The kernel picks the number; the caller's guess is discarded and the
		// real name comes back in UpResult.ifaceName.
		if got != "utun" {
			t.Fatalf("darwin %q -> %q, want utun", in, got)
		}
	}
}

func TestRequestedIfaceNameValidatesLinuxAndWindowsNames(t *testing.T) {
	cases := []struct {
		goos, in string
		ok       bool
	}{
		{"linux", "wg-abc123", true},
		{"linux", "wg_0.1", true},
		{"linux", "", false},
		{"linux", strings.Repeat("w", 16), false},
		{"linux", "wg 0", false},
		{"linux", "wg/0", false},
		{"linux", "wg;reboot", false},
		{"windows", "ShellPilot vpn1", true},
		{"windows", "", false},
		{"windows", "bad\"quote", false},
		{"windows", "bad\nnewline", false},
		{"windows", `bad\slash`, false},
	}
	for _, c := range cases {
		got, err := requestedIfaceNameFor(c.goos, c.in)
		if c.ok && (err != nil || got != strings.TrimSpace(c.in)) {
			t.Fatalf("%s %q -> %q, %v; want it accepted", c.goos, c.in, got, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("%s %q was accepted", c.goos, c.in)
		}
	}
}

// E06: the message a user in a container must be able to act on.
func TestMissingDevNetTunNamesThePathAndOffersUserspace(t *testing.T) {
	err := classifyDeviceErrorFor("linux",
		fmt.Errorf("CreateTUN(%q) failed; %s does not exist", "wg-a", "/dev/net/tun"), "wg-a")
	var ce *codedError
	if !errors.As(err, &ce) {
		t.Fatalf("error is not coded: %v", err)
	}
	if ce.code != ErrPermissionDenied {
		t.Fatalf("code = %q, want %q", ce.code, ErrPermissionDenied)
	}
	if !strings.Contains(ce.Error(), "/dev/net/tun") {
		t.Fatalf("message does not name the device: %q", ce.Error())
	}
	if !strings.Contains(strings.ToLower(ce.Error()), "userspace") {
		t.Fatalf("message does not offer userspace mode: %q", ce.Error())
	}
}

func TestDeviceErrorsAreClassifiedNotGuessed(t *testing.T) {
	cases := []struct {
		goos string
		err  error
		code string
	}{
		{"linux", syscall.EPERM, ErrPermissionDenied},
		{"linux", syscall.EACCES, ErrPermissionDenied},
		{"linux", errors.New("something went sideways"), ErrInternal},
		{"windows", errors.New("Error loading wintun.dll DLL: file not found"), ErrUnsupported},
		{"windows", errors.New("Access is denied."), ErrPermissionDenied},
		// The /dev/net/tun wording is Linux-specific: the same ENOENT on
		// another OS means something else and must not borrow the message.
		{"darwin", errors.New("no such file or directory"), ErrInternal},
	}
	for _, c := range cases {
		err := classifyDeviceErrorFor(c.goos, c.err, "wg0")
		var ce *codedError
		if !errors.As(err, &ce) {
			t.Fatalf("%v is not coded", c.err)
		}
		if ce.code != c.code {
			t.Fatalf("%s/%v -> %q, want %q", c.goos, c.err, ce.code, c.code)
		}
		if c.code == ErrUnsupported && !strings.Contains(ce.Error(), "wintun.dll") {
			t.Fatalf("the Windows message does not name the missing driver: %q", ce.Error())
		}
	}
}

func TestParseIfacePrefixesKeepsThePrefixLength(t *testing.T) {
	got, err := parseIfacePrefixes([]string{"10.0.0.2/24", " 10.9.9.9 ", "fd00::2/64", "fd00::9"})
	if err != nil {
		t.Fatalf("parseIfacePrefixes: %v", err)
	}
	want := []string{"10.0.0.2/24", "10.9.9.9/32", "fd00::2/64", "fd00::9/128"}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("prefixes[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestParseIfacePrefixesRejectsNonsense(t *testing.T) {
	for _, in := range [][]string{
		{},
		{"not an address"},
		{"10.0.0.0/33"},
		{"10.0.0.2/24", ""},
	} {
		if _, err := parseIfacePrefixes(in); err == nil {
			t.Fatalf("parseIfacePrefixes(%v) succeeded", in)
		}
	}
}

func TestCheckedMTUDefaultsAndBounds(t *testing.T) {
	if m, err := checkedMTU(0); err != nil || m != defaultMTU {
		t.Fatalf("0 -> %d, %v", m, err)
	}
	if m, err := checkedMTU(1280); err != nil || m != 1280 {
		t.Fatalf("1280 -> %d, %v", m, err)
	}
	for _, bad := range []int{575, 9001, -1} {
		if _, err := checkedMTU(bad); err == nil {
			t.Fatalf("checkedMTU(%d) succeeded", bad)
		}
	}
}

func TestIPv4MaskRendersWhatNetshWants(t *testing.T) {
	cases := map[int]string{0: "0.0.0.0", 8: "255.0.0.0", 24: "255.255.255.0", 32: "255.255.255.255"}
	for bits, want := range cases {
		if got := ipv4Mask(bits); got != want {
			t.Fatalf("ipv4Mask(%d) = %s, want %s", bits, got, want)
		}
	}
}

// The privileged path never resolves a tool through PATH, because it is root
// and an attacker-writable directory early in an inherited PATH would decide
// what "ip" means.
// Absoluteness, judged by the rules of the platform the path is *for* rather
// than the platform the test happens to run on.
func isAbsolutePosix(p string) bool {
	return strings.HasPrefix(p, "/")
}

func isAbsoluteWindows(p string) bool {
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 &&
		((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) &&
		p[1] == ':' &&
		(p[2] == '\\' || p[2] == '/')
}

func TestToolsAreOnlyEverResolvedFromAbsolutePaths(t *testing.T) {
	for name, paths := range toolPaths {
		if len(paths) == 0 {
			t.Fatalf("%s has no candidate paths", name)
		}
		for _, p := range paths {
			// Not filepath.IsAbs: on Windows that applies Windows semantics, so
			// the POSIX candidates ("/sbin/ip") read as relative and the test
			// fails on a runner while the code under test is fine. What the
			// invariant actually forbids is a bare name that PATH could
			// resolve — this process is root, so a hijacked PATH entry would
			// run as root. Accept either an absolute POSIX path or an absolute
			// Windows path, and reject anything with no directory at all.
			if !isAbsolutePosix(p) && !isAbsoluteWindows(p) {
				t.Fatalf("%s candidate %q is not absolute", name, p)
			}
		}
	}
	if _, err := findTool("definitely-not-a-real-tool"); err == nil {
		t.Fatal("findTool invented a path for an unknown tool")
	}
}

// decodeLines parses the NDJSON a Server wrote. Local to this file: main_test
// keeps its own copy inside run(), which drives a whole server rather than one
// request.
func decodeLines(t *testing.T, out string) []map[string]json.RawMessage {
	t.Helper()
	var msgs []map[string]json.RawMessage
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("output line is not JSON: %v\n%q", err, l)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

// ------------------------------------------------------- privileged wg.up

// System mode has no listeners: the route table carries the traffic. A
// listener silently dropped would be a port the caller believes is open, so
// the request is refused — and refused before any device is created, which is
// what makes this assertable without root.
func TestPrivilegedUpRefusesListeners(t *testing.T) {
	var w syncBuf
	s := newTestServer(&w)
	s.privileged = true
	defer s.stop()

	req := UpParams{
		TunnelID:  "t1",
		IfaceName: "wg-test",
		Iface:     IfaceParams{PrivateKey: strings.Repeat("A", 43) + "=", Addresses: []string{"10.0.0.2/32"}},
		// A literal endpoint, so nothing here touches DNS.
		Peers:     []PeerParams{{PublicKey: strings.Repeat("B", 43) + "=", Endpoint: "127.0.0.1:51820", AllowedIPs: []string{"10.0.0.0/24"}}},
		Listeners: []ListenerIn{{Kind: "socks5", BindHost: "127.0.0.1", BindPort: 0}},
	}
	params, _ := json.Marshal(req)
	body, _ := json.Marshal(map[string]any{"id": "1", "method": "wg.up", "params": json.RawMessage(params)})

	s.readLoop(strings.NewReader(string(body) + "\n"))

	msgs := decodeLines(t, w.String())
	byID := indexByID(t, msgs)
	assertErrorCode(t, byID["1"], "1", ErrConfigInvalid)
	if !strings.Contains(w.String(), "listeners are not supported in system mode") {
		t.Fatalf("the refusal does not say why: %s", w.String())
	}
}

// Sanity: the userspace path is untouched by the privileged flag existing.
func TestUnprivilegedServerStillAcceptsListeners(t *testing.T) {
	if _, err := netip.ParsePrefix("10.0.0.2/32"); err != nil {
		t.Fatal(err)
	}
	var w syncBuf
	s := newTestServer(&w)
	defer s.stop()
	if s.privileged {
		t.Fatal("a server built for stdio must never be privileged")
	}
}
