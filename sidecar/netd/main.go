// Command shellpilot-netd is ShellPilot's WireGuard sidecar.
//
// By default it runs the entire TCP/IP stack in-process on gVisor netstack, so
// there is no TUN device, no route-table change, no DNS change and no
// elevation prompt: the tunnel is exposed to the rest of the app as ordinary
// loopback listeners. Nothing it does in that mode requires root, on any
// platform.
//
// With `--privileged` it instead creates a real TUN device, which does require
// root. That mode is described in privileged.go; the protocol, the UAPI, the
// stats and the dispatch table are the same code either way — only the device
// and the transport differ.
//
// It speaks newline-delimited JSON on stdin/stdout and nothing else. Secrets
// arrive only on stdin — never argv, never the environment — because argv is
// world-readable through `ps aux` and Get-CimInstance Win32_Process, and no
// key ever touches disk.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Version and BuildSha are stamped by scripts/build-sidecar.sh via -ldflags.
// The defaults are what a bare `go build` produces, and probe() on the
// TypeScript side treats a dev version as untrusted-but-usable.
var (
	Version  = "0.0.0-dev"
	BuildSha = "unknown"
)

// Stdin lines carry a full wg.up including every peer, so 64 KiB (the
// bufio.Scanner default) is not enough for a large profile. 8 MiB is far more
// than any real request and is still a bound, not an invitation.
const maxRequestBytes = 8 << 20

// How long `shutdown` waits for in-flight handlers before stopping anyway.
// Chosen under the supervisor's 5 s gracefulTimeoutMs (§5.3) so the graceful
// path completes rather than escalating to a signal.
const gracefulDrain = 4 * time.Second

// waitTimeout is sync.WaitGroup.Wait with a deadline.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

type Server struct {
	out *Writer

	// True only in --privileged mode. It changes exactly one thing: which
	// device wg.up builds. Everything else — the dispatch table, the UAPI,
	// the stats, the teardown — is the same code, because a forked protocol
	// is a second thing to keep in sync and a second thing to get wrong.
	privileged bool

	mu      sync.Mutex
	tunnels map[string]*Tunnel
	// Reserves a tunnelId across the slow part of wg.up so two concurrent
	// ups for the same profile cannot both build a device.
	starting map[string]bool
	// forwardId -> tunnelId, so wg.forward.close needs only the id the
	// caller was given.
	forwards map[string]string
	// Set by stop() so a wg.up that was still building cannot register a
	// tunnel into a server that has already torn everything down.
	stopping bool

	ctx      context.Context
	cancel   context.CancelFunc
	forwardN atomic.Uint64

	// Closed once, by whichever of shutdown / signal / stdin-EOF happens
	// first.
	stopOnce sync.Once
	stopped  chan struct{}
}

// options is the whole command line. There are four flags and there is no
// intention of there being more: everything else arrives as a request.
type options struct {
	version    bool
	help       bool
	privileged bool
	// Where the privileged process listens. Chosen by the parent, because on
	// Windows (and on macOS) the elevated child has no pipe back to us to
	// report a path it chose itself.
	socket string
	// A file holding 64 hex characters — the 32-byte shared nonce. A path,
	// never the nonce itself: argv is world-readable.
	nonceFile string
}

const usage = `shellpilot-netd %s

Speaks newline-delimited JSON on stdin/stdout.

Flags:
  --version                 print {version, goVersion, buildSha} as JSON
  --privileged              create a real TUN device and serve one
                            authenticated client on --socket (requires root)
  --socket <path>           unix socket to listen on (--privileged only)
  --nonce-file <path>       file holding the 64 hex characters the first
                            request must present (--privileged only)
`

// parseArgs is deliberately hand-written rather than flag.FlagSet: the default
// FlagSet prints to stdout, and stdout is protocol-only for this binary.
func parseArgs(argv []string) (*options, error) {
	o := &options{}
	for i := 0; i < len(argv); i++ {
		raw := argv[i]
		name, inline, hasInline := strings.Cut(raw, "=")
		// value consumes either --flag=value or --flag value.
		value := func() (string, error) {
			if hasInline {
				if inline == "" {
					return "", fmt.Errorf("%s needs a value", name)
				}
				return inline, nil
			}
			if i+1 >= len(argv) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			i++
			return argv[i], nil
		}
		switch name {
		case "--version", "-version":
			o.version = true
		case "--help", "-h":
			o.help = true
		case "--privileged":
			o.privileged = true
		case "--socket":
			v, err := value()
			if err != nil {
				return nil, err
			}
			o.socket = v
		case "--nonce-file":
			v, err := value()
			if err != nil {
				return nil, err
			}
			o.nonceFile = v
		default:
			// An unknown flag is a packaging bug, not a user error.
			return nil, fmt.Errorf("unknown argument %q", raw)
		}
	}
	if o.version || o.help {
		return o, nil
	}
	if o.privileged {
		if o.socket == "" || o.nonceFile == "" {
			// Refused rather than defaulted. A privileged process that
			// invented its own socket path would be a root process listening
			// somewhere the parent is not, and the only thing worse than that
			// is one listening somewhere anybody can reach.
			return nil, errors.New("--privileged requires both --socket and --nonce-file")
		}
	} else if o.socket != "" || o.nonceFile != "" {
		return nil, errors.New("--socket and --nonce-file are only meaningful with --privileged")
	}
	return o, nil
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "shellpilot-netd: %s\n", err.Error())
		os.Exit(2)
	}
	// --version is used by the TS driver's probe() to identify the binary
	// before it is ever asked to hold a key.
	if opts.version {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]string{
			"version":   Version,
			"goVersion": runtime.Version(),
			"buildSha":  BuildSha,
		})
		return
	}
	if opts.help {
		// Usage goes to stderr: stdout is protocol-only, always.
		fmt.Fprintf(os.Stderr, usage, Version)
		return
	}

	if opts.privileged {
		// Never touches stdin or stdout: an elevated child has neither
		// connected to us on two of the three platforms. Everything it says
		// goes out over the authenticated socket.
		os.Exit(runPrivileged(opts))
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := newServer(ctx, cancel, NewWriter(os.Stdout))

	// SIGTERM/SIGINT are treated exactly like the `shutdown` method: close
	// everything, exit 0. A supervisor that has already sent `shutdown` and
	// then escalates to SIGTERM must not see a non-zero exit and log a crash.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			s.stop()
		case <-s.stopped:
		}
	}()

	s.readLoop(os.Stdin)

	// readLoop returning means stdin reached EOF — the parent process is gone
	// and nobody will ever read our output again. This is the orphan safety
	// net: without it a crashed Electron main process leaves a netd holding
	// listen ports and a live tunnel until the machine reboots.
	s.stop()
	os.Exit(0)
}

// newServer builds the dispatcher around one output writer. Shared by the
// stdio path and the privileged socket path so neither can drift.
func newServer(ctx context.Context, cancel context.CancelFunc, out *Writer) *Server {
	return &Server{
		out:      out,
		tunnels:  map[string]*Tunnel{},
		starting: map[string]bool{},
		forwards: map[string]string{},
		ctx:      ctx,
		cancel:   cancel,
		stopped:  make(chan struct{}),
	}
}

func (s *Server) readLoop(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxRequestBytes)
	var wg sync.WaitGroup
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		// Scanner reuses its buffer, so the handler goroutine needs its own
		// copy.
		buf := make([]byte, len(line))
		copy(buf, line)

		var req Request
		if err := json.Unmarshal(buf, &req); err != nil {
			// No id to echo, so the parent cannot correlate this; the log
			// event is the only place it can surface. Never quote the line
			// back — a malformed wg.up contains a private key.
			s.out.Log("error", "", "could not parse a request: "+err.Error())
			continue
		}
		if req.Method == "shutdown" {
			// Let the requests already in flight finish and answer first, so
			// the shutdown response is a real boundary: once the parent sees
			// it, every id it sent has been accounted for. Bounded, because a
			// wedged handler must not be able to stop us from stopping — the
			// supervisor's next move is SIGTERM and then SIGKILL, and a
			// sidecar that has to be killed leaves listen ports behind.
			waitTimeout(&wg, gracefulDrain)
			s.out.Respond(req.ID, map[string]bool{"stopping": true})
			s.stop()
			return
		}
		// Handlers run concurrently: wg.up can take a moment and must not
		// stall a wg.stats for another tunnel. Ordering is the parent's
		// problem and it has the ids to solve it with.
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.dispatch(&req)
		}()
	}
	if err := sc.Err(); err != nil {
		// A line over the cap loses stream framing irrecoverably; there is no
		// safe way to resynchronise, so report and let the caller shut down.
		s.out.Log("error", "", "stdin read failed: "+err.Error())
	}
	wg.Wait()
}

func (s *Server) dispatch(req *Request) {
	defer func() {
		// A panic in one handler must not take the whole sidecar with it and
		// strand a live tunnel. The request fails; the process survives.
		if r := recover(); r != nil {
			s.out.Fail(req.ID, codedf(ErrInternal, "internal error handling %s", req.Method))
			s.out.Log("error", "", fmt.Sprintf("panic in %s: %v", req.Method, r))
		}
	}()

	switch req.Method {
	case "ping":
		s.out.Respond(req.ID, &PingResult{
			Version: Version, GoVersion: runtime.Version(), BuildSha: BuildSha,
		})
	case "wg.up":
		s.handle(req, s.wgUp)
	case "wg.down":
		s.handle(req, s.wgDown)
	case "wg.stats":
		s.handle(req, s.wgStats)
	case "wg.forward.open":
		s.handle(req, s.forwardOpen)
	case "wg.forward.close":
		s.handle(req, s.forwardClose)
	case "wg.keygen":
		s.handle(req, s.wgKeygen)
	case "auth":
		// Only ever valid as the very first message on a --privileged
		// connection, where privileged.go consumes it before this dispatcher
		// exists. Reaching here means a second attempt, and there is no such
		// thing: one connection, authenticated once.
		s.out.Fail(req.ID, codedf(ErrUnsupported, "this connection is already authenticated"))
	default:
		s.out.Fail(req.ID, codedf(ErrUnsupported, "unknown method %q", req.Method))
	}
}

// handle runs one method and turns its (result, error) into a response, so
// no method has to remember the ok/error framing.
func (s *Server) handle(req *Request, fn func(*Request) (interface{}, error)) {
	res, err := fn(req)
	if err != nil {
		s.out.Fail(req.ID, err)
		return
	}
	s.out.Respond(req.ID, res)
}

func decodeParams(req *Request, v interface{}) error {
	if len(req.Params) == 0 {
		return codedf(ErrConfigInvalid, "%s requires params", req.Method)
	}
	if err := json.Unmarshal(req.Params, v); err != nil {
		// json.Unmarshal errors quote the offending value, which for a
		// mistyped privateKey would be the key itself. Never pass err
		// through here.
		return codedf(ErrConfigInvalid, "the params for %s are not the expected shape", req.Method)
	}
	return nil
}

// ------------------------------------------------------------- wg methods

func (s *Server) wgUp(req *Request) (interface{}, error) {
	var p UpParams
	if err := decodeParams(req, &p); err != nil {
		return nil, err
	}
	if p.TunnelID == "" {
		return nil, codedf(ErrConfigInvalid, "tunnelId is required")
	}

	s.mu.Lock()
	if _, live := s.tunnels[p.TunnelID]; live || s.starting[p.TunnelID] {
		s.mu.Unlock()
		return nil, codedf(ErrAlreadyRunning, "tunnel %q is already running", p.TunnelID)
	}
	s.starting[p.TunnelID] = true
	s.mu.Unlock()

	release := func() {
		s.mu.Lock()
		delete(s.starting, p.TunnelID)
		s.mu.Unlock()
	}

	// Endpoints are resolved on the host resolver before the device sees
	// them: the peer is on the outside of the tunnel by definition, and doing
	// it here yields `dns-failure` instead of an opaque device error.
	peers, err := resolveEndpoints(s.ctx, p.Peers)
	if err != nil {
		release()
		return nil, err
	}
	p.Peers = peers

	var t *Tunnel
	if s.privileged {
		// Listeners are a userspace concept: they exist because netstack has
		// no other way to reach the tunnel. In system mode the operating
		// system's own route table carries the traffic, so a SOCKS proxy on
		// loopback would be a second, differently-behaved path into the same
		// tunnel. Rejected loudly rather than ignored quietly — a listener
		// silently dropped is a port the caller believes is open.
		if len(p.Listeners) > 0 {
			release()
			return nil, codedf(ErrConfigInvalid,
				"listeners are not supported in system mode: the route table already carries this traffic")
		}
		t, err = newSystemTunnel(s.ctx, s.out, &p)
	} else {
		t, err = newTunnel(s.ctx, s.out, &p)
	}
	if err != nil {
		release()
		return nil, err
	}

	bound := make([]ListenerOut, 0, len(p.Listeners))
	for _, l := range p.Listeners {
		out, lerr := t.addListener(l)
		if lerr != nil {
			// Partial listener failure tears the whole tunnel down. A
			// half-configured tunnel — SOCKS up, forward missing — is worse
			// than no tunnel: the caller would think it succeeded.
			t.closeAll()
			release()
			return nil, lerr
		}
		bound = append(bound, out)
	}

	s.mu.Lock()
	stopping := s.stopping
	if !stopping {
		s.tunnels[p.TunnelID] = t
	}
	delete(s.starting, p.TunnelID)
	s.mu.Unlock()

	if stopping {
		// A shutdown landed while this wg.up was still building. Registering
		// now would strand a live device and its listen ports past exit, so
		// tear it down and fail the request instead.
		t.closeAll()
		return nil, codedf(ErrInternal, "the sidecar is shutting down")
	}

	t.setState("starting", "", "", "")
	t.monitor()

	return &UpResult{
		TunnelID:   p.TunnelID,
		Listeners:  bound,
		AssignedIP: t.assignedIP,
		// Empty in userspace mode: there is no interface. In system mode this
		// is the name the kernel actually gave the device, which on macOS is
		// never the name that was asked for (E01/§6.1) — routes and DNS are
		// applied against this, so guessing it is how system mode breaks.
		IfaceName: t.ifaceName,
	}, nil
}

func (s *Server) wgDown(req *Request) (interface{}, error) {
	var p TunnelRef
	if err := decodeParams(req, &p); err != nil {
		return nil, err
	}
	t, err := s.take(p.TunnelID)
	if err != nil {
		return nil, err
	}
	// Blocks until every listener is closed, every relay has ended and the
	// device is down. The caller is entitled to assume the ports are free
	// when this returns.
	t.closeAll()
	s.out.Emit("wg.state", &StateData{TunnelID: p.TunnelID, State: "stopped"})
	return map[string]string{"tunnelId": p.TunnelID}, nil
}

func (s *Server) wgStats(req *Request) (interface{}, error) {
	var p TunnelRef
	if err := decodeParams(req, &p); err != nil {
		return nil, err
	}
	t, err := s.lookup(p.TunnelID)
	if err != nil {
		return nil, err
	}
	return t.stats()
}

// wgKeygen is the only method with no tunnel, no device and no state. It lives
// here because the alternative was telling users to install wireguard-tools to
// make a key for an app that bundles everything else WireGuard needs.
//
// Nothing it produces is written anywhere but the response.
func (s *Server) wgKeygen(req *Request) (interface{}, error) {
	var p KeygenParams
	// Params are optional here and required everywhere else: `wg.keygen` with
	// nothing to say is the common case, and making the caller send `{}` to
	// mean "generate one" would be ceremony for its own sake.
	if len(req.Params) > 0 {
		if err := decodeParams(req, &p); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(p.PublicKeyFor) != "" {
		return derivePublicKey(p.PublicKeyFor)
	}
	return generateKeypair()
}

func (s *Server) forwardOpen(req *Request) (interface{}, error) {
	var p ForwardOpenParams
	if err := decodeParams(req, &p); err != nil {
		return nil, err
	}
	t, err := s.lookup(p.TunnelID)
	if err != nil {
		return nil, err
	}
	id := "fwd-" + strconv.FormatUint(s.forwardN.Add(1), 10)
	res, err := t.openForward(id, p.BindHost, p.BindPort, p.Host, p.Port)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.forwards[id] = p.TunnelID
	s.mu.Unlock()
	return &res, nil
}

func (s *Server) forwardClose(req *Request) (interface{}, error) {
	var p ForwardCloseParams
	if err := decodeParams(req, &p); err != nil {
		return nil, err
	}
	s.mu.Lock()
	tid, ok := s.forwards[p.ForwardID]
	delete(s.forwards, p.ForwardID)
	t := s.tunnels[tid]
	s.mu.Unlock()
	if !ok {
		return nil, codedf(ErrConfigInvalid, "unknown forwardId %q", p.ForwardID)
	}
	// A forward whose tunnel already went down is not an error: wg.down closed
	// it, and the caller catching up is the normal ordering.
	if t != nil {
		t.closeForward(p.ForwardID)
	}
	return map[string]string{"forwardId": p.ForwardID}, nil
}

// ----------------------------------------------------------------- state

func (s *Server) lookup(id string) (*Tunnel, error) {
	if id == "" {
		return nil, codedf(ErrConfigInvalid, "tunnelId is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tunnels[id]
	if !ok {
		return nil, codedf(ErrConfigInvalid, "no tunnel with id %q is running", id)
	}
	return t, nil
}

// take removes a tunnel from the registry, along with the forward ids that
// belonged to it, and returns it for closing.
func (s *Server) take(id string) (*Tunnel, error) {
	if id == "" {
		return nil, codedf(ErrConfigInvalid, "tunnelId is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tunnels[id]
	if !ok {
		return nil, codedf(ErrConfigInvalid, "no tunnel with id %q is running", id)
	}
	delete(s.tunnels, id)
	for fid, tid := range s.forwards {
		if tid == id {
			delete(s.forwards, fid)
		}
	}
	return t, nil
}

// stop closes every tunnel and returns once they are all down. Idempotent:
// `shutdown`, SIGTERM and stdin EOF can and do race.
func (s *Server) stop() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopping = true
		all := make([]*Tunnel, 0, len(s.tunnels))
		for id, t := range s.tunnels {
			all = append(all, t)
			delete(s.tunnels, id)
		}
		s.forwards = map[string]string{}
		s.mu.Unlock()

		var wg sync.WaitGroup
		for _, t := range all {
			wg.Add(1)
			go func(t *Tunnel) { defer wg.Done(); t.closeAll() }(t)
		}
		wg.Wait()
		s.cancel()
		close(s.stopped)
	})
}
