package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The wire protocol is newline-delimited JSON over stdin/stdout.
//
// Three message shapes travel on it:
//
//	→ request   {"id":"7","method":"wg.up","params":{…}}
//	← response  {"id":"7","ok":true,"result":{…}}
//	            {"id":"7","ok":false,"error":{"code":"config-invalid","message":"…"}}
//	← event     {"event":"wg.state","data":{…}}
//
// stdout carries protocol traffic and nothing else. A single stray Println
// there desynchronises the parent's parser for the rest of the process
// lifetime, so all diagnostics go out as `log` events (or, before the writer
// exists, to stderr).

// Request is one inbound call. `id` is opaque to us and echoed verbatim.
type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the reply to exactly one Request.
type Response struct {
	ID     string      `json:"id"`
	OK     bool        `json:"ok"`
	Result interface{} `json:"result,omitempty"`
	Error  *WireError  `json:"error,omitempty"`
}

// WireError carries a machine-readable code plus prose for the log drawer.
// Code is always a member of the TypeScript `VpnErrorCode` union in
// src/shared/vpn.ts — the TS side switches on it exhaustively.
type WireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Event is an unsolicited message. It carries no `id`, which is how the
// parent's reader tells it apart from a Response.
type Event struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

// Error codes. Every constant here must exist in the TS VpnErrorCode union;
// protocol_test.go reads src/shared/vpn.ts and asserts exactly that.
const (
	ErrConfigInvalid      = "config-invalid"
	ErrPortInUse          = "port-in-use"
	ErrPermissionDenied   = "permission-denied"
	ErrHandshakeTimeout   = "handshake-timeout"
	ErrNetworkUnreachable = "network-unreachable"
	ErrDNSFailure         = "dns-failure"
	ErrAlreadyRunning     = "already-running"
	ErrUnsupported        = "unsupported"
	ErrInternal           = "internal"
)

// knownCodes mirrors the subset of VpnErrorCode this binary can emit.
var knownCodes = map[string]bool{
	ErrConfigInvalid:      true,
	ErrPortInUse:          true,
	ErrPermissionDenied:   true,
	ErrHandshakeTimeout:   true,
	ErrNetworkUnreachable: true,
	ErrDNSFailure:         true,
	ErrAlreadyRunning:     true,
	ErrUnsupported:        true,
	ErrInternal:           true,
}

// codedError is an error that already knows which VpnErrorCode it maps to.
// Handlers return these; the dispatcher unwraps them into a WireError. An
// error without a code becomes `internal`, which is the honest answer: if we
// did not classify it, we do not know what it was.
type codedError struct {
	code string
	msg  string
	wrap error
}

func (e *codedError) Error() string {
	if e.wrap != nil {
		return e.msg + ": " + e.wrap.Error()
	}
	return e.msg
}

func (e *codedError) Unwrap() error { return e.wrap }

func codedf(code string, format string, args ...interface{}) error {
	return &codedError{code: code, msg: fmt.Sprintf(format, args...)}
}

func wrapCoded(code string, err error, format string, args ...interface{}) error {
	return &codedError{code: code, msg: fmt.Sprintf(format, args...), wrap: err}
}

// toWireError classifies any error into the protocol shape. The message is
// run through redact() on the way out: an error string is one of the easiest
// places for key material to escape, and the parent puts these straight into
// a user-visible log ring.
func toWireError(err error) *WireError {
	var ce *codedError
	if errors.As(err, &ce) && knownCodes[ce.code] {
		return &WireError{Code: ce.code, Message: redact(ce.Error())}
	}
	return &WireError{Code: ErrInternal, Message: redact(err.Error())}
}

// ---------------------------------------------------------------- params

// UpParams is `wg.up`. Every secret in here arrived on stdin and must never
// be written to argv, an env var, disk, or a log line.
type UpParams struct {
	TunnelID  string       `json:"tunnelId"`
	Iface     IfaceParams  `json:"iface"`
	Peers     []PeerParams `json:"peers"`
	Listeners []ListenerIn `json:"listeners"`
	// How loud the wireguard-go device logger should be: "error" (the
	// default), "debug" or "silent". Debug is genuinely useful when a
	// handshake will not complete and genuinely unusable otherwise — the
	// device emits a line per worker goroutine at startup, so leaving it on
	// would put ~60 log events on the pipe for every wg.up.
	LogLevel string `json:"logLevel,omitempty"`
	// System mode only (--privileged): the name to give the real TUN device.
	//
	// Advisory on macOS and ignored there beyond its prefix — the kernel
	// allocates the utun number and the name it actually chose comes back in
	// UpResult.IfaceName. Ignored entirely in userspace mode, where there is
	// no interface to name.
	IfaceName string `json:"ifaceName,omitempty"`
}

type IfaceParams struct {
	// base64, 32 bytes decoded. Converted to hex for the UAPI.
	PrivateKey string   `json:"privateKey"`
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu,omitempty"`
	// Optional fixed UDP source port. Absent or 0 means "pick one", which is
	// what you want unless the peer has a matching endpoint pinned.
	ListenPort int `json:"listenPort,omitempty"`
}

type PeerParams struct {
	PublicKey           string   `json:"publicKey"`
	PresharedKey        string   `json:"presharedKey,omitempty"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowedIps"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

// ListenerIn mirrors the TS `VpnListener` union, flattened.
type ListenerIn struct {
	Kind       string `json:"kind"` // socks5 | http | forward
	BindHost   string `json:"bindHost,omitempty"`
	BindPort   int    `json:"bindPort"`
	TargetHost string `json:"targetHost,omitempty"`
	TargetPort int    `json:"targetPort,omitempty"`
}

// ListenerOut mirrors the TS `VpnBoundListener`. BindHost is echoed back
// verbatim rather than normalised (E25): if the caller asked for 0.0.0.0 the
// TS side needs to see 0.0.0.0 so it can warn that the proxy is LAN-visible.
// BindPort is always the *actual* bound port, so `bindPort: 0` resolves.
type ListenerOut struct {
	Kind       string `json:"kind"`
	BindHost   string `json:"bindHost"`
	BindPort   int    `json:"bindPort"`
	TargetHost string `json:"targetHost,omitempty"`
	TargetPort int    `json:"targetPort,omitempty"`
}

type UpResult struct {
	TunnelID   string        `json:"tunnelId"`
	Listeners  []ListenerOut `json:"listeners"`
	AssignedIP string        `json:"assignedIp,omitempty"`
	// System mode only: the name the kernel ACTUALLY gave the device. On
	// macOS the caller cannot know it in advance (the kernel picks the utun
	// number) and on Linux and Windows the requested name can still be
	// rejected or truncated, so routes and DNS must be applied against this
	// value and never against the one that was asked for.
	IfaceName string `json:"ifaceName,omitempty"`
}

type TunnelRef struct {
	TunnelID string `json:"tunnelId"`
}

// AuthParams is the first and only `auth` request, and in --privileged mode it
// is the first message on the connection or the connection dies. Nonce is the
// 32-byte shared secret as 64 lowercase hex characters.
type AuthParams struct {
	Nonce string `json:"nonce"`
}

// AuthResult tells the client which binary it just authenticated to, so a
// version skew is caught on the first message rather than on the first wg.up.
type AuthResult struct {
	Authenticated bool   `json:"authenticated"`
	Privileged    bool   `json:"privileged"`
	Version       string `json:"version"`
	BuildSha      string `json:"buildSha"`
}

// StatsResult is the parsed IpcGet snapshot.
//
// LastHandshakeUnixSec is an ABSOLUTE unix second, not an age (E63). The
// parent computes the age itself against a monotonic base, because a system
// clock jump while connected would otherwise produce a nonsense — possibly
// negative — age. Zero/absent means there has never been a handshake (E22,
// E27), which the parent turns into `handshake-timeout` once its own 30 s
// grace window expires.
type StatsResult struct {
	TunnelID             string `json:"tunnelId"`
	RxBytes              int64  `json:"rxBytes"`
	TxBytes              int64  `json:"txBytes"`
	LastHandshakeUnixSec int64  `json:"lastHandshakeUnixSec,omitempty"`
	RemoteEndpoint       string `json:"remoteEndpoint,omitempty"`
	AssignedIP           string `json:"assignedIp,omitempty"`
	Peers                int    `json:"peers"`
	// Unix millis at which netd sampled. Lets the parent age the sample.
	SampledAt int64 `json:"sampledAt"`
}

type ForwardOpenParams struct {
	TunnelID string `json:"tunnelId"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	// Optional. Defaults to 127.0.0.1; an ephemeral forward has no business
	// being reachable from the LAN.
	BindHost string `json:"bindHost,omitempty"`
	BindPort int    `json:"bindPort,omitempty"`
}

type ForwardOpenResult struct {
	ForwardID  string `json:"forwardId"`
	BindHost   string `json:"bindHost"`
	ListenPort int    `json:"listenPort"`
}

type ForwardCloseParams struct {
	ForwardID string `json:"forwardId"`
}

type PingResult struct {
	Version   string `json:"version"`
	GoVersion string `json:"goVersion"`
	BuildSha  string `json:"buildSha"`
}

// KeygenParams is `wg.keygen`, and it is the one method whose params are
// optional: absent or `{}` means "make me a fresh keypair". PublicKeyFor
// instead derives the public half of a private key the caller already holds,
// which is the other thing anybody ever runs `wg` for.
type KeygenParams struct {
	// base64, 32 bytes decoded. A secret, on the way in as much as on the way
	// out: it is never echoed back, never logged and never quoted in an error.
	PublicKeyFor string `json:"publicKeyFor,omitempty"`
}

// KeygenResult carries base64 keys, and PrivateKey is present only when this
// process generated it — a key supplied in PublicKeyFor is not sent back.
//
// This is the one result on the protocol that is deliberately NOT passed
// through redact() on the way out, and it could not be: redact() blanks
// anything 32-bytes-of-base64 shaped, so it would blank the very thing the
// caller asked for. The safety comes from the other end instead — the result
// goes into the response and nowhere near a log event.
type KeygenResult struct {
	PrivateKey string `json:"privateKey,omitempty"`
	PublicKey  string `json:"publicKey"`
}

// StateData is the payload of the unsolicited `wg.state` event. `State` is a
// member of the TS `VpnState` union.
type StateData struct {
	TunnelID   string `json:"tunnelId"`
	State      string `json:"state"`
	AssignedIP string `json:"assignedIp,omitempty"`
	Endpoint   string `json:"remoteEndpoint,omitempty"`
	ErrorCode  string `json:"errorCode,omitempty"`
	Error      string `json:"error,omitempty"`
}

type LogData struct {
	Level string `json:"level"` // debug | info | warn | error
	Msg   string `json:"msg"`
	// Present when the line belongs to one tunnel's device logger.
	TunnelID string `json:"tunnelId,omitempty"`
}

// ---------------------------------------------------------------- writer

// Writer serialises everything that reaches stdout. A single mutex is the
// whole design: NDJSON only works if one goroutine finishes its line before
// the next starts, and handlers run concurrently.
type Writer struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer {
	enc := json.NewEncoder(w)
	// SetEscapeHTML(false) keeps endpoints and error text readable; the
	// encoder still emits exactly one line per value.
	enc.SetEscapeHTML(false)
	return &Writer{w: w, enc: enc}
}

func (o *Writer) emit(v interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// A write failure here means the parent's pipe is gone. There is nowhere
	// left to report it, and main's stdin watcher is already on its way to
	// shutting us down, so drop it rather than spinning.
	_ = o.enc.Encode(v)
}

func (o *Writer) Respond(id string, result interface{}) {
	o.emit(&Response{ID: id, OK: true, Result: result})
}

func (o *Writer) Fail(id string, err error) {
	o.emit(&Response{ID: id, OK: false, Error: toWireError(err)})
}

func (o *Writer) Emit(event string, data interface{}) {
	o.emit(&Event{Event: event, Data: data})
}

func (o *Writer) Log(level, tunnelID, msg string) {
	o.Emit("log", &LogData{Level: level, Msg: redact(msg), TunnelID: tunnelID})
}
