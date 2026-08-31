package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// syncBuf is an io.Writer safe for the concurrent handlers readLoop spawns.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newTestServer(w *syncBuf) *Server {
	s := &Server{
		out:      NewWriter(w),
		tunnels:  map[string]*Tunnel{},
		starting: map[string]bool{},
		forwards: map[string]string{},
		stopped:  make(chan struct{}),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
}

// run feeds a script of NDJSON lines through the real read loop and returns
// every message that came back out, in order.
func run(t *testing.T, lines ...string) []map[string]json.RawMessage {
	t.Helper()
	var w syncBuf
	s := newTestServer(&w)
	defer s.stop()

	s.readLoop(strings.NewReader(strings.Join(lines, "\n") + "\n"))

	var out []map[string]json.RawMessage
	for _, l := range strings.Split(strings.TrimRight(w.String(), "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("output line is not JSON: %v\n%q", err, l)
		}
		out = append(out, m)
	}
	return out
}

func TestPingRoundTrip(t *testing.T) {
	msgs := run(t, `{"id":"1","method":"ping"}`)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1: %v", len(msgs), msgs)
	}
	var resp struct {
		ID     string     `json:"id"`
		OK     bool       `json:"ok"`
		Result PingResult `json:"result"`
	}
	raw, _ := json.Marshal(msgs[0])
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != "1" || !resp.OK {
		t.Fatalf("response = %+v", resp)
	}
	if resp.Result.Version == "" || resp.Result.GoVersion == "" {
		t.Fatalf("ping result = %+v", resp.Result)
	}
}

func TestUnknownMethodIsUnsupported(t *testing.T) {
	msgs := run(t, `{"id":"9","method":"wg.teleport"}`)
	assertErrorCode(t, msgs[0], "9", ErrUnsupported)
}

// A request the parent never sent an id for cannot be answered, but it must
// not desynchronise the stream either: the loop keeps going and the next
// request is answered normally.
func TestMalformedLineDoesNotKillTheLoop(t *testing.T) {
	msgs := run(t,
		`{"id":"1","method":"ping"}`,
		`{not json at all`,
		`{"id":"2","method":"ping"}`,
	)
	// Handlers run concurrently, so responses are matched by id, not position.
	ids := map[string]bool{}
	for _, m := range msgs {
		if raw, ok := m["id"]; ok {
			var id string
			_ = json.Unmarshal(raw, &id)
			ids[id] = true
		}
	}
	if len(ids) != 2 || !ids["1"] || !ids["2"] {
		t.Fatalf("ids = %v, want both 1 and 2", ids)
	}
	// The parse failure surfaces as a log event, since there is no id to fail.
	found := false
	for _, m := range msgs {
		if ev, ok := m["event"]; ok && string(ev) == `"log"` {
			found = true
		}
	}
	if !found {
		t.Fatal("a malformed line produced no log event")
	}
}

// Never quote a rejected line back: a truncated wg.up contains a private key.
func TestMalformedLineIsNotEchoed(t *testing.T) {
	const secret = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	var w syncBuf
	s := newTestServer(&w)
	defer s.stop()
	s.readLoop(strings.NewReader(`{"id":"1","method":"wg.up","params":{"privateKey":"` + secret + `"` + "\n"))
	if strings.Contains(w.String(), secret) {
		t.Fatalf("the parse error echoed the line: %s", w.String())
	}
}

func TestMethodsRequireParams(t *testing.T) {
	for _, m := range []string{"wg.up", "wg.down", "wg.stats", "wg.forward.open", "wg.forward.close"} {
		msgs := run(t, `{"id":"1","method":"`+m+`"}`)
		assertErrorCode(t, msgs[0], "1", ErrConfigInvalid)
	}
}

func TestOperationsOnAnUnknownTunnel(t *testing.T) {
	msgs := run(t,
		`{"id":"1","method":"wg.stats","params":{"tunnelId":"nope"}}`,
		`{"id":"2","method":"wg.down","params":{"tunnelId":"nope"}}`,
		`{"id":"3","method":"wg.forward.open","params":{"tunnelId":"nope","host":"10.0.0.1","port":80}}`,
		`{"id":"4","method":"wg.forward.close","params":{"forwardId":"fwd-99"}}`,
	)
	// Asserted per id rather than by counting lines. A `log` event is
	// unsolicited by definition — the sidecar is entitled to emit one at any
	// moment — so `len(msgs) == 4` was an assertion about the absence of
	// logging, not about the four answers, and any incidental log line under
	// load turned it red.
	byID := indexByID(t, msgs)
	if len(byID) != 4 {
		t.Fatalf("got %d answered ids, want 4: %v", len(byID), msgs)
	}
	for _, id := range []string{"1", "2", "3", "4"} {
		m, ok := byID[id]
		if !ok {
			t.Fatalf("no response for id %s", id)
		}
		assertErrorCode(t, m, id, ErrConfigInvalid)
	}
}

// Responses come back in whatever order the handlers finish, so tests that
// care about more than one look them up by id.
func indexByID(t *testing.T, msgs []map[string]json.RawMessage) map[string]map[string]json.RawMessage {
	t.Helper()
	out := map[string]map[string]json.RawMessage{}
	for _, m := range msgs {
		raw, ok := m["id"]
		if !ok {
			continue
		}
		var id string
		_ = json.Unmarshal(raw, &id)
		out[id] = m
	}
	return out
}

// The shutdown response is a boundary: by the time the parent sees it, every
// id it sent earlier has already been answered. Without the drain the
// shutdown reply overtakes handlers still running in their goroutines and the
// parent is left with pending requests it can never resolve.
func TestShutdownDrainsInFlightRequestsFirst(t *testing.T) {
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, `{"id":"p`+string(rune('a'+i))+`","method":"ping"}`)
	}
	lines = append(lines, `{"id":"bye","method":"shutdown"}`)

	var w syncBuf
	s := newTestServer(&w)
	defer s.stop()
	s.readLoop(strings.NewReader(strings.Join(lines, "\n") + "\n"))

	out := strings.Split(strings.TrimRight(w.String(), "\n"), "\n")
	if len(out) != 21 {
		t.Fatalf("got %d messages, want 21", len(out))
	}
	// The shutdown reply must be last.
	if !strings.Contains(out[len(out)-1], `"id":"bye"`) {
		t.Fatalf("the shutdown reply was not last:\n%s", w.String())
	}
	for _, l := range out[:len(out)-1] {
		if strings.Contains(l, `"id":"bye"`) {
			t.Fatal("the shutdown reply appeared before an in-flight response")
		}
	}
}

func TestShutdownAnswersThenStops(t *testing.T) {
	var w syncBuf
	s := newTestServer(&w)
	// The line after shutdown must never be processed; the parent is entitled
	// to assume the sidecar stopped reading.
	s.readLoop(strings.NewReader("{\"id\":\"1\",\"method\":\"shutdown\"}\n{\"id\":\"2\",\"method\":\"ping\"}\n"))

	lines := strings.Split(strings.TrimRight(w.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d messages after shutdown, want 1:\n%s", len(lines), w.String())
	}
	if !strings.Contains(lines[0], `"id":"1"`) || !strings.Contains(lines[0], `"ok":true`) {
		t.Fatalf("shutdown response = %s", lines[0])
	}
	select {
	case <-s.stopped:
	default:
		t.Fatal("shutdown did not stop the server")
	}
	// stop() is called by shutdown, by SIGTERM and by stdin EOF; those race in
	// production, so it has to be idempotent.
	s.stop()
}

func TestStdinEOFStopsTheServer(t *testing.T) {
	var w syncBuf
	s := newTestServer(&w)
	s.readLoop(strings.NewReader(`{"id":"1","method":"ping"}` + "\n"))
	// main calls stop() the moment readLoop returns; that is the orphan
	// safety net for a parent that died without saying shutdown.
	s.stop()
	select {
	case <-s.stopped:
	default:
		t.Fatal("the server did not stop after stdin EOF")
	}
}

// A line over the cap loses framing irrecoverably, so the loop reports and
// gives up rather than resynchronising onto a fragment of a request.
func TestOverlongLineIsReportedAndEndsTheLoop(t *testing.T) {
	huge := `{"id":"1","method":"ping","pad":"` + strings.Repeat("x", maxRequestBytes+1024) + `"}`
	var w syncBuf
	s := newTestServer(&w)
	defer s.stop()
	s.readLoop(strings.NewReader(huge + "\n" + `{"id":"2","method":"ping"}` + "\n"))

	out := w.String()
	if !strings.Contains(out, `"event":"log"`) {
		t.Fatalf("no log event for the oversized line:\n%s", out)
	}
	if strings.Contains(out, `"id":"2"`) {
		t.Fatal("the loop kept reading after losing framing")
	}
}

func TestConcurrentRequestsAllGetAnswered(t *testing.T) {
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, `{"id":"`+string(rune('a'+i%26))+string(rune('0'+i/26))+`","method":"ping"}`)
	}
	msgs := run(t, lines...)
	if len(msgs) != 50 {
		t.Fatalf("got %d responses, want 50", len(msgs))
	}
	// Handlers run concurrently, so order is not promised — but every id must
	// come back exactly once.
	seen := map[string]int{}
	for _, m := range msgs {
		var id string
		_ = json.Unmarshal(m["id"], &id)
		seen[id]++
	}
	if len(seen) != 50 {
		t.Fatalf("got %d distinct ids, want 50", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("id %q answered %d times", id, n)
		}
	}
}

func assertErrorCode(t *testing.T, m map[string]json.RawMessage, wantID, wantCode string) {
	t.Helper()
	var id string
	_ = json.Unmarshal(m["id"], &id)
	if id != wantID {
		t.Fatalf("id = %q, want %q", id, wantID)
	}
	var ok bool
	_ = json.Unmarshal(m["ok"], &ok)
	if ok {
		t.Fatalf("expected a failure for id %s", wantID)
	}
	var we WireError
	if err := json.Unmarshal(m["error"], &we); err != nil {
		t.Fatalf("error field: %v", err)
	}
	if we.Code != wantCode {
		t.Fatalf("code = %q, want %q (message: %s)", we.Code, wantCode, we.Message)
	}
	if we.Message == "" {
		t.Fatal("error has no message")
	}
}
