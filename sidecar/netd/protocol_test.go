package main

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every code this binary can emit must exist in the TypeScript VpnErrorCode
// union, because the renderer switches on it to pick the "how to fix" copy.
// Reading the real file rather than a copied list is the point: a rename on
// the TS side breaks this test instead of silently producing an errorCode the
// UI has no branch for.
func TestErrorCodesExistInSharedVpnTs(t *testing.T) {
	const rel = "../../src/shared/vpn.ts"
	src, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("could not read %s: %v", rel, err)
	}
	start := bytes.Index(src, []byte("export type VpnErrorCode"))
	if start < 0 {
		t.Fatal("VpnErrorCode union not found in src/shared/vpn.ts")
	}
	// The union runs to the first blank line after the declaration.
	rest := src[start:]
	if end := bytes.Index(rest, []byte("\n\n")); end > 0 {
		rest = rest[:end]
	}
	member := regexp.MustCompile(`'([a-z0-9-]+)'`)
	union := map[string]bool{}
	for _, m := range member.FindAllSubmatch(rest, -1) {
		union[string(m[1])] = true
	}
	if len(union) < 10 {
		t.Fatalf("only parsed %d union members; the parser is wrong, not the code", len(union))
	}
	for code := range knownCodes {
		if !union[code] {
			t.Errorf("netd emits %q, which is not a member of the TS VpnErrorCode union", code)
		}
	}
}

func TestRedactScrubsKeyShapes(t *testing.T) {
	// A real 32-byte base64 key and its hex form. Neither is a live key.
	const b64 = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	const hexKey = "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab6142202418001ddf066"

	cases := []struct{ name, in string }{
		{"base64 alone", b64},
		{"base64 in prose", "peer rejected key " + b64 + " at 10:01"},
		{"uapi hex assignment", "private_key=" + hexKey},
		{"preshared hex", "preshared_key=" + hexKey + " endpoint=1.2.3.4:51820"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redact(c.in)
			if strings.Contains(got, b64) || strings.Contains(got, hexKey) {
				t.Fatalf("key survived redaction: %q", got)
			}
			if !strings.Contains(got, placeholder) {
				t.Fatalf("expected a placeholder in %q", got)
			}
		})
	}

	// Ordinary text must not be mangled — a redactor that eats endpoints and
	// error messages is worse than useless.
	keep := "could not connect to db.internal:5432 through the tunnel"
	if redact(keep) != keep {
		t.Fatalf("redact damaged ordinary text: %q", redact(keep))
	}
}

func TestToWireErrorClassifies(t *testing.T) {
	t.Run("coded errors keep their code", func(t *testing.T) {
		we := toWireError(codedf(ErrPortInUse, "Port 1080 on 127.0.0.1 is already in use."))
		if we.Code != ErrPortInUse {
			t.Fatalf("code = %q", we.Code)
		}
		if !strings.Contains(we.Message, "1080") {
			t.Fatalf("message lost the port: %q", we.Message)
		}
	})

	t.Run("unclassified errors become internal", func(t *testing.T) {
		we := toWireError(errString("something went sideways"))
		if we.Code != ErrInternal {
			t.Fatalf("code = %q, want internal", we.Code)
		}
	})

	t.Run("a code we do not own is not passed through", func(t *testing.T) {
		// Guards against a typo'd constant reaching the renderer as an
		// errorCode with no matching branch.
		we := toWireError(&codedError{code: "made-up-code", msg: "x"})
		if we.Code != ErrInternal {
			t.Fatalf("code = %q, want internal", we.Code)
		}
	})

	t.Run("messages are redacted", func(t *testing.T) {
		const b64 = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
		we := toWireError(codedf(ErrConfigInvalid, "bad key %s", b64))
		if strings.Contains(we.Message, b64) {
			t.Fatalf("wire error leaked a key: %q", we.Message)
		}
	})
}

type errString string

func (e errString) Error() string { return string(e) }

// The writer is the one place where a formatting mistake desynchronises the
// parent's parser for good, so assert the framing directly.
func TestWriterEmitsOneJSONObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.Respond("7", map[string]int{"port": 1080})
	w.Fail("8", codedf(ErrPortInUse, "Port 1080 on 127.0.0.1 is already in use."))
	w.Emit("wg.state", &StateData{TunnelID: "vpn-abc", State: "connected"})
	w.Log("info", "vpn-abc", "hello")

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4:\n%s", len(lines), buf.String())
	}
	for i, l := range lines {
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("line %d is not JSON: %v (%q)", i, err, l)
		}
	}

	var ok Response
	_ = json.Unmarshal([]byte(lines[0]), &ok)
	if ok.ID != "7" || !ok.OK {
		t.Fatalf("success response = %+v", ok)
	}

	var bad Response
	_ = json.Unmarshal([]byte(lines[1]), &bad)
	if bad.ID != "8" || bad.OK || bad.Error == nil || bad.Error.Code != ErrPortInUse {
		t.Fatalf("failure response = %+v", bad)
	}
	// A failure must not carry a result key; the parent branches on `ok` and
	// then reads one or the other.
	if strings.Contains(lines[1], `"result"`) {
		t.Fatalf("failure response carried a result: %s", lines[1])
	}

	// Events carry no id — that is how the parent tells them from responses.
	if strings.Contains(lines[2], `"id"`) {
		t.Fatalf("event carried an id: %s", lines[2])
	}
	var ev Event
	_ = json.Unmarshal([]byte(lines[2]), &ev)
	if ev.Event != "wg.state" {
		t.Fatalf("event = %+v", ev)
	}
}
