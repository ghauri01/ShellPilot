package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// A keypair that is well-formed but wrong is the worst outcome this file can
// produce: the profile saves, the UI shows a public key the user pastes into
// their server, and the handshake never completes with nothing to point at.
// So the tests check the arithmetic, not the shape.

func decodeKey(t *testing.T, b64, what string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("%s is not base64: %v", what, err)
	}
	if len(raw) != 32 {
		t.Fatalf("%s decodes to %d bytes, want 32", what, len(raw))
	}
	return raw
}

func TestGenerateKeypairDerivesItsOwnPublicKey(t *testing.T) {
	res, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	priv := decodeKey(t, res.PrivateKey, "privateKey")
	pub := decodeKey(t, res.PublicKey, "publicKey")

	// Computed independently of publicKeyOf, so a bug in that helper cannot
	// agree with itself.
	want, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	if base64.StdEncoding.EncodeToString(want) != base64.StdEncoding.EncodeToString(pub) {
		t.Fatalf("publicKey is not the public half of privateKey")
	}
}

// `wg genkey` clamps, so a key ShellPilot generated must be byte-identical to
// one `wg` would have produced from the same entropy — otherwise a user who
// copies it into a wg-quick config gets a different file back from `wg pubkey`
// than the one they were shown here.
func TestGenerateKeypairClampsLikeWgGenkey(t *testing.T) {
	for i := 0; i < 200; i++ {
		res, err := generateKeypair()
		if err != nil {
			t.Fatalf("generateKeypair: %v", err)
		}
		priv := decodeKey(t, res.PrivateKey, "privateKey")
		if priv[0]&7 != 0 {
			t.Fatalf("low three bits of byte 0 are set: %08b", priv[0])
		}
		if priv[31]&128 != 0 {
			t.Fatalf("top bit of byte 31 is set: %08b", priv[31])
		}
		if priv[31]&64 == 0 {
			t.Fatalf("second bit of byte 31 is clear: %08b", priv[31])
		}
	}
}

func TestGenerateKeypairIsNotDeterministic(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		res, err := generateKeypair()
		if err != nil {
			t.Fatalf("generateKeypair: %v", err)
		}
		if seen[res.PrivateKey] {
			t.Fatal("generateKeypair returned the same private key twice")
		}
		seen[res.PrivateKey] = true
	}
}

func TestDerivePublicKeyAgreesWithGenerate(t *testing.T) {
	gen, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	got, err := derivePublicKey(gen.PrivateKey)
	if err != nil {
		t.Fatalf("derivePublicKey: %v", err)
	}
	if got.PublicKey != gen.PublicKey {
		t.Fatalf("derive gave %q, generate gave %q", got.PublicKey, gen.PublicKey)
	}
	// The caller already holds the private key; sending it back would put it
	// on the wire twice for no reason at all.
	if got.PrivateKey != "" {
		t.Fatal("derivePublicKey echoed the private key back")
	}
}

// Whitespace is what a paste out of a terminal looks like.
func TestDerivePublicKeyToleratesSurroundingWhitespace(t *testing.T) {
	gen, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	got, err := derivePublicKey("  " + gen.PrivateKey + "\n")
	if err != nil {
		t.Fatalf("derivePublicKey: %v", err)
	}
	if got.PublicKey != gen.PublicKey {
		t.Fatalf("whitespace changed the answer: %q vs %q", got.PublicKey, gen.PublicKey)
	}
}

// Every rejection path has to stay silent about what it was handed: the input
// is a private key, and an error message is the easiest place for one to
// escape onto a pipe the parent puts in a user-visible log ring.
func TestDerivePublicKeyNeverQuotesItsInput(t *testing.T) {
	cases := []struct{ name, in string }{
		{"empty", ""},
		{"not base64", "this-is-not-base64-!!!"},
		{"too short", base64.StdEncoding.EncodeToString([]byte("sixteen bytes.."))},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 64))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := derivePublicKey(c.in)
			if err == nil {
				t.Fatalf("expected a rejection, got %+v", res)
			}
			var ce *codedError
			if !errors.As(err, &ce) || ce.code != ErrConfigInvalid {
				t.Fatalf("error = %v, want a config-invalid codedError", err)
			}
			if c.in != "" && strings.Contains(err.Error(), c.in) {
				t.Fatalf("the rejected input was quoted back: %q", err.Error())
			}
		})
	}
}

// A 32-byte value `wg` would accept has to be accepted here too, even the
// degenerate ones: X25519 clamps internally, so the all-zero scalar becomes
// 2^254 and derives a perfectly ordinary point. Rejecting it would make
// ShellPilot disagree with `wg pubkey` about a key somebody already has.
func TestDerivePublicKeyAcceptsWhatWgWouldAccept(t *testing.T) {
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	res, err := derivePublicKey(zero)
	if err != nil {
		t.Fatalf("derivePublicKey: %v", err)
	}
	decodeKey(t, res.PublicKey, "publicKey")
}

// ---------------------------------------------------------------- dispatch

func keygenResult(t *testing.T, m map[string]json.RawMessage) KeygenResult {
	t.Helper()
	var ok bool
	_ = json.Unmarshal(m["ok"], &ok)
	if !ok {
		t.Fatalf("wg.keygen failed: %s", string(m["error"]))
	}
	var res KeygenResult
	if err := json.Unmarshal(m["result"], &res); err != nil {
		t.Fatalf("result: %v", err)
	}
	return res
}

func TestKeygenOverTheWireWithoutParams(t *testing.T) {
	msgs := run(t, `{"id":"1","method":"wg.keygen"}`)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1: %v", len(msgs), msgs)
	}
	res := keygenResult(t, msgs[0])
	decodeKey(t, res.PrivateKey, "privateKey")
	decodeKey(t, res.PublicKey, "publicKey")
}

func TestKeygenOverTheWireDerivesFromAPastedKey(t *testing.T) {
	gen, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	line, _ := json.Marshal(map[string]interface{}{
		"id": "1", "method": "wg.keygen",
		"params": map[string]string{"publicKeyFor": gen.PrivateKey},
	})
	msgs := run(t, string(line))
	res := keygenResult(t, msgs[0])
	if res.PublicKey != gen.PublicKey {
		t.Fatalf("publicKey = %q, want %q", res.PublicKey, gen.PublicKey)
	}
	if res.PrivateKey != "" {
		t.Fatal("the pasted private key came back in the response")
	}
}

func TestKeygenRejectsAMalformedPublicKeyFor(t *testing.T) {
	msgs := run(t, `{"id":"3","method":"wg.keygen","params":{"publicKeyFor":"nope"}}`)
	assertErrorCode(t, msgs[0], "3", ErrConfigInvalid)
}

// The whole point of doing this in the sidecar is that the key exists in one
// process for as long as it takes to encode a response. If it also reached the
// log stream the parent would put it in the ring buffer the log drawer shows.
func TestKeygenEmitsNoLogEvent(t *testing.T) {
	gen, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	line, _ := json.Marshal(map[string]interface{}{
		"id": "1", "method": "wg.keygen",
		"params": map[string]string{"publicKeyFor": gen.PrivateKey},
	})
	for _, msgs := range [][]map[string]json.RawMessage{
		run(t, `{"id":"1","method":"wg.keygen"}`),
		run(t, string(line)),
		run(t, `{"id":"1","method":"wg.keygen","params":{"publicKeyFor":"nope"}}`),
	} {
		for _, m := range msgs {
			if _, isEvent := m["event"]; isEvent {
				t.Fatalf("wg.keygen produced an event: %v", m)
			}
		}
	}
}
