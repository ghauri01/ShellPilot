package main

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// The Go redactor is the sidecar's last line of defence. Generating real
// 32-byte values rather than fixtures is the point: a fixture set agrees with
// whatever regex wrote it.
func TestRedactBlanksEveryRealKey(t *testing.T) {
	leaked := 0
	var sample string
	for i := 0; i < 2000; i++ {
		raw := make([]byte, 32)
		rand.Read(raw)
		// A real key's 43rd char is constrained by the encoding itself, so any
		// random 32 bytes produces a legitimately-shaped one.
		k := base64.StdEncoding.EncodeToString(raw)
		line := "configuring peer private_key " + k + " on utun4"
		if strings.Contains(redact(line), k) {
			leaked++
			if sample == "" {
				sample = k
			}
		}
	}
	if leaked > 0 {
		t.Fatalf("%d/2000 keys survived redaction, e.g. %q", leaked, sample)
	}
}

func TestRedactHandlesAdjacentKeys(t *testing.T) {
	a := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw := make([]byte, 32)
	rand.Read(raw)
	b := base64.StdEncoding.EncodeToString(raw)
	out := redact(a + " " + b)
	if strings.Contains(out, a) || strings.Contains(out, b) {
		t.Fatalf("adjacent keys not both redacted: %q", out)
	}
}

func TestRedactLeavesOrdinaryOutputAlone(t *testing.T) {
	long := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if !strings.Contains(redact("blob "+long), long) {
		t.Fatal("a longer base64 blob was eaten")
	}
}
