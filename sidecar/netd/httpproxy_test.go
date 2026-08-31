package main

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func readConnect(s string) (string, int, error) {
	return readConnectRequest(bufio.NewReaderSize(strings.NewReader(s), httpReadBufSize))
}

func TestReadConnectRequest(t *testing.T) {
	host, port, err := readConnect("CONNECT db.internal:5432 HTTP/1.1\r\nHost: db.internal:5432\r\nProxy-Connection: keep-alive\r\n\r\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "db.internal" || port != 5432 {
		t.Fatalf("got %q:%d", host, port)
	}
}

func TestReadConnectRequestDefaultsPort443(t *testing.T) {
	// Malformed per the RFC, but every proxy in the world treats a bare host
	// as :443 and refusing helps nobody.
	host, port, err := readConnect("CONNECT example.com HTTP/1.1\r\n\r\n")
	if err != nil || host != "example.com" || port != 443 {
		t.Fatalf("got %q:%d %v", host, port, err)
	}
}

func TestReadConnectRequestIPv6Target(t *testing.T) {
	host, port, err := readConnect("CONNECT [fd00::2]:8443 HTTP/1.1\r\n\r\n")
	if err != nil || host != "fd00::2" || port != 8443 {
		t.Fatalf("got %q:%d %v", host, port, err)
	}
}

func TestReadConnectRequestRejectsOtherMethods(t *testing.T) {
	// Absolute-form proxying is deliberately not implemented. 501 says so;
	// silently closing would look like a network fault.
	_, _, err := readConnect("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	var he *httpError
	if !errors.As(err, &he) || he.status != 501 {
		t.Fatalf("want 501, got %v", err)
	}
}

func TestReadConnectRequestRejectsGarbage(t *testing.T) {
	_, _, err := readConnect("hello\r\n\r\n")
	var he *httpError
	if !errors.As(err, &he) || he.status != 400 {
		t.Fatalf("want 400, got %v", err)
	}

	_, _, err = readConnect("CONNECT host:notaport HTTP/1.1\r\n\r\n")
	if !errors.As(err, &he) || he.status != 400 {
		t.Fatalf("want 400 for a non-numeric port, got %v", err)
	}
}

// E58: a client that sends header lines until we run out of memory must be
// stopped by an explicit cap, not by luck.
func TestReadConnectRequestBoundsHeaders(t *testing.T) {
	t.Run("too many lines", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("CONNECT example.com:443 HTTP/1.1\r\n")
		for i := 0; i < httpMaxHeaderLines+10; i++ {
			b.WriteString("X-Pad: x\r\n")
		}
		b.WriteString("\r\n")
		_, _, err := readConnect(b.String())
		var he *httpError
		if !errors.As(err, &he) || he.status != 431 {
			t.Fatalf("want 431, got %v", err)
		}
	})

	t.Run("one enormous line", func(t *testing.T) {
		// A single line longer than the read buffer must fail rather than
		// grow the buffer to fit it.
		big := "CONNECT example.com:443 HTTP/1.1\r\nX-Pad: " + strings.Repeat("x", httpReadBufSize*2) + "\r\n\r\n"
		_, _, err := readConnect(big)
		if err == nil {
			t.Fatal("an over-long header line was accepted")
		}
	})

	t.Run("many medium lines", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("CONNECT example.com:443 HTTP/1.1\r\n")
		// Stays under the line cap but blows the byte cap — the case a
		// line-count-only limit would miss.
		for i := 0; i < 100; i++ {
			b.WriteString("X-Pad: " + strings.Repeat("y", 1000) + "\r\n")
		}
		b.WriteString("\r\n")
		_, _, err := readConnect(b.String())
		var he *httpError
		if !errors.As(err, &he) || he.status != 431 {
			t.Fatalf("want 431, got %v", err)
		}
	})
}

func TestReadConnectRequestLeavesPipelinedBytes(t *testing.T) {
	// A client that writes the TLS ClientHello straight after the CONNECT
	// head leaves it in the reader. serveHTTPConnect forwards those bytes
	// before starting the relay; if it did not, the handshake would be
	// silently truncated.
	br := bufio.NewReaderSize(strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\n\r\n\x16\x03\x01EARLY"), httpReadBufSize)
	host, port, err := readConnectRequest(br)
	if err != nil || host != "example.com" || port != 443 {
		t.Fatalf("got %q:%d %v", host, port, err)
	}
	rest := make([]byte, br.Buffered())
	if _, err := br.Read(rest); err != nil {
		t.Fatalf("read leftover: %v", err)
	}
	if string(rest) != "\x16\x03\x01EARLY" {
		t.Fatalf("leftover = %q", rest)
	}
}
