package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// An HTTP proxy that implements CONNECT and nothing else.
//
// Absolute-form GET/POST proxying (plain HTTP through the tunnel) is not
// implemented: it would mean this process parsing, buffering and re-emitting
// user traffic, and every client that matters — curl, git, the JVM, Node,
// every browser — issues CONNECT for https:// and can be pointed at the
// SOCKS5 listener for anything else. A tunnel process should move bytes, not
// interpret them.

const (
	httpHeaderTimeout = 30 * time.Second
	// Hard caps on the request head. A proxy that reads header lines until
	// the client stops is a memory-exhaustion bug waiting for a bad client
	// (E58), so the limits are explicit rather than implied by a buffer size.
	httpMaxHeaderBytes = 32 * 1024
	httpMaxHeaderLines = 200
	httpReadBufSize    = 8 * 1024
)

func serveHTTPConnect(ctx context.Context, t *Tunnel, c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(httpHeaderTimeout))
	br := bufio.NewReaderSize(c, httpReadBufSize)

	host, port, err := readConnectRequest(br)
	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
			writeHTTPError(c, he.status, he.reason)
		}
		return
	}

	upstream, derr := t.dial(ctx, host, port)
	if derr != nil {
		// 502 is the honest answer: we are a gateway and the far side did not
		// answer. The reason phrase is redacted like every other outbound
		// string, though a dial error should never carry key material.
		writeHTTPError(c, 502, "Bad Gateway")
		t.out.Log("warn", t.id, "http connect to "+hostPort(host, port)+": "+redact(derr.Error()))
		return
	}
	defer upstream.Close()

	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	// A client that pipelines — writing the TLS ClientHello immediately after
	// the CONNECT head without waiting for the 200 — has already left those
	// bytes in the bufio. Forwarding them before starting the relay is not an
	// optimisation; skipping it silently corrupts the stream.
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := br.Read(buf); err == nil {
			if _, err := upstream.Write(buf); err != nil {
				return
			}
		}
	}

	relay(ctx, c, upstream)
}

type httpError struct {
	status int
	reason string
}

func (e *httpError) Error() string { return strconv.Itoa(e.status) + " " + e.reason }

// readConnectRequest parses the request head and enforces the size caps. It
// leaves the reader positioned immediately after the blank line.
func readConnectRequest(br *bufio.Reader) (string, int, error) {
	line, err := readHTTPLine(br)
	if err != nil {
		return "", 0, err
	}
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return "", 0, &httpError{400, "Bad Request"}
	}
	method, target := parts[0], parts[1]
	if !strings.EqualFold(method, "CONNECT") {
		return "", 0, &httpError{501, "Not Implemented"}
	}

	host, portStr, serr := net.SplitHostPort(target)
	if serr != nil {
		// CONNECT without a port is malformed, but defaulting to 443 is what
		// every real proxy does and refusing helps nobody.
		host, portStr = target, "443"
	}
	port, perr := strconv.Atoi(portStr)
	if host == "" || perr != nil || port <= 0 || port > 65535 {
		return "", 0, &httpError{400, "Bad Request"}
	}

	// Drain the headers. Their contents are irrelevant to a CONNECT — we do
	// not offer proxy auth — but they must leave the stream.
	total := len(line)
	for i := 0; ; i++ {
		if i >= httpMaxHeaderLines {
			return "", 0, &httpError{431, "Request Header Fields Too Large"}
		}
		h, err := readHTTPLine(br)
		if err != nil {
			return "", 0, err
		}
		if h == "" {
			break
		}
		total += len(h)
		if total > httpMaxHeaderBytes {
			return "", 0, &httpError{431, "Request Header Fields Too Large"}
		}
	}
	return host, port, nil
}

// readHTTPLine reads one CRLF-terminated line, refusing anything longer than
// the buffer rather than growing to meet it.
func readHTTPLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", &httpError{431, "Request Header Fields Too Large"}
		}
		return "", err
	}
	if len(line) > httpReadBufSize {
		return "", &httpError{431, "Request Header Fields Too Large"}
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func writeHTTPError(c net.Conn, status int, reason string) {
	body := reason + "\n"
	_, _ = fmt.Fprintf(c,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, reason, len(body), body)
}
