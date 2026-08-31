package main

import (
	"errors"
	"strings"
	"testing"
)

// Test vectors from the WireGuard cross-platform UAPI documentation. These are
// the published example keys, not live material.
const (
	tvPrivB64 = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	tvPrivHex = "c809f3e5317e9575c9b5ed78b638b7ce530dabe85ddab614220241801ddf0669"
	tvPubB64  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	tvPubHex  = "c53201039adba14be71f886da1d8dbe9eebded08cb111b75340078999aa9f038"
	tvPskB64  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	tvPskHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

func TestKeyToHex(t *testing.T) {
	got, err := keyToHex(tvPrivB64, "private key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != tvPrivHex {
		t.Fatalf("got %s\nwant %s", got, tvPrivHex)
	}

	// Whitespace is what you get when a key was pasted out of a .conf file.
	if got, err := keyToHex("  "+tvPubB64+"\n", "public key"); err != nil || got != tvPubHex {
		t.Fatalf("trimming failed: %q %v", got, err)
	}

	for _, c := range []struct{ name, in string }{
		{"empty", ""},
		{"not base64", "this is not a key"},
		{"too short", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGA=="},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := keyToHex(c.in, "test key")
			if err == nil {
				t.Fatal("expected an error")
			}
			var ce *codedError
			if !errors.As(err, &ce) || ce.code != ErrConfigInvalid {
				t.Fatalf("want config-invalid, got %v", err)
			}
			// A rejected key must never appear in the message; the caller
			// pipes these straight into a user-visible log.
			if c.in != "" && strings.Contains(err.Error(), c.in) {
				t.Fatalf("error echoed the key material: %q", err.Error())
			}
		})
	}
}

// The exact UAPI text matters: the device parses it line by line and order is
// significant (replace_allowed_ips must precede the allowed_ip lines it
// applies to). Comparing the whole string is deliberate.
func TestBuildUAPIFullShape(t *testing.T) {
	p := &UpParams{
		TunnelID: "vpn-abc",
		Iface: IfaceParams{
			PrivateKey: tvPrivB64,
			Addresses:  []string{"10.0.0.2/32"},
			DNS:        []string{"10.0.0.1"},
			MTU:        1420,
		},
		Peers: []PeerParams{{
			PublicKey:           tvPubB64,
			PresharedKey:        tvPskB64,
			Endpoint:            "203.0.113.9:51820",
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
		}},
	}
	got, err := buildUAPI(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := strings.Join([]string{
		"private_key=" + tvPrivHex,
		"replace_peers=true",
		"public_key=" + tvPubHex,
		"preshared_key=" + tvPskHex,
		"endpoint=203.0.113.9:51820",
		"persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("uapi mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// E17: a /0 allowed-ip is passed through untouched. In userspace there is no
// route table to hijack, so special-casing it would break the single most
// common WireGuard configuration for no benefit.
func TestBuildUAPIKeepsDefaultRouteAllowedIP(t *testing.T) {
	p := &UpParams{
		Iface: IfaceParams{PrivateKey: tvPrivB64},
		Peers: []PeerParams{{
			PublicKey:  tvPubB64,
			Endpoint:   "203.0.113.9:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
	got, err := buildUAPI(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "allowed_ip=0.0.0.0/0\n") {
		t.Fatalf("0.0.0.0/0 did not survive:\n%s", got)
	}
}

func TestBuildUAPIOmitsOptionalLines(t *testing.T) {
	p := &UpParams{
		Iface: IfaceParams{PrivateKey: tvPrivB64},
		Peers: []PeerParams{{PublicKey: tvPubB64, AllowedIPs: []string{"10.0.0.0/24"}}},
	}
	got, err := buildUAPI(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, absent := range []string{"preshared_key=", "endpoint=", "persistent_keepalive_interval=", "listen_port="} {
		if strings.Contains(got, absent) {
			t.Errorf("emitted %q for an absent field:\n%s", absent, got)
		}
	}
	// replace_peers and replace_allowed_ips are unconditional: netd owns the
	// device, so every wg.up is authoritative rather than additive.
	for _, present := range []string{"replace_peers=true\n", "replace_allowed_ips=true\n"} {
		if !strings.Contains(got, present) {
			t.Errorf("missing %q:\n%s", present, got)
		}
	}
}

func TestBuildUAPIEmitsListenPortWhenPinned(t *testing.T) {
	p := &UpParams{
		Iface: IfaceParams{PrivateKey: tvPrivB64, ListenPort: 51820},
		Peers: []PeerParams{{PublicKey: tvPubB64, AllowedIPs: []string{"10.0.0.0/24"}}},
	}
	got, _ := buildUAPI(p)
	if !strings.Contains(got, "listen_port=51820\n") {
		t.Fatalf("listen_port missing:\n%s", got)
	}
}

func TestBuildUAPIMultiPeerOrdering(t *testing.T) {
	p := &UpParams{
		Iface: IfaceParams{PrivateKey: tvPrivB64},
		Peers: []PeerParams{
			{PublicKey: tvPubB64, AllowedIPs: []string{"10.0.1.0/24"}},
			{PublicKey: tvPskB64, AllowedIPs: []string{"10.0.2.0/24"}},
		},
	}
	got, err := buildUAPI(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// replace_peers appears exactly once, before any peer; each peer gets its
	// own replace_allowed_ips.
	if n := strings.Count(got, "replace_peers=true"); n != 1 {
		t.Fatalf("replace_peers appeared %d times:\n%s", n, got)
	}
	if n := strings.Count(got, "replace_allowed_ips=true"); n != 2 {
		t.Fatalf("replace_allowed_ips appeared %d times:\n%s", n, got)
	}
	if strings.Index(got, tvPubHex) > strings.Index(got, tvPskHex) {
		t.Fatal("peers were reordered")
	}
}

func TestBuildUAPIRejectsBadInput(t *testing.T) {
	base := func(mut func(*UpParams)) *UpParams {
		p := &UpParams{
			Iface: IfaceParams{PrivateKey: tvPrivB64},
			Peers: []PeerParams{{PublicKey: tvPubB64, Endpoint: "203.0.113.9:51820", AllowedIPs: []string{"0.0.0.0/0"}}},
		}
		mut(p)
		return p
	}
	cases := []struct {
		name string
		p    *UpParams
	}{
		{"no peers", base(func(p *UpParams) { p.Peers = nil })},
		{"bad private key", base(func(p *UpParams) { p.Iface.PrivateKey = "nope" })},
		{"bad public key", base(func(p *UpParams) { p.Peers[0].PublicKey = "nope" })},
		{"bad preshared key", base(func(p *UpParams) { p.Peers[0].PresharedKey = "nope" })},
		{"endpoint without a port", base(func(p *UpParams) { p.Peers[0].Endpoint = "vpn.example.com" })},
		{"allowed ip is not a CIDR", base(func(p *UpParams) { p.Peers[0].AllowedIPs = []string{"10.0.0.1"} })},
		{"keepalive out of range", base(func(p *UpParams) { p.Peers[0].PersistentKeepalive = 70000 })},
		{"listen port out of range", base(func(p *UpParams) { p.Iface.ListenPort = 70000 })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildUAPI(c.p); err == nil {
				t.Fatal("expected an error")
			} else {
				var ce *codedError
				if !errors.As(err, &ce) || ce.code != ErrConfigInvalid {
					t.Fatalf("want config-invalid, got %v", err)
				}
			}
		})
	}
}

func TestParseAddrsAcceptsCIDRAndBareAddress(t *testing.T) {
	got, err := parseAddrs([]string{"10.0.0.2/32", " fd00::2/128 ", "192.0.2.5"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.0.0.2", "fd00::2", "192.0.2.5"}
	if len(got) != len(want) {
		t.Fatalf("got %d addresses, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("addresses[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := parseAddrs(nil); err == nil {
		t.Fatal("an interface with no address should be rejected")
	}
	if _, err := parseAddrs([]string{"not-an-ip"}); err == nil {
		t.Fatal("a junk address should be rejected")
	}
}
