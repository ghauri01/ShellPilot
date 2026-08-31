package main

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

// Key generation, so that making a peer of your own does not mean installing
// wireguard-tools.
//
// ShellPilot bundles everything needed to *run* WireGuard and, until this
// existed, nothing at all to make a key with. Importing a provider's `.conf`
// worked because the key is in the file; standing up your own peer meant
// `wg genkey` in a terminal, which meant installing the very package the
// bundled sidecar exists to avoid. This is that hole closed.
//
// It is short because the primitive is short. `wg genkey` is 32 bytes from the
// CSPRNG with the standard X25519 clamp; `wg pubkey` is one scalar-base
// multiplication of that. Both are already linked into this binary — the
// device package's key types and the curve25519 the handshake itself runs on —
// so there is no new dependency and no second implementation to keep honest.
//
// NOTHING HERE IS EVER LOGGED. redact() would blank a key anyway (a public and
// a private key are the same 32 bytes of base64 and cannot be told apart by
// shape), but relying on that would mean the private key had already been put
// into a string that something else might print. It is encoded straight into
// the response and written nowhere else — not a log event, not an error
// message, not even on the failure paths below, which is why none of them
// quote their input.

// generateKeypair mints a fresh private key and the public half that goes with
// it.
func generateKeypair() (*KeygenResult, error) {
	var sk device.NoisePrivateKey
	if _, err := rand.Read(sk[:]); err != nil {
		// No fallback source, deliberately. A "random" key from a degraded
		// generator is worse than no key at all, because it looks like it
		// worked and the tunnel it protects comes up normally.
		return nil, wrapCoded(ErrInternal, err, "could not read enough randomness for a new key")
	}
	// Standard X25519 clamping, the same wireguard-go applies to every private
	// key it loads. It does not change the public key — X25519 clamps the
	// scalar internally too — it changes the private key we hand back, so that
	// what the user stores is byte-for-byte what `wg genkey` would have
	// produced from the same entropy.
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64

	pk, err := publicKeyOf(sk)
	if err != nil {
		return nil, err
	}
	return &KeygenResult{
		PrivateKey: base64.StdEncoding.EncodeToString(sk[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pk[:]),
	}, nil
}

// derivePublicKey is `wg pubkey`: the public half of a private key the caller
// already has. The other half of why anyone runs `wg` by hand — an imported
// profile knows its private key and cannot otherwise say which public key the
// far end has to authorise.
func derivePublicKey(b64 string) (*KeygenResult, error) {
	t := strings.TrimSpace(b64)
	if t == "" {
		return nil, codedf(ErrConfigInvalid, "publicKeyFor is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		// Never echoes the input, and never passes err through: both would
		// quote a private key back onto a pipe the parent logs from.
		return nil, codedf(ErrConfigInvalid, "publicKeyFor is not valid base64")
	}
	if len(raw) != 32 {
		return nil, codedf(ErrConfigInvalid, "publicKeyFor decodes to %d bytes, expected 32", len(raw))
	}
	var sk device.NoisePrivateKey
	copy(sk[:], raw)
	// Not clamped. `wg pubkey` does not clamp either, and X25519 clamps its
	// scalar internally regardless, so the answer is the same one `wg` gives
	// for the same input — which is the only property that matters here.
	pk, err := publicKeyOf(sk)
	if err != nil {
		return nil, err
	}
	// PrivateKey is deliberately absent from the result: the caller already
	// has it, so echoing it would put it on the wire a second time for nothing.
	return &KeygenResult{PublicKey: base64.StdEncoding.EncodeToString(pk[:])}, nil
}

func publicKeyOf(sk device.NoisePrivateKey) (device.NoisePublicKey, error) {
	var pk device.NoisePublicKey
	out, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		// Unreachable today — the base-point path cannot produce the all-zero
		// output that is the only thing X25519 rejects — but the signature
		// says it can fail, and a key derivation is not the place to assume a
		// library will keep being unable to.
		return pk, wrapCoded(ErrInternal, err, "could not derive a public key")
	}
	copy(pk[:], out)
	return pk, nil
}
