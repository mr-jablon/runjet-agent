// Package signing provides the Ed25519 trust primitives shared by the control
// plane and its agents: sealed envelopes for dispatched work, and signed
// requests for everything an agent reports back.
//
// Both directions verify the other. The scheduler seals every dispatch with its
// private key, so an agent executes nothing it cannot attribute to the
// scheduler; every agent request is signed, so the scheduler knows who is
// talking. Neither direction depends on TLS for authenticity — TLS is still
// required for confidentiality, since commands and their output carry secrets.
//
// Callers must map every error here to one indistinguishable rejection for the
// peer. The sentinel errors exist to make logs useful, not responses.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnknownKey     = errors.New("unknown key id")
	ErrBadSignature   = errors.New("signature verification failed")
	ErrStaleTimestamp = errors.New("timestamp outside the accepted window")
	ErrReplay         = errors.New("nonce already used")
	ErrMalformed      = errors.New("malformed envelope")
)

// Envelope carries a signed payload.
//
// The payload travels as opaque bytes and is verified before it is parsed.
// Signing exactly the bytes that go on the wire sidesteps canonical JSON:
// re-marshalling a struct can reorder fields or change escaping, which would
// invalidate a perfectly good signature. Verify first, then unmarshal.
type Envelope struct {
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`   // base64url, unpadded
	Signature string `json:"signature"` // base64, standard alphabet
}

// Signer holds one private key and the ID published with every signature.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewSigner validates the key material up front so a misconfigured key fails at
// startup rather than on the first dispatch.
func NewSigner(keyID string, priv ed25519.PrivateKey) (*Signer, error) {
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New("signing: key id is required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv))
	}
	return &Signer{keyID: keyID, priv: priv}, nil
}

// KeyID names the key this signer uses, so peers can select it from a ring.
func (s *Signer) KeyID() string { return s.keyID }

// Public returns the key peers need in order to verify this signer.
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Seal marshals payload and signs the exact bytes produced.
func (s *Signer) Seal(payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("signing: marshal payload: %w", err)
	}
	return Envelope{
		KeyID:     s.keyID,
		Payload:   base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, raw)),
	}, nil
}

// Sign produces the signature an agent sends in the X-Signature header.
func (s *Signer) Sign(q Request) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, q.signingString()))
}

// KeyRing is the set of public keys a verifier accepts. Holding more than one
// is what makes rotation possible: publish the new key, wait for every peer to
// pick it up, then retire the old one.
type KeyRing map[string]ed25519.PublicKey

// Open verifies an envelope and decodes its payload into `into`, which may be
// nil to verify without decoding. The signature is checked before any parsing
// happens, so malformed-but-signed and well-formed-but-forged are both refused
// before the payload reaches application code.
func (r KeyRing) Open(env Envelope, into any) error {
	pub, ok := r[env.KeyID]
	if !ok {
		return ErrUnknownKey
	}
	raw, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	if !ed25519.Verify(pub, raw, sig) {
		return ErrBadSignature
	}
	if into == nil {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("signing: decode payload: %w", err)
	}
	return nil
}

// Request is the set of components covered by a request signature.
type Request struct {
	Method    string // HTTP method, exactly as sent
	Path      string // path plus raw query, exactly as sent
	Timestamp int64  // unix seconds
	Nonce     string
	Body      []byte
}

// signingString builds the canonical string a request signature covers. The
// field order and the separator are part of the wire protocol: changing either
// invalidates every deployed agent, so it must move with a protocol version.
func (q Request) signingString() []byte {
	sum := sha256.Sum256(q.Body)
	return []byte(strings.Join([]string{
		q.Method,
		q.Path,
		strconv.FormatInt(q.Timestamp, 10),
		q.Nonce,
		hex.EncodeToString(sum[:]),
	}, "\n"))
}

// VerifyRequest checks a request signature against one public key.
func VerifyRequest(pub ed25519.PublicKey, signature string, q Request) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	if !ed25519.Verify(pub, q.signingString(), sig) {
		return ErrBadSignature
	}
	return nil
}

// CheckTimestamp rejects timestamps outside the clock-skew window in either
// direction. The window bounds how long a captured request stays replayable,
// and is what lets NonceCache forget entries instead of growing forever.
func CheckTimestamp(ts int64, now time.Time, skew time.Duration) error {
	delta := now.Sub(time.Unix(ts, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return ErrStaleTimestamp
	}
	return nil
}

// NonceCache remembers recently used nonces so a captured request cannot be
// replayed inside the clock-skew window. Entries only need to outlive that
// window: past it CheckTimestamp rejects the request anyway.
type NonceCache struct {
	ttl time.Duration
	now func() time.Time

	mu        sync.Mutex
	seen      map[string]time.Time
	nextPrune time.Time
}

// NewNonceCache builds a cache holding nonces for ttl, which should be at least
// twice the accepted clock skew so an entry cannot expire while the request
// that carried it is still considered fresh.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, now: time.Now, seen: make(map[string]time.Time)}
}

// Use records a nonce, reporting false if it was already used within the TTL.
func (c *NonceCache) Use(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if now.After(c.nextPrune) {
		c.prune(now)
		c.nextPrune = now.Add(c.ttl)
	}
	if usedAt, ok := c.seen[key]; ok && now.Sub(usedAt) < c.ttl {
		return false
	}
	c.seen[key] = now
	return true
}

// Len reports how many nonces are currently held, for tests and metrics.
func (c *NonceCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func (c *NonceCache) prune(now time.Time) {
	for key, usedAt := range c.seen {
		if now.Sub(usedAt) >= c.ttl {
			delete(c.seen, key)
		}
	}
}

// GenerateKey creates a new Ed25519 keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodeKey renders key material for configuration files and the UI.
func EncodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// ParsePublicKey reads a base64 public key from configuration.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("signing: decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing: public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads a base64 private key from configuration.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("signing: decode private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// ParseKeyRing reads the "id:base64[,id:base64…]" form used to tell an agent
// which scheduler keys it will accept. Listing several is how a key is rotated
// without downtime.
func ParseKeyRing(s string) (KeyRing, error) {
	ring := KeyRing{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, encoded, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("signing: key %q is not in id:base64 form", entry)
		}
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("signing: key id is empty in %q", entry)
		}
		if _, duplicate := ring[id]; duplicate {
			return nil, fmt.Errorf("signing: duplicate key id %q", id)
		}
		pub, err := ParsePublicKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("signing: key %q: %w", id, err)
		}
		ring[id] = pub
	}
	if len(ring) == 0 {
		return nil, errors.New("signing: no keys configured")
	}
	return ring, nil
}
