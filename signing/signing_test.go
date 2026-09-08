package signing

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// A signature scheme that is subtly wrong still looks correct from the happy
// path: valid signatures verify either way. These tests exist to prove the
// rejection paths are real, so every case below feeds in something that must
// be refused.

type payload struct {
	RunID   string `json:"runId"`
	Command string `json:"command"`
}

func newSigner(t *testing.T, keyID string) *Signer {
	t.Helper()
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := NewSigner(keyID, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func ringFor(signers ...*Signer) KeyRing {
	ring := KeyRing{}
	for _, s := range signers {
		ring[s.KeyID()] = s.Public()
	}
	return ring
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newSigner(t, "sched-1")
	ring := ringFor(s)

	env, err := s.Seal(payload{RunID: "r-1", Command: "echo hello"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if env.KeyID != "sched-1" {
		t.Errorf("key id = %q, want sched-1", env.KeyID)
	}

	var got payload
	if err := ring.Open(env, &got); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.RunID != "r-1" || got.Command != "echo hello" {
		t.Errorf("payload round trip = %+v", got)
	}
}

func TestOpenRejectsTamperedPayload(t *testing.T) {
	s := newSigner(t, "sched-1")
	ring := ringFor(s)

	env, err := s.Seal(payload{RunID: "r-1", Command: "echo hello"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Swap the payload for a different, well-formed command — the attack the
	// envelope exists to stop.
	forged, err := s.Seal(payload{RunID: "r-1", Command: "rm -rf /"})
	if err != nil {
		t.Fatalf("seal forged: %v", err)
	}
	env.Payload = forged.Payload

	var got payload
	if err := ring.Open(env, &got); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("open tampered payload = %v, want ErrBadSignature", err)
	}
	if got.Command != "" {
		t.Errorf("payload was decoded despite a bad signature: %+v", got)
	}
}

func TestOpenRejectsTamperedSignature(t *testing.T) {
	s := newSigner(t, "sched-1")
	ring := ringFor(s)

	env, err := s.Seal(payload{RunID: "r-1"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	raw[0] ^= 0xff
	env.Signature = base64.StdEncoding.EncodeToString(raw)

	if err := ring.Open(env, &payload{}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("open tampered signature = %v, want ErrBadSignature", err)
	}
}

func TestOpenRejectsUnknownKeyID(t *testing.T) {
	known := newSigner(t, "sched-1")
	stranger := newSigner(t, "sched-99")

	env, err := stranger.Seal(payload{RunID: "r-1"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := ringFor(known).Open(env, &payload{}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("open unknown key = %v, want ErrUnknownKey", err)
	}
}

// An attacker who knows a valid key ID still cannot produce a valid signature
// for it.
func TestOpenRejectsImpersonatedKeyID(t *testing.T) {
	real := newSigner(t, "sched-1")
	impostor := newSigner(t, "sched-1")

	env, err := impostor.Seal(payload{RunID: "r-1", Command: "curl evil.example"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := ringFor(real).Open(env, &payload{}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("open impersonated key id = %v, want ErrBadSignature", err)
	}
}

func TestOpenRejectsMalformedEncoding(t *testing.T) {
	s := newSigner(t, "sched-1")
	ring := ringFor(s)
	env, err := s.Seal(payload{RunID: "r-1"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	cases := map[string]Envelope{
		"payload":   {KeyID: "sched-1", Payload: "!!not base64!!", Signature: env.Signature},
		"signature": {KeyID: "sched-1", Payload: env.Payload, Signature: "!!not base64!!"},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ring.Open(bad, &payload{}); !errors.Is(err, ErrMalformed) {
				t.Fatalf("open malformed %s = %v, want ErrMalformed", name, err)
			}
		})
	}
}

func testRequest() Request {
	return Request{
		Method:    "POST",
		Path:      "/agent/runs/r-1/output?seq=3",
		Timestamp: 1700000000,
		Nonce:     "bm9uY2U",
		Body:      []byte(`{"seq":3,"data":"hello"}`),
	}
}

func TestVerifyRequestRoundTrip(t *testing.T) {
	s := newSigner(t, "agent-1")
	q := testRequest()

	if err := VerifyRequest(s.Public(), s.Sign(q), q); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// Every component named in the signing string must actually be covered by it.
// A field left out would let an attacker rewrite that part of the request.
func TestVerifyRequestRejectsTamperedComponent(t *testing.T) {
	s := newSigner(t, "agent-1")
	original := testRequest()
	signature := s.Sign(original)

	cases := map[string]func(q *Request){
		"method":    func(q *Request) { q.Method = "DELETE" },
		"path":      func(q *Request) { q.Path = "/agent/runs/r-2/output?seq=3" },
		"query":     func(q *Request) { q.Path = "/agent/runs/r-1/output?seq=99" },
		"timestamp": func(q *Request) { q.Timestamp++ },
		"nonce":     func(q *Request) { q.Nonce = "b3RoZXI" },
		"body":      func(q *Request) { q.Body = []byte(`{"seq":3,"data":"goodbye"}`) },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			q := testRequest()
			tamper(&q)
			if err := VerifyRequest(s.Public(), signature, q); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("verify tampered %s = %v, want ErrBadSignature", name, err)
			}
		})
	}
}

func TestVerifyRequestRejectsOtherSigner(t *testing.T) {
	s := newSigner(t, "agent-1")
	other := newSigner(t, "agent-2")
	q := testRequest()

	if err := VerifyRequest(s.Public(), other.Sign(q), q); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("verify foreign signature = %v, want ErrBadSignature", err)
	}
}

func TestCheckTimestamp(t *testing.T) {
	now := time.Unix(1700000000, 0)
	const skew = 60 * time.Second

	cases := []struct {
		name    string
		ts      time.Time
		wantErr bool
	}{
		{"current", now, false},
		{"just inside the past window", now.Add(-59 * time.Second), false},
		{"just inside the future window", now.Add(59 * time.Second), false},
		{"too old", now.Add(-61 * time.Second), true},
		{"too far ahead", now.Add(61 * time.Second), true},
		{"replayed a day later", now.Add(-24 * time.Hour), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckTimestamp(c.ts.Unix(), now, skew)
			if c.wantErr && !errors.Is(err, ErrStaleTimestamp) {
				t.Fatalf("CheckTimestamp = %v, want ErrStaleTimestamp", err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("CheckTimestamp = %v, want nil", err)
			}
		})
	}
}

func TestNonceCacheRejectsReplay(t *testing.T) {
	c := NewNonceCache(2 * time.Minute)

	if !c.Use("agent-1:abc") {
		t.Fatal("first use was rejected")
	}
	if c.Use("agent-1:abc") {
		t.Fatal("replayed nonce was accepted")
	}
	// The same nonce from a different agent is a different key entirely.
	if !c.Use("agent-2:abc") {
		t.Fatal("nonce from another agent was rejected")
	}
}

func TestNonceCacheForgetsAfterTTL(t *testing.T) {
	c := NewNonceCache(2 * time.Minute)
	clock := time.Unix(1700000000, 0)
	c.now = func() time.Time { return clock }

	if !c.Use("agent-1:abc") {
		t.Fatal("first use was rejected")
	}

	// Still inside the window: the replay must not get through.
	clock = clock.Add(90 * time.Second)
	if c.Use("agent-1:abc") {
		t.Fatal("replay inside the TTL was accepted")
	}

	// Past the window the entry is forgotten, which is safe because a request
	// carrying it would already fail CheckTimestamp.
	clock = clock.Add(4 * time.Minute)
	if !c.Use("agent-1:abc") {
		t.Fatal("nonce was still remembered past its TTL")
	}
	if got := c.Len(); got != 1 {
		t.Errorf("cache holds %d entries after pruning, want 1", got)
	}
}

func TestParseKeyRing(t *testing.T) {
	a := newSigner(t, "sched-a")
	b := newSigner(t, "sched-b")
	encoded := "sched-a:" + EncodeKey(a.Public()) + ", sched-b:" + EncodeKey(b.Public())

	ring, err := ParseKeyRing(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ring) != 2 {
		t.Fatalf("ring has %d keys, want 2", len(ring))
	}

	// Both keys must actually work — rotation depends on it.
	for _, s := range []*Signer{a, b} {
		env, err := s.Seal(payload{RunID: "r-1"})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if err := ring.Open(env, &payload{}); err != nil {
			t.Errorf("open with key %s: %v", s.KeyID(), err)
		}
	}
}

func TestParseKeyRingRejectsBadInput(t *testing.T) {
	valid := EncodeKey(newSigner(t, "sched-a").Public())

	cases := map[string]string{
		"empty":          "",
		"no id":          valid,
		"empty id":       ":" + valid,
		"bad base64":     "sched-a:!!!",
		"wrong length":   "sched-a:" + base64.StdEncoding.EncodeToString([]byte("short")),
		"duplicate id":   "sched-a:" + valid + ",sched-a:" + valid,
		"only separator": ",",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKeyRing(input); err == nil {
				t.Fatalf("ParseKeyRing(%q) succeeded, want an error", input)
			}
		})
	}
}

func TestNewSignerRejectsBadKey(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := NewSigner("", priv); err == nil {
		t.Error("NewSigner accepted an empty key id")
	}
	if _, err := NewSigner("sched-1", priv[:10]); err == nil {
		t.Error("NewSigner accepted a truncated private key")
	}
}

func TestParsePublicKeyRejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	if _, err := ParsePublicKey(short); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("ParsePublicKey(short) = %v, want a length error", err)
	}
}

// Callers must map every error here to one indistinguishable rejection, but the
// sentinels have to be right for the logs to be worth reading — and Open must
// refuse before it parses, so a well-signed payload that is nonsense and a
// forged one that is well-formed both stop at the same place.

// Verification comes first; only then is the payload decoded. A signed payload
// that will not fit the caller's type is a different failure from a forgery,
// and saying so is what keeps a protocol mistake from reading as an attack.
func TestOpenSeparatesAForgeryFromAPayloadThatWillNotFit(t *testing.T) {
	signer, ring := testSignerAndRing(t)

	env, err := signer.Seal(map[string]string{"runId": "run-1"})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var wrong struct {
		RunID int `json:"runId"` // the payload says string
	}
	err = ring.Open(env, &wrong)
	if err == nil {
		t.Fatal("a payload that does not fit the target was accepted")
	}
	if errors.Is(err, ErrBadSignature) {
		t.Error("a decoding failure was reported as a bad signature, which reads as an attack")
	}
	if !strings.Contains(err.Error(), "decode payload") {
		t.Errorf("error = %v, want it to say the payload could not be decoded", err)
	}
}

// Verifying without decoding is how a caller checks authenticity when it has no
// use for the contents.
func TestOpenVerifiesWithoutDecodingWhenAskedTo(t *testing.T) {
	signer, ring := testSignerAndRing(t)
	env, err := signer.Seal(map[string]string{"runId": "run-1"})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if err := ring.Open(env, nil); err != nil {
		t.Errorf("Open with no target = %v, want nil", err)
	}

	env.Signature = "AAAA"
	if err := ring.Open(env, nil); err == nil {
		t.Error("a forged envelope passed verification when no target was given")
	}
}

// Seal signs the exact bytes it produces. A payload that cannot be marshalled
// must fail here rather than travel as an envelope around nothing.
func TestSealRefusesAPayloadItCannotMarshal(t *testing.T) {
	signer, _ := testSignerAndRing(t)

	if _, err := signer.Seal(make(chan int)); err == nil {
		t.Fatal("Seal accepted a payload that cannot be marshalled")
	}
}

// A signature that is not base64 is malformed, not forged, and the two are
// worth telling apart in a log.
func TestVerifyRequestSeparatesMalformedFromForged(t *testing.T) {
	signer, _ := testSignerAndRing(t)
	q := Request{Method: "GET", Path: "/agent/work", Timestamp: 1, Nonce: "n"}

	err := VerifyRequest(signer.Public(), "not base64 at all!!", q)
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("VerifyRequest with an unparseable signature = %v, want ErrMalformed", err)
	}
}

// A private key of the wrong length cannot sign, and configuration is where
// that must be caught.
func TestParsePrivateKeyRejectsWhatCannotSign(t *testing.T) {
	if _, err := ParsePrivateKey("not base64 at all!!"); err == nil {
		t.Error("ParsePrivateKey accepted something that is not base64")
	}
	if _, err := ParsePrivateKey(EncodeKey([]byte("too short"))); err == nil {
		t.Error("ParsePrivateKey accepted a key of the wrong size")
	}

	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	round, err := ParsePrivateKey(EncodeKey(priv))
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if !round.Equal(priv) {
		t.Error("a key did not survive the round trip through configuration")
	}
}

// testSignerAndRing is one scheduler and the ring an agent would trust it by.
func testSignerAndRing(t *testing.T) (*Signer, KeyRing) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := NewSigner("sched-1", priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer, KeyRing{"sched-1": pub}
}
