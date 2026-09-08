package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/signing"
)

// run is the startup wiring, and the order in it is load-bearing: the secrets
// store and the job environment both take their copy before scrubEnv empties
// the real one, and the job account is proved usable before any work is taken.
// The pieces have tests of their own; what is tested here is that they are
// assembled, and that a host which cannot honour its configuration refuses to
// start rather than running jobs the operator did not ask for.

// agentEnv points a would-be agent at ts and gives it somewhere to keep state.
// Everything the agent reads is set here, so a variable left over from another
// test cannot change the outcome.
func agentEnv(t *testing.T, url, keys, stateDir string) {
	t.Helper()
	for _, kv := range [][2]string{
		{"RUNJET_URL", url},
		{"RUNJET_PUBLIC_KEYS", keys},
		{"AGENT_STATE_DIR", stateDir},
		{"AGENT_NAME", "test-host"},
		{"AGENT_JOB_USER", ""}, // jobs as the agent: no privilege needed to start
		{"AGENT_JOB_GROUP", ""},
		{"AGENT_SECRETS_FILE", ""},
		{"AGENT_PASS_ENV", ""},
		{"AGENT_MAX_PARALLEL", "2"},
		{"AGENT_POLL_WAIT", "1s"},
		{"ENROLLMENT_TOKEN", ""},
	} {
		t.Setenv(kv[0], kv[1])
	}
}

// storedIdentity writes an enrollment that has already happened, so a test can
// start an agent without one.
func storedIdentity(t *testing.T, stateDir string) {
	t.Helper()
	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg := config{StateDir: stateDir}
	if err := cfg.saveIdentity(identity{
		AgentID:    "agent-1",
		AgentName:  "test-host",
		PrivateKey: signing.EncodeKey(priv),
	}); err != nil {
		t.Fatalf("saveIdentity: %v", err)
	}
}

func keyRingFor(ts *testRunjet) string {
	return ts.signer.KeyID() + ":" + signing.EncodeKey(ts.signer.Public())
}

// The happy path, end to end: configuration read, identity reused, poll loop
// entered, and a clean stop on the signal a service manager sends.
func TestRunStartsPollsAndStopsOnSignal(t *testing.T) {
	ts := newTestRunjet(t)
	var polls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/agent/work") {
			atomic.AddInt64(&polls, 1)
			_ = json.NewEncoder(w).Encode(workResponse{})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	storedIdentity(t, dir)
	agentEnv(t, srv.URL, keyRingFor(ts), dir)
	// Something the agent must not pass on, to prove scrubEnv ran.
	t.Setenv("ENROLLMENT_TOKEN", "should-be-scrubbed")

	done := make(chan error, 1)
	go func() { done <- run(slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	// Signal only once the agent is demonstrably running, or the signal would
	// arrive before signal.NotifyContext is installed and kill the test binary.
	deadline := time.After(10 * time.Second)
	for atomic.LoadInt64(&polls) == 0 {
		select {
		case err := <-done:
			t.Fatalf("run returned before it ever polled: %v", err)
		case <-deadline:
			t.Fatal("the agent never polled")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v, want a clean stop", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after SIGTERM: a service manager's stop would time out")
	}

	if v := os.Getenv("ENROLLMENT_TOKEN"); v != "" {
		t.Errorf("ENROLLMENT_TOKEN survived startup as %q: scrubEnv did not run, and a job "+
			"sharing the agent's uid could read it out of /proc", v)
	}
}

// Configuration that cannot be honoured stops the agent. Each of these would
// otherwise surface as jobs failing one by one on a host nobody is watching.
func TestRunRefusesToStartOnUnusableConfiguration(t *testing.T) {
	ts := newTestRunjet(t)

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{
			name:  "no scheduler URL",
			setup: func(t *testing.T, _ string) { t.Setenv("RUNJET_URL", "") },
			want:  "RUNJET_URL is required",
		},
		{
			name:  "no scheduler keys",
			setup: func(t *testing.T, _ string) { t.Setenv("RUNJET_PUBLIC_KEYS", "") },
			want:  "RUNJET_PUBLIC_KEYS is required",
		},
		{
			name:  "a poll wait that is not a duration",
			setup: func(t *testing.T, _ string) { t.Setenv("AGENT_POLL_WAIT", "soon") },
			want:  "invalid AGENT_POLL_WAIT",
		},
		{
			name: "a secrets file that is not there",
			setup: func(t *testing.T, dir string) {
				t.Setenv("AGENT_SECRETS_FILE", filepath.Join(dir, "missing"))
			},
			want: "does not exist",
		},
		{
			name:  "a job account that cannot be resolved",
			setup: func(t *testing.T, _ string) { t.Setenv("AGENT_JOB_USER", "nobody-by-this-name") },
			want:  "AGENT_JOB_USER",
		},
		{
			name: "an identity file that cannot be parsed",
			setup: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "parse identity",
		},
		{
			name:  "no identity and no token to get one",
			setup: func(t *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, "identity.json")) },
			want:  "no stored identity and no ENROLLMENT_TOKEN",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			storedIdentity(t, dir)
			agentEnv(t, "http://runjet.invalid", keyRingFor(ts), dir)
			tc.setup(t, dir)

			err := run(slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil {
				t.Fatal("run returned no error, so the agent would have started and taken work")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("run error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// ensureEnrolled has two ways in — a stored identity, or a token spent now —
// and both have to end with the client able to sign, or every later request is
// refused for a reason that has nothing to do with the request.

func TestEnsureEnrolledReusesAStoredIdentity(t *testing.T) {
	dir := t.TempDir()
	storedIdentity(t, dir)

	ts := newTestRunjet(t)
	c := newClient("http://runjet.invalid", ts.ring())
	id, err := ensureEnrolled(context.Background(), config{StateDir: dir}, c,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("ensureEnrolled: %v", err)
	}
	if id.AgentID != "agent-1" {
		t.Errorf("agent id = %q, want the stored one", id.AgentID)
	}
	if c.signer == nil {
		t.Error("the client cannot sign after reusing an identity, so every request would be refused")
	}
}

func TestEnsureEnrolledSpendsATokenAndKeepsWhatItGetsBack(t *testing.T) {
	ts := newTestRunjet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSealed(t, w, ts.signer, enrollResponse{
			AgentID: "agent-9", AgentName: "fresh-host", KeyID: "sched-1",
			Protocol: 2, PollWait: "30s",
		})
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	cfg := config{StateDir: dir, RunjetURL: srv.URL, EnrollmentToken: "one-time"}
	c := newClient(srv.URL, ts.ring())

	id, err := ensureEnrolled(context.Background(), cfg, c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("ensureEnrolled: %v", err)
	}
	if id.AgentName != "fresh-host" {
		t.Errorf("agent name = %q, want the one the scheduler issued", id.AgentName)
	}
	if c.signer == nil {
		t.Fatal("the client cannot sign after enrolling")
	}

	// The point of writing it down: the next start must not spend a token again,
	// because the one it had is burned.
	stored, _, ok, err := cfg.loadIdentity()
	if err != nil || !ok {
		t.Fatalf("identity was not persisted (ok=%v, err=%v): the agent would try to re-enrol "+
			"with a token that is already spent", ok, err)
	}
	if stored.AgentID != "agent-9" {
		t.Errorf("stored agent id = %q, want agent-9", stored.AgentID)
	}
}

func TestEnsureEnrolledSurfacesARefusedEnrollment(t *testing.T) {
	ts := newTestRunjet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "that token is spent", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	cfg := config{StateDir: t.TempDir(), RunjetURL: srv.URL, EnrollmentToken: "already-used"}
	_, err := ensureEnrolled(context.Background(), cfg, newClient(srv.URL, ts.ring()),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("a refused enrollment was reported as success")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %v, want the scheduler's refusal in it", err)
	}
}

// The state directory is unreadable, so the agent cannot tell "never enrolled"
// from "enrolled and I cannot see it". Guessing the first would spend a fresh
// token and abandon a registration the scheduler still holds.
func TestEnsureEnrolledFailsWhenTheIdentityCannotBeRead(t *testing.T) {
	ts := newTestRunjet(t)

	// A regular file where the state directory should be: reading through it is
	// not "no such file", it is a broken host.
	blocked := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config{StateDir: blocked, EnrollmentToken: "one-time"}
	_, err := ensureEnrolled(context.Background(), cfg, newClient("http://runjet.invalid", ts.ring()),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("an unreadable state directory was taken for a host that has never enrolled")
	}
	if !strings.Contains(err.Error(), "read identity") {
		t.Errorf("error = %v, want it to say the identity could not be read", err)
	}
}

// The key came back but there is nowhere to put it. Reporting success here
// would leave an agent running on a spent token that cannot survive a restart.
func TestEnsureEnrolledFailsWhenTheIdentityCannotBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory, so the failure cannot be staged")
	}
	ts := newTestRunjet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSealed(t, w, ts.signer, enrollResponse{
			AgentID: "agent-9", AgentName: "fresh-host", KeyID: "sched-1", Protocol: 2,
		})
	}))
	t.Cleanup(srv.Close)

	// The directory is there — so there is no stored identity to find — but
	// nothing can be created in it.
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	cfg := config{StateDir: dir, RunjetURL: srv.URL, EnrollmentToken: "one-time"}
	_, err := ensureEnrolled(context.Background(), cfg, newClient(srv.URL, ts.ring()),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("enrollment reported success although the key was never written down")
	}
	if !strings.Contains(err.Error(), "write identity") {
		t.Errorf("error = %v, want it to say the identity could not be written", err)
	}
}

// Configured to isolate on a host that cannot: the agent refuses to start. It
// is the one case where starting would be worse than not starting, because the
// operator would believe in isolation that is not there.
func TestRunRefusesToStartWhereItCannotBecomeTheJobUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can become anybody, so the failure cannot be staged")
	}
	if _, err := user.Lookup("nobody"); err != nil {
		t.Skipf("no nobody account to point at: %v", err)
	}
	ts := newTestRunjet(t)
	dir := t.TempDir()
	storedIdentity(t, dir)
	agentEnv(t, "http://runjet.invalid", keyRingFor(ts), dir)
	t.Setenv("AGENT_JOB_USER", "nobody")

	err := run(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("the agent started without the privilege it was configured to use, so every " +
			"job on this host would fail at exec")
	}
	if !strings.Contains(err.Error(), "CAP_SETUID") {
		t.Errorf("error = %v, want it to say what the unit file is missing", err)
	}
}
