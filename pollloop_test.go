package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/protocol"
	"github.com/mr-jablon/runjet-agent/signing"
)

// The poll loop is the only way anything reaches this agent. Whatever else it
// is doing, it has to keep asking — a loop that stops polling is an agent that
// cannot be told anything, and the control plane has no other way in.

// A cap reached is the ordinary state of a busy host, not an exceptional one.
// Waiting for a slot inside the loop stops the polling, and what arrives on a
// poll is the cancellation that would free the slot being waited for — so the
// agent could only be unstuck by the very run it had been asked to stop. The
// run waits off to one side instead.
func TestPollLoopKeepsPollingWhileItIsAtTheCap(t *testing.T) {
	ts := newTestRunjet(t)
	var polls int64

	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/agent/work") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// The first answer fills the host and leaves one dispatch over.
		if atomic.AddInt64(&polls, 1) == 1 {
			writeWork(t, w, ts,
				protocol.Dispatch{RunID: "a", JobName: "long", Command: "sleep 30", Timeout: "60s"},
				protocol.Dispatch{RunID: "b", JobName: "queued", Command: "echo hi", Timeout: "60s"})
			return
		}
		_ = json.NewEncoder(w).Encode(workResponse{})
	}))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	secrets, err := loadSecrets("", logger)
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}
	cfg := config{MaxParallel: 1, PollWait: 50 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		pollLoop(ctx, cfg, c, secrets, jobRuntime{env: newJobEnv(jobUser{}, nil)}, logger)
		close(done)
	}()

	time.Sleep(time.Second)
	if got := atomic.LoadInt64(&polls); got < 3 {
		t.Errorf("polls = %d in a second at a 50ms wait: the loop stopped asking "+
			"while it held a dispatch it had no room for", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("pollLoop did not return after its context ended")
	}
}

// writeWork seals dispatches the way the scheduler does and answers a poll with
// them.
func writeWork(t *testing.T, w http.ResponseWriter, ts *testRunjet, dispatches ...protocol.Dispatch) {
	t.Helper()
	var envs []signing.Envelope
	for _, d := range dispatches {
		d.Protocol = protocol.AgentProtocolVersion
		env, err := ts.signer.Seal(d)
		if err != nil {
			t.Errorf("seal: %v", err)
			return
		}
		envs = append(envs, env)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(workResponse{Dispatches: envs}); err != nil {
		t.Errorf("encode work: %v", err)
	}
}

// A ceiling from the control plane has to take effect on the same poll that
// carried it, and the agent may only ever take *less*: less parallelism, and a
// longer wait between polls. Both directions are what keep a plan limit from
// being raised by editing this host's environment.
func TestPollLoopAppliesTheCeilingsItIsSent(t *testing.T) {
	ts := newTestRunjet(t)
	waits := make(chan string, 8)

	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/agent/work") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case waits <- r.URL.Query().Get("wait"):
		default:
		}
		env, err := ts.signer.Seal(protocol.Limits{
			MaxParallel: 1, PollWait: "7s", Protocol: protocol.AgentProtocolVersion,
		})
		if err != nil {
			t.Errorf("seal: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(workResponse{Limits: &env})
	}))

	cfg := config{MaxParallel: 4, PollWait: 50 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		pollLoop(ctx, cfg, c, mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, discardLogger())
		close(done)
	}()

	first := <-waits
	if first != "0" {
		t.Errorf("first poll asked to wait %qs, want this host's own 50ms rounded to 0", first)
	}
	// The second poll must already be using the wait the scheduler asked for.
	var second string
	select {
	case second = <-waits:
	case <-time.After(3 * time.Second):
		t.Fatal("there was no second poll")
	}
	if second != "7" {
		t.Errorf("second poll asked to wait %qs, want 7 — the longer of the two", second)
	}

	cancel()
	<-done
}

// A scheduler that is down must not take the agent with it: the poll backs off
// and comes back, because the machine it is on is one nobody can reach to
// restart it.
func TestPollLoopBacksOffAndRecoversFromAFailedPoll(t *testing.T) {
	ts := newTestRunjet(t)
	var polls int64

	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/agent/work") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if atomic.AddInt64(&polls, 1) == 1 {
			http.Error(w, "the scheduler is restarting", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(workResponse{})
	}))

	cfg := config{MaxParallel: 1, PollWait: 50 * time.Millisecond}
	// Long enough to outlast one pollBackoff, so the recovery is what is tested
	// rather than the giving up.
	ctx, cancel := context.WithTimeout(context.Background(), pollBackoff+4*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		pollLoop(ctx, cfg, c, mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, discardLogger())
		close(done)
	}()

	deadline := time.After(pollBackoff + 3*time.Second)
	for atomic.LoadInt64(&polls) < 2 {
		select {
		case <-deadline:
			t.Fatalf("the agent polled %d times and gave up: a scheduler restart would strand this host",
				atomic.LoadInt64(&polls))
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// Shutdown must not wait out a backoff. A service manager that asked the agent
// to stop gets it stopped, not five seconds later.
func TestPollLoopStopsImmediatelyDuringABackoff(t *testing.T) {
	ts := newTestRunjet(t)
	polled := make(chan struct{}, 1)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/agent/work") {
			select {
			case polled <- struct{}{}:
			default:
			}
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollLoop(ctx, config{MaxParallel: 1, PollWait: 50 * time.Millisecond}, c,
			mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, discardLogger())
		close(done)
	}()

	<-polled // now it is inside the backoff
	cancel()
	select {
	case <-done:
	case <-time.After(pollBackoff):
		t.Fatal("pollLoop sat out the whole backoff before noticing it had been asked to stop")
	}
}

// A cancellation reaches the run it names. This is the whole of "the agent
// enforces nothing": the boundary is a decision made on the server, and it only
// means anything if the agent acts on it.
func TestPollLoopStopsTheRunItIsToldTo(t *testing.T) {
	ts := newTestRunjet(t)
	var claimed atomic.Bool
	var polls int64

	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/agent/work"):
			n := atomic.AddInt64(&polls, 1)
			if n == 1 {
				writeWork(t, w, ts, protocol.Dispatch{
					RunID: "run-1", JobName: "long", Command: "sleep 30", Timeout: "60s",
				})
				return
			}
			if !claimed.Load() {
				_ = json.NewEncoder(w).Encode(workResponse{})
				return
			}
			env, err := ts.signer.Seal(protocol.Cancel{
				RunID: "run-1", Reason: "over the plan's limit",
				Protocol: protocol.AgentProtocolVersion,
			})
			if err != nil {
				t.Errorf("seal: %v", err)
				return
			}
			_ = json.NewEncoder(w).Encode(workResponse{Cancel: []signing.Envelope{env}})
		case strings.HasSuffix(r.URL.Path, "/status"):
			body := ts.record(r)
			if strings.Contains(string(body), `"state":"running"`) {
				claimed.Store(true)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		pollLoop(ctx, config{MaxParallel: 2, PollWait: 50 * time.Millisecond}, c,
			mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, discardLogger())
		close(done)
	}()

	// The run must end long before its own 60s timeout, and say why.
	deadline := time.After(15 * time.Second)
	for {
		var verdict string
		for _, req := range ts.recorded() {
			if strings.HasSuffix(req.Path, "/status") && strings.Contains(string(req.Body), `"finished"`) {
				verdict = string(req.Body)
			}
		}
		if verdict != "" {
			if !strings.Contains(verdict, "over the plan's limit") {
				t.Errorf("verdict = %s, want the reason Runjet gave rather than the agent's own reading",
					verdict)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("the cancelled run never reported an outcome")
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// mustSecrets is an empty store, for loops that never resolve one.
func mustSecrets(t *testing.T) *secretStore {
	t.Helper()
	s, err := loadSecrets("", discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}
	return s
}
