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
