package main

import (
	"context"
	"errors"
	"github.com/mr-jablon/runjet-agent/runner"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/protocol"
)

// The report deadline bounds one HTTP request. It must not be shared across a
// run: a context built before the command starts is spent by the time the
// verdict is sent, and the verdict is the one report that cannot be retried —
// the scheduler's sweeper then records a successful job as orphaned, which
// costs the word "orphaned" its meaning for every run in the fleet.
func TestExecuteReportsARunThatOutlastsTheReportTimeout(t *testing.T) {
	restore := reportTimeout
	reportTimeout = 200 * time.Millisecond
	t.Cleanup(func() { reportTimeout = restore })

	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.WriteHeader(http.StatusNoContent)
	}))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	secrets, err := loadSecrets("", logger)
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}
	jobs := jobRuntime{env: newJobEnv(jobUser{}, nil)}

	// Longer than reportTimeout, which is the whole point: the claim goes out
	// before the command and the verdict long after it.
	d := protocol.Dispatch{
		RunID:   "run-1",
		JobName: "slower than one report",
		Command: "sleep 0.6",
		Timeout: "10s",
	}
	execute(context.Background(), c, d, secrets, jobs, newInflight(), logger)

	var states []string
	for _, req := range ts.recorded() {
		if strings.HasSuffix(req.Path, "/status") {
			states = append(states, string(req.Body))
		}
	}
	if len(states) != 2 {
		t.Fatalf("posted %d status reports, want the claim and the outcome: %q", len(states), states)
	}
	if !strings.Contains(states[0], `"state":"running"`) {
		t.Errorf("first status = %s, want the claim", states[0])
	}
	if !strings.Contains(states[1], `"state":"finished"`) || !strings.Contains(states[1], `"success":true`) {
		t.Errorf("second status = %s, want a successful outcome", states[1])
	}
}

// The scheduler will not accept output or a verdict for a run it does not think
// this agent holds, so a claim it refuses leaves nothing useful to do. Running
// the command anyway would execute somebody's job and throw the result away.
func TestExecuteDoesNotRunACommandItCouldNotClaim(t *testing.T) {
	ts := newTestRunjet(t)
	var ran atomic.Bool
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		if strings.HasSuffix(r.URL.Path, "/status") {
			http.Error(w, "this run belongs to another agent", http.StatusConflict)
			return
		}
		ran.Store(true) // any output or heartbeat means the command started
		w.WriteHeader(http.StatusNoContent)
	}))

	marker := filepath.Join(t.TempDir(), "ran")
	execute(context.Background(), c, protocol.Dispatch{
		RunID: "run-1", JobName: "should not run",
		Command: "touch " + marker, Timeout: "10s",
	}, mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, newInflight(), discardLogger())

	if _, err := os.Stat(marker); err == nil {
		t.Error("the command ran although the run could not be claimed")
	}
	if ran.Load() {
		t.Error("the agent kept talking about a run the scheduler refused it")
	}
}

// A secret the agent cannot supply fails the run, and it fails it *after* the
// claim so the outcome is recorded. Left for the sweeper it would be blamed on a
// silent agent instead of on the missing value.
func TestExecuteReportsAMissingSecretAsAFailedRun(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.WriteHeader(http.StatusNoContent)
	}))

	execute(context.Background(), c, protocol.Dispatch{
		RunID: "run-1", JobName: "needs a secret", Command: "echo hello",
		Timeout: "10s", Secrets: []string{"NO_SUCH_SECRET"},
	}, mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, newInflight(), discardLogger())

	var states []string
	for _, req := range ts.recorded() {
		if strings.HasSuffix(req.Path, "/status") {
			states = append(states, string(req.Body))
		}
	}
	if len(states) != 2 {
		t.Fatalf("posted %d status reports, want the claim and the failure: %q", len(states), states)
	}
	if !strings.Contains(states[0], `"state":"running"`) {
		t.Errorf("first status = %s, want the claim to go out before the secret is resolved", states[0])
	}
	if !strings.Contains(states[1], `"success":false`) ||
		!strings.Contains(states[1], "NO_SUCH_SECRET") {
		t.Errorf("second status = %s, want a failure naming the secret", states[1])
	}
}

// describe phrases a failed outcome for the run record. "signal: killed" says
// nothing about why the process died, and the reasons mean opposite things to
// whoever opens the run afterwards.
func TestDescribeSaysWhoEndedTheRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome runner.Outcome
		stopped string
		want    string
	}{
		{
			name:    "runjet stopped it",
			outcome: runner.Outcome{Reason: runner.ReasonCancelled},
			stopped: "over the plan's limit",
			want:    "over the plan's limit",
		},
		{
			name:    "the agent was shutting down",
			outcome: runner.Outcome{Reason: runner.ReasonCancelled},
			want:    "killed by agent shutdown",
		},
		{
			name:    "it ran out of time",
			outcome: runner.Outcome{Reason: runner.ReasonTimeout},
			want:    "timed out",
		},
		{
			name:    "something held the output open",
			outcome: runner.Outcome{Reason: runner.ReasonStalled},
			want:    "background process holding its output",
		},
		{
			name:    "a stall runjet asked for is still runjet's doing",
			outcome: runner.Outcome{Reason: runner.ReasonStalled},
			stopped: "over the plan's limit",
			want:    "over the plan's limit",
		},
		{
			name:    "it simply failed",
			outcome: runner.Outcome{Reason: runner.ReasonExit, Err: errors.New("exit status 2")},
			want:    "exit status 2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := describe(tc.outcome, 30*time.Second, tc.stopped)
			if !strings.Contains(got, tc.want) {
				t.Errorf("describe() = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

// A timeout the agent cannot parse becomes no cap at all rather than a run that
// is killed immediately. The scheduler still holds the boundary, so the courtesy
// deadline being absent is survivable; a zero one would not be.
func TestExecuteTreatsAnUnparseableTimeoutAsNoCap(t *testing.T) {
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.WriteHeader(http.StatusNoContent)
	}))

	execute(context.Background(), c, protocol.Dispatch{
		RunID: "run-1", JobName: "nonsense timeout", Command: "echo hello", Timeout: "whenever",
	}, mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, newInflight(), discardLogger())

	var verdict string
	for _, req := range ts.recorded() {
		if strings.HasSuffix(req.Path, "/status") && strings.Contains(string(req.Body), "finished") {
			verdict = string(req.Body)
		}
	}
	if !strings.Contains(verdict, `"success":true`) {
		t.Errorf("verdict = %s, want the command to have run to completion", verdict)
	}
}

// The verdict is the one report that cannot be retried. When it cannot be sent
// the agent has to say so in its own log, because the run will be swept up as
// orphaned and the log is the only place the truth survives.
func TestExecuteSaysSoWhenAVerdictCannotBeReported(t *testing.T) {
	ts := newTestRunjet(t)
	var claimed atomic.Bool
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			if claimed.CompareAndSwap(false, true) {
				w.WriteHeader(http.StatusNoContent) // the claim goes through
				return
			}
			http.Error(w, "the lease expired", http.StatusGone) // the verdict does not
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	execute(context.Background(), c, protocol.Dispatch{
		RunID: "run-1", JobName: "orphaned", Command: "echo hello", Timeout: "10s",
	}, mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, newInflight(), logger)

	if !strings.Contains(logged.String(), "could not report outcome") {
		t.Errorf("a verdict that never reached the scheduler left no trace in the log:\n%s", logged.String())
	}
}

// The same for a run that failed before it started: if the failure cannot be
// reported either, the log is all there is.
func TestExecuteSaysSoWhenAMissingSecretCannotBeReported(t *testing.T) {
	ts := newTestRunjet(t)
	var claimed atomic.Bool
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			if claimed.CompareAndSwap(false, true) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Error(w, "the lease expired", http.StatusGone)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	execute(context.Background(), c, protocol.Dispatch{
		RunID: "run-1", JobName: "needs a secret", Command: "echo hello",
		Timeout: "10s", Secrets: []string{"NO_SUCH_SECRET"},
	}, mustSecrets(t), jobRuntime{env: newJobEnv(jobUser{}, nil)}, newInflight(), logger)

	if !strings.Contains(logged.String(), "could not report missing secret") {
		t.Errorf("the unreportable failure left no trace in the log:\n%s", logged.String())
	}
}
