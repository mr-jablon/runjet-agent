package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
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
