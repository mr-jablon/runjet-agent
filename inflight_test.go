package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/runner"
)

// A cancellation reaches the process, and the runner kills the group the same
// way a timeout does. This is the property the whole of phase 1 rests on: the
// control plane decides, and the agent's own deadline stops being the boundary.
func TestCancellingAnInflightRunKillsIt(t *testing.T) {
	f := newInflight()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rc, forget := f.add("run-1", cancel)
	defer forget()

	done := make(chan runner.Outcome, 1)
	go func() {
		done <- runner.Run(ctx, runner.Spec{Command: "sleep 30"}, nil)
	}()

	// Let the process actually start, or the kill lands on nothing and the test
	// would pass without proving anything.
	time.Sleep(150 * time.Millisecond)
	if !f.cancel("run-1", "stopped by Runjet: over the plan's limit") {
		t.Fatal("a run this agent was holding was not found")
	}

	select {
	case o := <-done:
		if o.Reason != runner.ReasonCancelled {
			t.Errorf("Reason = %q, want %q", o.Reason, runner.ReasonCancelled)
		}
		if o.ExitCode != nil {
			t.Errorf("ExitCode = %d; a killed process has none", *o.ExitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command outlived its cancellation")
	}

	if got := rc.stoppedBecause(); got != "stopped by Runjet: over the plan's limit" {
		t.Errorf("stoppedBecause = %q, want the reason the control plane gave", got)
	}
}

// A miss is the ordinary case, not an error: the control plane repeats a
// pending cancellation on every poll, so the second one arrives after the run
// has already ended.
func TestCancellingAnUnknownRunIsHarmless(t *testing.T) {
	f := newInflight()
	if f.cancel("never-heard-of-it", "stopped") {
		t.Error("cancelling a run this agent is not holding reported success")
	}
}

// First reason wins. A run already dying because the agent is shutting down
// must not be relabelled by a cancellation landing in the same instant — the
// process is ending for the reason that got there first, and the later one
// caused nothing.
func TestTheFirstReasonWins(t *testing.T) {
	f := newInflight()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	rc, forget := f.add("run-2", cancel)
	defer forget()

	rc.stop("killed by agent shutdown")
	rc.stop("stopped by Runjet")

	if got := rc.stoppedBecause(); got != "killed by agent shutdown" {
		t.Errorf("stoppedBecause = %q, want the first reason", got)
	}
}

// forget removes the run, so a cancellation arriving after it finished finds
// nothing rather than killing whatever took its place in the map.
func TestForgettingARunRemovesIt(t *testing.T) {
	f := newInflight()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, forget := f.add("run-3", cancel)

	if !f.cancel("run-3", "while it was held") {
		t.Fatal("a held run was not found")
	}
	forget()
	if f.cancel("run-3", "after it was forgotten") {
		t.Error("a forgotten run was still cancellable")
	}
}

// The map is touched by the poll loop and by every run's goroutine at once.
func TestInflightIsSafeUnderConcurrentUse(t *testing.T) {
	f := newInflight()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, cancel := context.WithCancel(context.Background())
			defer cancel()
			id := string(rune('a' + i%26))
			_, forget := f.add(id, cancel)
			f.cancel(id, "concurrent")
			forget()
		}(i)
	}
	wg.Wait()
}
