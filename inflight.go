package main

import (
	"context"
	"sync"
)

// inflight is what the agent is running right now, so the control plane can ask
// for one of them to stop.
//
// **This is the whole of "the agent enforces nothing".** The run timeout used to
// be the agent's own deadline and nothing else's, which was defensible while the
// agent was built from the control plane's tree. It is not defensible for a
// binary anybody can compile: a limit enforced by the thing being limited is a
// limit held by goodwill. The deadline stays — it is faster, and it works when
// the network does not — but it is now the agent's *courtesy* rather than the
// boundary, and the boundary is a decision made on the server.
//
// It is deliberately not a general remote-control channel. One verb, on a run
// this agent started, in a process that keeps running afterwards.
type inflight struct {
	mu  sync.Mutex
	run map[string]*runControl
}

// runControl is one executing run: how to stop it, and why it was stopped.
//
// The reason is stored beside the cancel func rather than passed through the
// context, because a cancelled context cannot say who cancelled it. Without it
// a run stopped by the control plane and a run stopped by the agent shutting
// down are the same event to the code that has to phrase the outcome — and they
// mean opposite things to the person reading that run afterwards.
type runControl struct {
	cancel context.CancelFunc
	mu     sync.Mutex
	reason string
}

// stop cancels the run and records why, ignoring a second attempt.
//
// First reason wins. A run that is already stopping because the agent is
// shutting down should not be relabelled by a cancellation that arrives in the
// same instant: the process is dying for the reason that got there first, and
// the later one did not cause anything.
func (r *runControl) stop(reason string) {
	r.mu.Lock()
	if r.reason == "" {
		r.reason = reason
	}
	r.mu.Unlock()
	r.cancel()
}

// stoppedBecause reports why this run was stopped, empty when nobody stopped it.
func (r *runControl) stoppedBecause() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reason
}

func newInflight() *inflight {
	return &inflight{run: make(map[string]*runControl)}
}

// add registers a run and returns its control plus the function that forgets it.
func (f *inflight) add(runID string, cancel context.CancelFunc) (*runControl, func()) {
	rc := &runControl{cancel: cancel}
	f.mu.Lock()
	f.run[runID] = rc
	f.mu.Unlock()
	return rc, func() {
		f.mu.Lock()
		delete(f.run, runID)
		f.mu.Unlock()
	}
}

// cancel stops a run if this agent is running it, and reports whether it was.
//
// A miss is the ordinary case rather than an error: the control plane repeats a
// pending cancellation on every poll, so the second one arrives after the run
// has already ended. Killing a process that is already dead costs one lookup
// that finds nothing, and that repetition is what makes the request survive an
// agent restarting between being asked and hearing about it.
func (f *inflight) cancel(runID, reason string) bool {
	f.mu.Lock()
	rc, ok := f.run[runID]
	f.mu.Unlock()
	if !ok {
		return false
	}
	rc.stop(reason)
	return true
}
