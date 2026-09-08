package main

import (
	"context"
	"sync"
	"time"
)

// slots bounds how many runs execute at once, and the bound can move.
//
// A buffered channel was the obvious semaphore and cannot be resized, which
// matters here: the ceiling now arrives from the control plane on every poll and
// a plan changed at lunchtime has to take effect without restarting agents on
// machines nobody can reach.
//
// **Shrinking never interrupts anything.** A cap lowered below what is already
// running lets those runs finish and refuses the next one — the alternative is
// killing work to satisfy a number, which is the opposite of what a scheduler is
// for. The cap that matters is the one at the moment a run is about to start.
type slots struct {
	mu    sync.Mutex
	free  *sync.Cond
	cap   int
	held  int
	limit limit
}

// limit is the pair the agent reconciles: what the host allows and what the
// control plane allows.
//
// Kept apart rather than collapsed into one number, because they answer to
// different people and either can change without the other. The effective value
// is always the smaller — the agent may take less than it is allowed and never
// more than the host permits.
type limit struct {
	local  int
	remote int
}

// effective is the smaller of the two, and the local one alone when the control
// plane has not expressed a ceiling — an agent talking to a server too old to
// send them behaves exactly as it did before.
func (l limit) effective() int {
	if l.remote <= 0 {
		return l.local
	}
	if l.local <= 0 || l.remote < l.local {
		return l.remote
	}
	return l.local
}

func newSlots(local int) *slots {
	s := &slots{limit: limit{local: local}}
	s.cap = s.limit.effective()
	s.free = sync.NewCond(&s.mu)
	return s
}

// setRemote applies a ceiling from the control plane.
func (s *slots) setRemote(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.limit.remote == n {
		return
	}
	s.limit.remote = n
	s.cap = s.limit.effective()
	// A raised cap has to wake whoever is waiting, or a run would sit blocked
	// behind a limit that no longer exists until some unrelated run finished.
	s.free.Broadcast()
}

// current is the effective cap, for logs and tests.
func (s *slots) current() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cap
}

// acquire waits for room to run, and reports false when ctx ended first.
//
// The context is watched by a goroutine that broadcasts, because sync.Cond has
// no way to be woken by anything else. It is one goroutine per waiting run, and
// a run only waits when the agent is already at its ceiling.
func (s *slots) acquire(ctx context.Context) bool {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			s.free.Broadcast()
		case <-stop:
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()
	for s.held >= s.cap && ctx.Err() == nil {
		s.free.Wait()
	}
	if ctx.Err() != nil {
		return false
	}
	s.held++
	return true
}

func (s *slots) release() {
	s.mu.Lock()
	s.held--
	s.mu.Unlock()
	s.free.Broadcast()
}

// pollWaitFor reconciles the two poll cadences.
//
// The longer of the two wins, which is the opposite direction to the run cap and
// the same principle: the agent may only ever ask for *less*. A shorter wait
// than the server asked for means more requests than it wanted, which is the
// same overreach as running more jobs than it allowed, arriving from the other
// side.
func pollWaitFor(local, remote time.Duration) time.Duration {
	if remote > local {
		return remote
	}
	return local
}
