package main

import (
	"context"
	"testing"
	"time"
)

// The ceiling is the smaller of the two, and which side it came from does not
// matter. This is what makes "the agent enforces nothing" true without handing
// the control plane the ability to fork two hundred processes on somebody's
// production box.
func TestTheEffectiveCapIsTheSmallerOfTheTwo(t *testing.T) {
	cases := []struct {
		name          string
		local, remote int
		want          int
	}{
		{"the plan is tighter", 8, 4, 4},
		{"the host is tighter", 2, 10, 2},
		{"they agree", 4, 4, 4},
		// A server too old to send limits leaves the host's setting alone,
		// which is exactly what an agent did before they existed.
		{"the server said nothing", 6, 0, 6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSlots(c.local)
			s.setRemote(c.remote)
			if got := s.current(); got != c.want {
				t.Errorf("cap = %d, want %d", got, c.want)
			}
		})
	}
}

// The cap actually bounds execution rather than only being reported.
func TestAcquireBlocksAtTheCap(t *testing.T) {
	s := newSlots(2)
	ctx := context.Background()

	if !s.acquire(ctx) || !s.acquire(ctx) {
		t.Fatal("the first two runs were refused their slots")
	}

	// A third has to wait, so a context that ends first must return false
	// rather than block forever.
	tight, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if s.acquire(tight) {
		t.Error("a third run started while two of two slots were held")
	}

	// Releasing one lets it through.
	s.release()
	done := make(chan bool, 1)
	go func() { done <- s.acquire(ctx) }()
	select {
	case ok := <-done:
		if !ok {
			t.Error("a run was refused a slot that had been released")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("releasing a slot did not wake the run waiting for it")
	}
}

// **Lowering the cap never interrupts what is already running.** Killing work to
// satisfy a number is the opposite of what a scheduler is for; the cap that
// matters is the one at the moment the next run is about to start.
func TestLoweringTheCapLetsRunningWorkFinish(t *testing.T) {
	s := newSlots(4)
	ctx := context.Background()
	for range 3 {
		if !s.acquire(ctx) {
			t.Fatal("a run was refused a slot below the cap")
		}
	}

	s.setRemote(1)
	if got := s.current(); got != 1 {
		t.Fatalf("cap = %d, want 1", got)
	}

	// Three are still held and nothing was cancelled; the next one waits.
	tight, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if s.acquire(tight) {
		t.Error("a fourth run started under a cap of one")
	}
}

// Raising it wakes whoever is waiting, or a run would sit behind a limit that no
// longer exists until some unrelated run happened to finish.
//
// The host allows four throughout; it is the control plane's ceiling that drops
// to one and is lifted again — a workspace changing plan. Starting from
// newSlots(1) would prove nothing, because a remote ceiling raised above what
// the host permits correctly changes nothing at all.
func TestRaisingTheCapWakesAWaitingRun(t *testing.T) {
	s := newSlots(4)
	s.setRemote(1)
	ctx := context.Background()
	if !s.acquire(ctx) {
		t.Fatal("the first run was refused")
	}

	done := make(chan bool, 1)
	go func() { done <- s.acquire(ctx) }()
	time.Sleep(50 * time.Millisecond)
	s.setRemote(4)

	select {
	case ok := <-done:
		if !ok {
			t.Error("the waiting run was refused after the cap was raised")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raising the cap did not wake the run waiting on it")
	}
}

// The poll cadence goes the other way, and the rule underneath is the same: the
// agent may only ever ask for *less*. Waiting less than the server asked for
// means more requests than it wanted.
func TestThePollWaitIsTheLongerOfTheTwo(t *testing.T) {
	cases := []struct {
		local, remote, want time.Duration
	}{
		{30 * time.Second, 60 * time.Second, 60 * time.Second},
		{60 * time.Second, 30 * time.Second, 60 * time.Second},
		{30 * time.Second, 0, 30 * time.Second},
	}
	for _, c := range cases {
		if got := pollWaitFor(c.local, c.remote); got != c.want {
			t.Errorf("pollWaitFor(%s, %s) = %s, want %s", c.local, c.remote, got, c.want)
		}
	}
}
