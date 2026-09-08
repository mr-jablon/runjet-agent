// Package protocol is the contract between an agent and Runjet.
//
// It lives in the agent's module and not in the control plane's, and the
// direction of that dependency is the whole point: an agent has to build from a
// tree the control plane is not in, so the contract cannot sit behind
// backend/internal. The server importing this reads as "the server speaks the
// agent protocol", which is what it does.
//
// Nothing here may grow a dependency on the rest of Runjet. A type in this
// package is one both halves compile, and one of those halves ships to machines
// nobody at Runjet can reach.
package protocol

import "time"

// The agent wire protocol is a window, not a number.
//
// Exact equality is correct for one installation whose operator upgrades the
// backend and its agents together. It is a loaded gun in a hosted product: the
// backend deploys for everybody at once, agents live on machines nobody here
// can reach, and raising the version would stop every job at every customer
// until each of them acted. For a product whose whole promise is that things
// run on a schedule, the symptom is "nothing happened" — the worst kind of
// outage to notice.
//
// So the server serves MinAgentProtocolVersion through AgentProtocolVersion,
// and an agent below the floor is refused only after having been reported as
// outdated in the UI for at least the two releases the window is wide.
//
// The cost is a constraint on every change to this protocol, and it is the real
// price of the window rather than a detail: whatever changes between versions
// has to be additive, or the response has to be built for the version that
// asked. Accepting an old agent's request and then handing it a new shape is
// the same outage with extra steps.
const (
	// AgentProtocolVersion is what this build speaks, and what an agent is told
	// to expect. It is also what an agent binary from this tree announces.
	//
	// 2 added Cancel: the control plane can ask an agent to stop a run. An agent
	// at 1 never receives the field — Go's decoder ignores what it has not heard
	// of — so it goes on working and its overdue runs are closed out by their
	// lease expiring instead. That is the window doing its job rather than a gap
	// in it, and it is why this could be a bump rather than a floor.
	AgentProtocolVersion = 2

	// MinAgentProtocolVersion is the oldest this build still serves. A version
	// leaves the window only in a release whose notes say so.
	//
	// Still 1: an agent that cannot be asked to stop a run is worse off than one
	// that can, but it is not broken, and refusing it would stop every job on
	// every host that has not been upgraded — for a capability the lease sweep
	// already covers more slowly.
	MinAgentProtocolVersion = 1
)

// SpeaksAgentProtocol reports whether this build serves the version an agent
// announced.
func SpeaksAgentProtocol(v int) bool {
	return v >= MinAgentProtocolVersion && v <= AgentProtocolVersion
}

// Dispatch is one unit of work handed to an agent. It is the payload sealed
// inside the envelope an agent verifies before executing anything, so every
// field here is covered by the scheduler's signature.
//
// Timeout travels with the work on purpose: the policy belongs to the control
// plane, and an agent must not be able to grant itself a longer runtime.
type Dispatch struct {
	RunID   string `json:"runId"`
	JobID   string `json:"jobId"`
	JobName string `json:"jobName"`
	Command string `json:"command"`
	// Secrets names the values the command needs. Only the names travel: the
	// agent resolves them from its own configuration, so the control plane
	// never holds a secret in its database, on the wire, or in a log.
	Secrets   []string  `json:"secrets"`
	Timeout   string    `json:"timeout"` // Go duration; "0" means no cap
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Protocol  int       `json:"protocol"`
}

// Cancel is the control plane asking an agent to stop a run it started.
//
// Sealed like a Dispatch and for the same reason. Confidentiality is not the
// point — the transport is TLS — but authenticity is: somebody who terminates
// that TLS must not be able to stop another customer's jobs, which is exactly
// as damaging as starting one and far easier to overlook.
//
// The agent kills the process group and reports the run as it would any other
// failure. It does not stop polling, and it does not exit: this ends one run,
// not the daemon.
type Cancel struct {
	RunID string `json:"runId"`
	// Reason is rendered into the run record, so it is written for whoever
	// opens that run rather than as a code for us. There is one today — the
	// plan's timeout — and the field exists anyway, because adding it later
	// would be a protocol change reaching machines nobody here can restart.
	Reason    string    `json:"reason"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Protocol  int       `json:"protocol"`
}

// Limits is what the control plane allows this agent, sent on every poll.
//
// **They are ceilings, not orders.** The agent may take less of each and never
// more, which is what keeps two things true at once: a plan limit cannot be
// raised by editing the agent's environment, and a host cannot be forced to run
// more work than its operator is willing to give it. The second matters — an
// agent that could be told to fork two hundred processes on somebody's
// production box is the loss of control people are right to fear from installing
// an agent at all.
//
// Sealed like a Dispatch. Raising MaxParallel is the interesting attack rather
// than lowering it: somebody who terminates the TLS could otherwise use a
// customer's own agent to exhaust their own machine.
//
// Sent on every poll rather than at enrolment, because an agent enrols once and
// a plan changes many times. An agent that has never heard of the field keeps
// whatever its environment says, which is exactly what it did before.
type Limits struct {
	// MaxParallel is the most runs this agent may execute at once. Zero means
	// the control plane is not expressing one, and the agent's own setting
	// stands alone.
	MaxParallel int `json:"maxParallel"`
	// PollWait is how long a poll should wait for work, as a Go duration.
	//
	// The agent may wait *longer* — the direction that asks less of both sides.
	// Waiting less would mean more requests than the server asked for, which is
	// the same shape of overreach as running more jobs than it allowed.
	PollWait  string    `json:"pollWait"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Protocol  int       `json:"protocol"`
}
