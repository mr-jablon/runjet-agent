package protocol

import "testing"

// The window is the whole reason this constant pair exists: the server serves
// MinAgentProtocolVersion through AgentProtocolVersion, and an agent outside it
// is refused. Getting the boundary wrong by one is an outage at every customer
// who has not upgraded, and the symptom is "nothing happened" — so the edges are
// worth pinning down rather than trusting to a comparison read once.
func TestSpeaksAgentProtocolAcceptsTheWholeWindowAndNothingElse(t *testing.T) {
	for v := MinAgentProtocolVersion; v <= AgentProtocolVersion; v++ {
		if !SpeaksAgentProtocol(v) {
			t.Errorf("SpeaksAgentProtocol(%d) = false, but %d is inside the window %d..%d",
				v, v, MinAgentProtocolVersion, AgentProtocolVersion)
		}
	}
	for _, v := range []int{
		MinAgentProtocolVersion - 1, // one below the floor: an agent too old to serve
		AgentProtocolVersion + 1,    // one above: an agent built from a newer tree
		0, -1,
	} {
		if SpeaksAgentProtocol(v) {
			t.Errorf("SpeaksAgentProtocol(%d) = true, but %d is outside the window %d..%d",
				v, v, MinAgentProtocolVersion, AgentProtocolVersion)
		}
	}
}

// The floor may only rise in a release whose notes say so, and the ceiling is
// what an agent from this tree announces. A change to either that arrives by
// accident — a refactor, a merge — is the kind that is noticed by customers
// rather than by us.
func TestTheWindowIsWhereTheReleaseNotesSayItIs(t *testing.T) {
	if MinAgentProtocolVersion != 1 {
		t.Errorf("MinAgentProtocolVersion = %d, want 1: raising the floor retires every agent "+
			"below it and belongs in a release whose notes say so", MinAgentProtocolVersion)
	}
	if AgentProtocolVersion != 2 {
		t.Errorf("AgentProtocolVersion = %d, want 2", AgentProtocolVersion)
	}
	if MinAgentProtocolVersion > AgentProtocolVersion {
		t.Fatal("the window is inverted: the floor sits above the ceiling, so nothing is served")
	}
}
