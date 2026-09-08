package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// main() is the contract the manual prints: `runjet-agent enroll …` on a host,
// and the service manager starting the binary with no arguments. Neither can be
// exercised in-process — main exits — so this builds the real thing and runs it,
// which is also the only test that would notice the enroll subcommand being
// routed away.

// agentBinary builds the agent once for this test file.
func agentBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "runjet-agent")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("building the agent: %v\n%s", err, out)
	}
	return bin
}

// A failed enrolment talks to a person: plain text on stderr and a non-zero
// exit, not the JSON the long-running agent emits.
func TestTheEnrollSubcommandReportsFailureToAPerson(t *testing.T) {
	cmd := exec.Command(agentBinary(t), "enroll")
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatal("`enroll` with no arguments succeeded")
	}
	var exit *exec.ExitError
	if !asExitError(err, &exit) || exit.ExitCode() != 1 {
		t.Errorf("exit status = %v, want 1 so an install script can tell", err)
	}
	if !strings.Contains(string(out), "-url and -key are both required") {
		t.Errorf("output does not say what is missing:\n%s", out)
	}
	if strings.Contains(string(out), `"level":`) {
		t.Errorf("enrolment emitted the agent's JSON logs at a person:\n%s", out)
	}
}

// -h prints the whole command the Register agent dialog produces, because this
// is run once by hand and the example matters more than the flag list.
func TestTheEnrollSubcommandPrintsAUsableExample(t *testing.T) {
	out, _ := exec.Command(agentBinary(t), "enroll", "-h").CombinedOutput()

	for _, want := range []string{"runjet-agent enroll", "-url", "-key", "-token", "runjet.dev"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("usage does not mention %q:\n%s", want, out)
		}
	}
}

// Started as a service with nothing configured, the agent must exit non-zero
// rather than sit there looking healthy, and must say so as JSON, which is what
// a log collector on the host will be reading.
func TestTheAgentExitsNonZeroWithoutConfiguration(t *testing.T) {
	cmd := exec.Command(agentBinary(t))
	cmd.Env = append(os.Environ(), "RUNJET_URL=", "RUNJET_PUBLIC_KEYS=", "ENROLLMENT_TOKEN=")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatal("the agent started with no scheduler configured")
	}
	var exit *exec.ExitError
	if !asExitError(err, &exit) || exit.ExitCode() != 1 {
		t.Errorf("exit status = %v, want 1 so the service manager restarts or reports it", err)
	}
	if !strings.Contains(string(out), "RUNJET_URL") {
		t.Errorf("output does not name the missing setting:\n%s", out)
	}
	if !strings.Contains(string(out), `"level":"ERROR"`) {
		t.Errorf("the failure was not logged as JSON, which is what a collector reads:\n%s", out)
	}
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}
