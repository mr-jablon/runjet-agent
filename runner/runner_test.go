package runner

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The runner is the only place in the tree that starts a process, and most of
// what it promises is about how a process *ends* — killed as a group, bounded by
// a deadline, classified afterwards. None of that shows up on the happy path, so
// the tests below spend their time on commands that misbehave.

func run(t *testing.T, ctx context.Context, spec Spec) (Outcome, string) {
	t.Helper()
	var out bytes.Buffer
	o := Run(ctx, spec, &out)
	return o, out.String()
}

func TestRunCapturesStdoutAndStderr(t *testing.T) {
	// Both streams land in the same writer, in order: a run record shows the
	// command's log the way a terminal would, not stdout with the errors missing.
	o, out := run(t, context.Background(), Spec{Command: "echo first; echo second 1>&2"})

	if !o.OK() {
		t.Fatalf("outcome = %+v, want OK", o)
	}
	if got := strings.Fields(out); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("output = %q, want both streams", out)
	}
}

func TestRunReportsNonZeroExit(t *testing.T) {
	o, _ := run(t, context.Background(), Spec{Command: "exit 3"})

	if o.OK() {
		t.Fatal("a command that exited 3 was reported as successful")
	}
	if o.Reason != ReasonExit {
		t.Errorf("reason = %q, want %q", o.Reason, ReasonExit)
	}
	if o.Err == nil {
		t.Error("Err is nil, so the caller has nothing to record")
	}
}

// A command that ignores its deadline must still be stopped, and stopped
// quickly: the caller's own shutdown budget depends on it.
func TestRunKillsOnTimeout(t *testing.T) {
	start := time.Now()
	o, _ := run(t, context.Background(), Spec{Command: "sleep 30", Timeout: 200 * time.Millisecond})

	if o.Reason != ReasonTimeout {
		t.Fatalf("reason = %q, want %q", o.Reason, ReasonTimeout)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Run took %s, so the process was not killed at the deadline", elapsed)
	}
	if o.Timeout != 200*time.Millisecond {
		t.Errorf("Timeout = %s, want the cap that applied", o.Timeout)
	}
}

// The whole point of the process group is the grandchild: a backgrounded process
// inherits the output pipe, so killing only `sh` would leave the pipe open and
// the caller blocked until WaitDelay expires. Finishing well inside WaitDelay is
// what proves the group — not just the direct child — was killed.
func TestRunTimeoutKillsBackgroundedGrandchildren(t *testing.T) {
	start := time.Now()
	o, _ := run(t, context.Background(), Spec{
		Command: "sleep 30 & echo started; wait",
		Timeout: 300 * time.Millisecond,
	})

	if o.Reason != ReasonTimeout {
		t.Fatalf("reason = %q, want %q", o.Reason, ReasonTimeout)
	}
	if elapsed := time.Since(start); elapsed >= WaitDelay {
		t.Errorf("Run took %s (>= WaitDelay %s): the backgrounded child survived the kill "+
			"and only the pipe timeout ended the wait", elapsed, WaitDelay)
	}
}

func TestRunReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	o, _ := run(t, ctx, Spec{Command: "sleep 30"})

	// Cancelled and timed out are different events for the caller: one is our
	// shutdown, the other is the job's own fault, and they get different words.
	if o.Reason != ReasonCancelled {
		t.Fatalf("reason = %q, want %q", o.Reason, ReasonCancelled)
	}
}

func TestRunWithoutTimeoutRunsToCompletion(t *testing.T) {
	// Timeout 0 means "no cap", not "expire immediately".
	o, out := run(t, context.Background(), Spec{Command: "echo done"})

	if !o.OK() {
		t.Fatalf("outcome = %+v, want OK", o)
	}
	if strings.TrimSpace(out) != "done" {
		t.Errorf("output = %q, want %q", out, "done")
	}
}

// Environ is absolute, and that is the whole of it: a command receives what the
// caller assembled and nothing the caller happens to be holding. Inheriting was
// how an agent's own configuration reached every job it ran.
func TestRunGivesTheCommandExactlyTheEnvironmentItWasGiven(t *testing.T) {
	t.Setenv("RUNNER_CALLER_ONLY", "must-not-appear")

	o, out := run(t, context.Background(), Spec{
		Command: "env",
		Environ: []string{"PATH=/usr/bin:/bin", "JOB_SECRET=s3cr3t"},
	})

	if !o.OK() {
		t.Fatalf("outcome = %+v, want OK", o)
	}
	if !strings.Contains(out, "JOB_SECRET=s3cr3t") {
		t.Errorf("the entry the caller supplied is missing from:\n%s", out)
	}
	if strings.Contains(out, "RUNNER_CALLER_ONLY") {
		t.Errorf("a variable from the caller's own environment reached the command:\n%s", out)
	}
}

// A nil Environ has to mean an empty environment. os/exec reads nil as
// "inherit", so leaving it unset would quietly restore the behaviour above for
// every command that happens to need no entries of its own.
//
// The probe is a shell builtin because with no environment there is no PATH,
// and an external binary would fail for the wrong reason.
func TestRunWithoutEnvironInheritsNothing(t *testing.T) {
	t.Setenv("RUNNER_CALLER_ONLY", "must-not-appear")

	o, out := run(t, context.Background(), Spec{Command: `echo "[$RUNNER_CALLER_ONLY]"`})

	if !o.OK() {
		t.Fatalf("outcome = %+v, want OK", o)
	}
	if strings.TrimSpace(out) != "[]" {
		t.Errorf("output = %q, want an empty expansion: the caller's environment was inherited", out)
	}
}

// The script goes to the shell on stdin precisely so it stays out of argv, where
// any local user could read it — and a command line often carries the very
// values a job was given secrets to avoid exposing.
func TestRunKeepsTheCommandOutOfArgv(t *testing.T) {
	const marker = "supersecretmarker"

	o, out := run(t, context.Background(), Spec{Command: "ps -o args= -p $$ # " + marker})
	if !o.OK() {
		t.Skipf("ps is unusable here (%v), cannot inspect argv", o.Err)
	}
	if strings.Contains(out, marker) {
		t.Errorf("the command text appears in the process's argv: %q", out)
	}
	if !strings.Contains(out, "sh") {
		t.Errorf("ps reported %q, which does not look like the shell we started", out)
	}
}

// The assertion the whole job-user design rests on: a command really does end
// up under another account, so a file the caller can read is one the command
// cannot.
//
// Switching user needs privilege, so this runs where there is some — as root on
// a Linux host — and skips on a developer's laptop. Skipping is why CI runs the
// suite a second time under sudo.
func TestRunAsAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not privileged: switching user needs root or CAP_SETUID")
	}
	other, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account to switch to: %v", err)
	}
	uid, _ := strconv.ParseUint(other.Uid, 10, 32)
	gid, _ := strconv.ParseUint(other.Gid, 10, 32)

	o, out := run(t, context.Background(), Spec{
		Command: "id -u",
		Environ: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		User:    &User{UID: uint32(uid), GID: uint32(gid)},
	})

	if !o.OK() {
		t.Fatalf("outcome = %+v, want OK", o)
	}
	if got := strings.TrimSpace(out); got != other.Uid {
		t.Errorf("command ran as uid %s, want %s (%s)", got, other.Uid, other.Username)
	}
}

// Supplementary groups are replaced, not extended. Unset, the child keeps the
// caller's, and on an agent that hands a job back whatever those grant.
func TestRunReplacesSupplementaryGroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not privileged: switching user needs root or CAP_SETUID")
	}
	other, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account to switch to: %v", err)
	}
	uid, _ := strconv.ParseUint(other.Uid, 10, 32)
	gid, _ := strconv.ParseUint(other.Gid, 10, 32)

	o, out := run(t, context.Background(), Spec{
		Command: "id -G",
		Environ: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		User:    &User{UID: uint32(uid), GID: uint32(gid), Groups: []uint32{uint32(gid)}},
	})

	if !o.OK() {
		t.Fatalf("outcome = %+v, want OK", o)
	}
	for _, got := range strings.Fields(out) {
		if got != other.Gid {
			t.Errorf("command is in group %s, want only %s: root's groups were inherited (%q)",
				got, other.Gid, strings.TrimSpace(out))
		}
	}
}

func TestOutcomeOK(t *testing.T) {
	// OK() is what decides success/failure on every run record, so pin it to the
	// reason rather than to the presence of an error.
	cases := map[Reason]bool{
		ReasonOK:        true,
		ReasonExit:      false,
		ReasonTimeout:   false,
		ReasonCancelled: false,
		ReasonStalled:   false,
	}
	for reason, want := range cases {
		if got := (Outcome{Reason: reason}).OK(); got != want {
			t.Errorf("Outcome{%q}.OK() = %v, want %v", reason, got, want)
		}
	}
}

// The exit code is the one fact about a run that cannot be recovered later, so
// these tests are about the boundary rather than the happy path: which endings
// have a code at all, and which only look as though they do.

func TestExitCodeIsTheStatusTheCommandEndedWith(t *testing.T) {
	o, _ := run(t, context.Background(), Spec{Command: "exit 3"})

	if o.ExitCode == nil {
		t.Fatal("a command that exited 3 reported no exit code")
	}
	if *o.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", *o.ExitCode)
	}
}

// Zero is recorded rather than left nil. It is a real exit code and the
// commonest one, and a success indistinguishable from a killed run would defeat
// the whole point of the field.
func TestExitCodeIsZeroOnSuccess(t *testing.T) {
	o, _ := run(t, context.Background(), Spec{Command: "true"})

	if o.ExitCode == nil {
		t.Fatal("a successful command reported no exit code")
	}
	if *o.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", *o.ExitCode)
	}
}

// A timeout kills the process group, so nothing ever exited and there is no
// code. Go reports -1 for a signalled process; recording that would put
// "killed" and "exited 0" on one axis and invite arithmetic across them.
func TestTimeoutHasNoExitCode(t *testing.T) {
	o, _ := run(t, context.Background(), Spec{Command: "sleep 5", Timeout: 100 * time.Millisecond})

	if o.Reason != ReasonTimeout {
		t.Fatalf("Reason = %q, want %q", o.Reason, ReasonTimeout)
	}
	if o.ExitCode != nil {
		t.Errorf("ExitCode = %d, want none for a killed process", *o.ExitCode)
	}
}

func TestCancellationHasNoExitCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	o, _ := run(t, ctx, Spec{Command: "sleep 5"})

	if o.Reason != ReasonCancelled {
		t.Fatalf("Reason = %q, want %q", o.Reason, ReasonCancelled)
	}
	if o.ExitCode != nil {
		t.Errorf("ExitCode = %d, want none for a cancelled run", *o.ExitCode)
	}
}

// A command that never starts has no exit status, and recording one would put
// "never ran" on the same axis as "ran and succeeded". The caller has to be able
// to tell them apart.
func TestACommandThatNeverStartsHasNoExitCode(t *testing.T) {
	// A working directory that is not there fails the exec itself, so no process
	// is ever created.
	o := Run(context.Background(), Spec{
		Command: "echo hello",
		Dir:     filepath.Join(t.TempDir(), "not-created"),
	}, io.Discard)

	if o.OK() {
		t.Fatal("a command that could not start was reported as a success")
	}
	if o.ExitCode != nil {
		t.Errorf("ExitCode = %d for a command that never ran, want nil", *o.ExitCode)
	}
	if o.Err == nil {
		t.Error("Err is nil, so the log says nothing about why nothing ran")
	}
	if o.Reason != ReasonExit {
		t.Errorf("Reason = %q, want %q", o.Reason, ReasonExit)
	}
}
