// Package runner executes a job's shell command.
//
// It is the only place in the tree that starts a process. Keeping it separate
// is what lets execution move off the control plane: the scheduler hands work
// out, agents run it, and both use this same hardened path.
package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// WaitDelay bounds the wait for a command's output pipe to close after its
// process group is gone, so a stray grandchild that inherited stdout cannot
// stall the caller forever.
const WaitDelay = 10 * time.Second

// Spec is a single command to execute.
type Spec struct {
	Command string
	Timeout time.Duration // wall-clock cap; 0 means no cap
	// Environ is the command's complete environment as KEY=value entries.
	// Nothing is inherited: an empty Environ means an empty environment, not
	// the caller's own.
	//
	// It used to extend the caller's environment instead, which is how an
	// agent's configuration — its scheduler key, its enrollment token, the
	// path to its secrets file — reached every command it ran. Whoever
	// assembles this decides what a command sees; the runner adds nothing.
	//
	// Secrets arrive here rather than interpolated into the command, which
	// keeps them out of the process's argv and out of anything that logs it.
	Environ []string
	// User is the account to run as. Nil runs as the caller's own user, which
	// on an agent means the command can read whatever the agent can — its
	// private key included, since a file cannot be hidden from a process
	// sharing its uid.
	User *User
	// Dir is the working directory. Empty inherits the caller's.
	//
	// The change of directory happens after the credential is applied, so this
	// only has to be reachable by User — a directory belonging to the job's own
	// account works even where the caller could not enter it.
	Dir string
}

// User is a resolved account to run a command as. Callers resolve it; the
// runner only applies it.
type User struct {
	UID, GID uint32
	// Groups replaces the caller's supplementary groups rather than extending
	// them. Left empty they are cleared, which is the safe reading: inheriting
	// the agent's would quietly hand back whatever those grant.
	Groups []uint32
}

// Reason classifies how a command ended.
//
// The runner deliberately does not phrase the outcome: "killed by scheduler
// shutdown" and "cancelled by the agent" are the same event seen from two
// sides, so the caller supplies the vocabulary and the runner supplies the
// fact.
type Reason string

const (
	ReasonOK        Reason = ""          // ran to completion, exit status 0
	ReasonExit      Reason = "exit"      // ran, but exited non-zero
	ReasonTimeout   Reason = "timeout"   // exceeded Spec.Timeout; process group killed
	ReasonCancelled Reason = "cancelled" // the caller's context was cancelled
	ReasonStalled   Reason = "stalled"   // exited, but a background process held the output pipe
)

// Outcome is the result of one execution.
type Outcome struct {
	Reason  Reason
	Err     error         // raw error from exec, for logs; nil when Reason is ReasonOK
	Timeout time.Duration // the cap that applied, for callers rendering a message
	// ExitCode is the status the command ended with, and nil when it did not
	// end with one at all.
	//
	// That distinction is the whole of this field. A process killed by a signal
	// — which is what the timeout and a cancelled context both do — has no exit
	// code to report, and Go says so by returning -1. Recording that as a number
	// would put "killed" and "exited 0" on one axis and invite arithmetic across
	// them. So the negative case becomes nil and the caller has to decide what
	// "no code" means, which is the honest question.
	ExitCode *int
}

// OK reports whether the command ran to a successful completion.
func (o Outcome) OK() bool { return o.Reason == ReasonOK }

// Run executes spec's command with `sh`, streaming combined output into out as
// it is produced.
//
// The script is fed to the shell on stdin rather than passed as an argument.
// With `sh -c <command>` the whole command line sits in the process's argv,
// where any local user on the machine can read it out of `ps` for as long as
// the run lasts — which stopped being acceptable once jobs began running on
// real servers instead of inside the backend's own container.
//
// The trade-off is that the command no longer has a stdin of its own: it now
// shares the shell's, which is the script itself. A job that reads from stdin
// (`read`, `cat` with no argument) would consume the rest of its own script
// instead of seeing the empty input it used to get. Jobs here are
// non-interactive, so this is a corner rather than a common case, but it is a
// real behaviour change. If one ever needs a clean stdin, the script can be
// passed on a spare descriptor (`sh /dev/fd/3` with ExtraFiles) instead.
//
// The command gets its own process group so a kill takes the whole tree (`sh`
// plus whatever it spawned) rather than just the direct child, and a bounded
// post-kill wait so a grandchild holding the output pipe cannot hang the
// caller. Cancelling ctx kills the group the same way a timeout does.
func Run(ctx context.Context, spec Spec, out io.Writer) Outcome {
	cmdCtx := ctx
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, "sh", "-s")
	cmd.Stdin = strings.NewReader(spec.Command)
	// os/exec reads a nil Env as "inherit the parent's", which is the leak
	// Environ exists to close — so an empty one becomes an empty slice.
	cmd.Env = spec.Environ
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	cmd.Dir = spec.Dir
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if spec.User != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid:    spec.User.UID,
			Gid:    spec.User.GID,
			Groups: spec.User.Groups,
		}
	}
	cmd.WaitDelay = WaitDelay
	cmd.Cancel = func() error {
		// Negative PID targets the process group. ESRCH just means the tree
		// already exited between the deadline firing and this call.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil &&
			!errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}

	err := cmd.Run()
	// Read from the process rather than from the error, and once for every
	// branch below. ProcessState is set whenever the child was reaped at all,
	// so a stalled command — which exited and then had its output pipe held
	// open by a grandchild — reports the status it really ended with, and a
	// killed one reports -1, which exitCode turns into nil.
	code := exitCode(cmd.ProcessState)
	if err == nil {
		return Outcome{Timeout: spec.Timeout, ExitCode: code}
	}
	switch {
	case errors.Is(cmdCtx.Err(), context.DeadlineExceeded):
		return Outcome{Reason: ReasonTimeout, Err: err, Timeout: spec.Timeout, ExitCode: code}
	case errors.Is(cmdCtx.Err(), context.Canceled):
		return Outcome{Reason: ReasonCancelled, Err: err, Timeout: spec.Timeout, ExitCode: code}
	case errors.Is(err, exec.ErrWaitDelay):
		return Outcome{Reason: ReasonStalled, Err: err, Timeout: spec.Timeout, ExitCode: code}
	default:
		return Outcome{Reason: ReasonExit, Err: err, Timeout: spec.Timeout, ExitCode: code}
	}
}

// exitCode reads a finished process's status, or nil when there is not one.
//
// A nil state means the command never started — nothing was executed, so there
// is nothing to report. A negative code means the process was terminated by a
// signal, which is how the timeout and a cancelled context end a run: also no
// exit code, and saying so beats recording -1 as though it were one.
func exitCode(st *os.ProcessState) *int {
	if st == nil {
		return nil
	}
	c := st.ExitCode()
	if c < 0 {
		return nil
	}
	return &c
}
