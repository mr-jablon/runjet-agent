package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/mr-jablon/runjet-agent/runner"
)

// A file cannot be hidden from a process running under the same uid. That is a
// property of Unix rather than a gap in the code, so as long as job commands
// run as the agent, `cat $AGENT_STATE_DIR/identity.json` hands a job the key
// the agent signs with, and `cat $AGENT_SECRETS_FILE` hands it every secret on
// the host. Running them as somebody else is the only answer.

// defaultJobUser is the account the packaging creates. Jobs run as their own
// user unless an operator deliberately says otherwise.
const defaultJobUser = "runjet-job"

// jobUser is the account job commands run under.
type jobUser struct {
	// Cred is nil when commands run as the agent itself, which is what
	// AGENT_JOB_USER="" asks for.
	Cred *runner.User
	Name string
	Home string
	// WorkDir is where commands run, empty when there is nowhere suitable and
	// they should stay in the agent's directory. It is Home when that exists:
	// the account owns it, and os/exec changes directory *after* applying the
	// credential, so a 0700 home works without the agent needing any access to
	// it at all.
	WorkDir string
}

// separate reports whether jobs are actually isolated from the agent.
func (u jobUser) separate() bool { return u.Cred != nil }

// resolveJobUser turns AGENT_JOB_USER into an account to run commands as.
//
// A name that cannot be resolved stops the agent. Falling back to the agent's
// own user would leave an operator believing they had isolation they do not
// have, which is worse than a host that will not start and says why.
func resolveJobUser(name, group string) (jobUser, error) {
	if name == "" {
		return jobUser{}, nil
	}

	if u, err := lookup(name); err == nil {
		return fromPasswd(u)
	} else if _, isNumeric := parseID(name); !isNumeric {
		return jobUser{}, fmt.Errorf("AGENT_JOB_USER %q: %w\n"+
			"\tThis agent is built without cgo — a static binary is the point — so it reads\n"+
			"\t/etc/passwd directly and cannot see accounts that exist only through NSS\n"+
			"\t(LDAP, SSSD). For those, give a numeric id in AGENT_JOB_USER and set\n"+
			"\tAGENT_JOB_GROUP. Otherwise create the account: useradd --system "+
			"--no-create-home %s", name, err, name)
	}

	// A numeric id with no passwd entry behind it. Nothing can be derived, so
	// the group has to be given too.
	uid, _ := parseID(name)
	if group == "" {
		return jobUser{}, fmt.Errorf("AGENT_JOB_USER is the numeric id %s and no account has it, "+
			"so AGENT_JOB_GROUP must supply the group id: there is no passwd entry to read it from", name)
	}
	gid, ok := parseID(group)
	if !ok {
		return jobUser{}, fmt.Errorf("AGENT_JOB_GROUP %q is not a numeric group id", group)
	}
	return jobUser{
		Cred: &runner.User{UID: uid, GID: gid},
		Name: name,
		Home: "/",
	}, nil
}

// lookup accepts either a name or a numeric id, so AGENT_JOB_USER reads the
// same whichever the host uses.
func lookup(name string) (*user.User, error) {
	u, err := user.Lookup(name)
	if err == nil {
		return u, nil
	}
	if _, isNumeric := parseID(name); isNumeric {
		return user.LookupId(name)
	}
	return nil, err
}

func fromPasswd(u *user.User) (jobUser, error) {
	uid, ok := parseID(u.Uid)
	if !ok {
		return jobUser{}, fmt.Errorf("account %s has a non-numeric uid %q", u.Username, u.Uid)
	}
	gid, ok := parseID(u.Gid)
	if !ok {
		return jobUser{}, fmt.Errorf("account %s has a non-numeric gid %q", u.Username, u.Gid)
	}

	// Supplementary groups are set explicitly rather than left alone: unset,
	// the child keeps the agent's, and whatever those open comes straight back.
	ids, err := u.GroupIds()
	if err != nil {
		return jobUser{}, fmt.Errorf("groups for %s: %w", u.Username, err)
	}
	groups := make([]uint32, 0, len(ids))
	for _, raw := range ids {
		id, ok := parseID(raw)
		if !ok {
			return jobUser{}, fmt.Errorf("account %s is in a group with a non-numeric id %q", u.Username, raw)
		}
		groups = append(groups, id)
	}

	home := u.HomeDir
	if home == "" {
		home = "/"
	}
	return jobUser{
		Cred:    &runner.User{UID: uid, GID: gid, Groups: groups},
		Name:    u.Username,
		Home:    home,
		WorkDir: usableDir(home),
	}, nil
}

// usableDir returns dir when a command could plausibly run in it, and "" to
// leave the working directory alone otherwise.
//
// Only existence is checked. Whether the account can actually write there is
// its own business — a read-only working directory is a job's problem to
// notice, while a missing one fails the exec itself and would take down every
// run on the host.
func usableDir(dir string) string {
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir
	}
	return ""
}

// verify proves the agent can actually become this user before it takes any
// work.
//
// Without CAP_SETUID the first sign would otherwise be every job on the host
// failing at exec, which is a slow and confusing way to learn that a unit file
// is missing a line. One trivial command at startup turns that into a host that
// refuses to start and says what is wrong.
func (u jobUser) verify(ctx context.Context) error {
	if !u.separate() {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	outcome := runner.Run(probe, runner.Spec{Command: ":", User: u.Cred}, io.Discard)
	if outcome.OK() {
		return nil
	}
	return fmt.Errorf("cannot run commands as %s: %w\n"+
		"\tRunning jobs as another account needs CAP_SETUID and CAP_SETGID. Under systemd add\n"+
		"\tAmbientCapabilities=CAP_SETUID CAP_SETGID to the unit; in a container add\n"+
		"\t--cap-add=SETUID --cap-add=SETGID. Set AGENT_JOB_USER= (empty) to run jobs as this\n"+
		"\tagent instead, accepting that they can then read its key and its secrets file",
		u.Name, outcome.Err)
}

func parseID(raw string) (uint32, bool) {
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(id), true
}
