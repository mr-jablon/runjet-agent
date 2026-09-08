package main

import (
	"os/user"
	"strings"
	"testing"

	"github.com/mr-jablon/runjet-agent/runner"
)

// What the agent reports as its job account is the only way an operator learns,
// from the agent list, that a host is running jobs as the agent itself. The
// risky configuration must not be the one that says least — so the name is
// resolved rather than left blank, and isolated=false is what tells the two
// apart.

func TestJobAccountReportsTheJobUserWhenJobsAreIsolated(t *testing.T) {
	who := jobUser{Cred: &runner.User{UID: 10002, GID: 10002}, Name: "runjet-job"}

	name, isolated := jobAccount(who)
	if name != "runjet-job" {
		t.Errorf("name = %q, want the job account", name)
	}
	if !isolated {
		t.Error("isolated = false for an account separate from the agent's")
	}
}

// The case that matters. jobUser.Name is empty here, and reporting that empty
// string would make the host that deserves attention the one that shows
// nothing.
func TestJobAccountNamesTheAgentsOwnUserWhenJobsAreNotIsolated(t *testing.T) {
	name, isolated := jobAccount(jobUser{})

	if isolated {
		t.Error("isolated = true although jobs run as the agent itself")
	}
	if name == "" {
		t.Fatal("name is empty: the configuration an operator most needs to see would " +
			"be the one reporting nothing")
	}
	if want := currentAccount(); name != want {
		t.Errorf("name = %q, want this process's own account %q", name, want)
	}
}

// A container often has no passwd entry for the uid it runs as. A number is
// worse to read than a name and far better than nothing, so there must always
// be something.
func TestCurrentAccountAlwaysNamesSomething(t *testing.T) {
	got := currentAccount()
	if got == "" {
		t.Fatal("currentAccount() is empty")
	}

	u, err := user.Current()
	if err != nil {
		// No passwd entry: the fallbacks are all that is left, and either is fine.
		if !strings.HasPrefix(got, "uid ") && got != "unknown" {
			t.Errorf("currentAccount() = %q with no resolvable user, want a uid or \"unknown\"", got)
		}
		return
	}
	if u.Username != "" && got != u.Username {
		t.Errorf("currentAccount() = %q, want %q", got, u.Username)
	}
}
