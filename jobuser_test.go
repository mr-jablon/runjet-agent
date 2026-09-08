package main

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/runner"
)

// Resolution has to fail loudly. An agent that quietly falls back to running
// jobs as itself leaves an operator believing in isolation that is not there,
// which is the one outcome worse than a host that will not start.

func TestResolveJobUserEmptyRunsAsTheAgent(t *testing.T) {
	u, err := resolveJobUser("", "")
	if err != nil {
		t.Fatalf("resolveJobUser(\"\", \"\") = %v, want the explicit opt-out to be allowed", err)
	}
	if u.separate() {
		t.Error("an empty AGENT_JOB_USER produced a credential")
	}
}

func TestResolveJobUserRejectsAnUnknownAccount(t *testing.T) {
	_, err := resolveJobUser("no-such-account-here", "")
	if err == nil {
		t.Fatal("resolveJobUser accepted an account that does not exist")
	}
	// The agent is built without cgo, so this is the failure an operator on a
	// directory-backed host will hit. The message has to say so, and say what
	// to do instead, because nothing about "user: unknown user" suggests it.
	for _, want := range []string{"cgo", "AGENT_JOB_GROUP", "useradd"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q, so it does not lead anywhere:\n%s", want, err)
		}
	}
}

// A numeric id is the way through for accounts that only exist in a directory,
// and there is no passwd entry to take the group from.
func TestResolveJobUserNumericNeedsAGroup(t *testing.T) {
	if _, err := resolveJobUser("4294967000", ""); err == nil {
		t.Fatal("resolveJobUser accepted a numeric id with no AGENT_JOB_GROUP")
	}

	u, err := resolveJobUser("4294967000", "4294967001")
	if err != nil {
		t.Fatalf("resolveJobUser with both ids: %v", err)
	}
	if !u.separate() {
		t.Fatal("a numeric id produced no credential")
	}
	if u.Cred.UID != 4294967000 || u.Cred.GID != 4294967001 {
		t.Errorf("credential = %+v, want the ids given", u.Cred)
	}
}

func TestResolveJobUserRejectsANonNumericGroup(t *testing.T) {
	if _, err := resolveJobUser("4294967000", "not-a-number"); err == nil {
		t.Fatal("resolveJobUser accepted a non-numeric AGENT_JOB_GROUP")
	}
}

// Resolving by name is the normal path. The account running the tests is the
// one account guaranteed to exist wherever they run.
func TestResolveJobUserReadsThePasswdEntry(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}

	u, err := resolveJobUser(me.Username, "")
	if err != nil {
		t.Fatalf("resolveJobUser(%q): %v", me.Username, err)
	}
	if !u.separate() {
		t.Fatal("a named account produced no credential")
	}
	if want, _ := strconv.ParseUint(me.Uid, 10, 32); uint64(u.Cred.UID) != want {
		t.Errorf("uid = %d, want %d", u.Cred.UID, want)
	}
	if u.Home != me.HomeDir || u.Name != me.Username {
		t.Errorf("account = %+v, want home and name from passwd", u)
	}
	// Left unset, the child keeps the agent's supplementary groups and whatever
	// those grant comes straight back.
	if len(u.Cred.Groups) == 0 {
		t.Error("no supplementary groups resolved, so the agent's would be inherited")
	}
}

// HOME, USER and LOGNAME describe the account a command runs under. Inheriting
// the agent's would point every job at its state directory — the one place
// this whole exercise is keeping them out of.
func TestJobEnvDerivesTheAccountFromTheJobUser(t *testing.T) {
	t.Setenv("HOME", "/var/lib/runjet-agent")
	t.Setenv("USER", "runjet-agent")
	t.Setenv("LOGNAME", "runjet-agent")
	t.Setenv("SHELL", "/usr/bin/zsh")

	base := newJobEnv(jobUser{
		Cred: &runner.User{UID: 1001, GID: 1001},
		Name: "runjet-job",
		Home: "/home/runjet-job",
	}, nil).base

	want := map[string]string{
		"HOME":    "/home/runjet-job",
		"USER":    "runjet-job",
		"LOGNAME": "runjet-job",
		// The runner executes through `sh`, so this is what the command really
		// runs under — more accurate than the agent user's login shell.
		"SHELL": "/bin/sh",
	}
	for key, value := range want {
		if !contains(base, key+"="+value) {
			t.Errorf("base is missing %s=%s: %v", key, value, base)
		}
	}
	for _, absent := range []string{"HOME=/var/lib/runjet-agent", "USER=runjet-agent", "SHELL=/usr/bin/zsh"} {
		if contains(base, absent) {
			t.Errorf("%q was inherited from the agent: %v", absent, base)
		}
	}
}

// The promise this whole plane exists to make: a file the agent can read is one
// a job cannot. Everything else — the environment allowlist, the scrubbing, the
// masking — is layered on top of this one property, and it is the only part
// that cannot be checked without privilege.
//
// Skips on a laptop, runs where CI is root.
func TestAJobCannotReadTheAgentsFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not privileged: switching user needs root or CAP_SETUID")
	}
	other, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account to run jobs as: %v", err)
	}

	// A stand-in for identity.json: 0600 inside a 0700 directory, owned by the
	// account the agent runs as. The tree above it is deliberately traversable,
	// so what stops the job is the state directory rather than a temp directory
	// that happened to be private — which would pass this test for a reason
	// having nothing to do with the design.
	dir := filepath.Join(tempTree(t), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	key := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(key, []byte("private-key-material"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	u, err := resolveJobUser(other.Username, "")
	if err != nil {
		t.Fatalf("resolveJobUser(%q): %v", other.Username, err)
	}
	jobs := jobRuntime{user: u, env: newJobEnv(u, nil)}

	var out bytes.Buffer
	outcome := runner.Run(context.Background(), jobs.spec("cat "+key, 10*time.Second, nil), &out)

	if outcome.OK() {
		t.Fatalf("a job read the agent's private key: %q", out.String())
	}
	if strings.Contains(out.String(), "private-key-material") {
		t.Errorf("the key leaked into the job's output: %q", out.String())
	}

	// And the same file is readable by the agent itself, so the test is
	// measuring the boundary rather than a broken fixture.
	if _, err := os.ReadFile(key); err != nil {
		t.Errorf("the agent cannot read its own key either, so this proved nothing: %v", err)
	}
}

// A job needs somewhere it can write. Its own home is that place, and it works
// without the agent having any access to it: os/exec changes directory after
// applying the credential, so a 0700 home belonging to the job account is
// reachable even though the agent could not enter it.
func TestAJobRunsInItsOwnHomeAndCanWriteThere(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not privileged: switching user needs root or CAP_SETUID")
	}
	other, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no nobody account to run jobs as: %v", err)
	}
	uid, _ := strconv.Atoi(other.Uid)
	gid, _ := strconv.Atoi(other.Gid)

	home := filepath.Join(tempTree(t), "jobhome")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("create home: %v", err)
	}
	if err := os.Chown(home, uid, gid); err != nil {
		t.Fatalf("chown home: %v", err)
	}
	// Some filesystems ignore ownership, and there the directory would be
	// reachable for the wrong reason. Checking the chown took is the probe —
	// trying to write is not, since root may write anywhere regardless.
	info, err := os.Stat(home)
	if err != nil {
		t.Fatalf("stat home: %v", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(uid) {
		t.Skip("ownership did not take on this filesystem, so the test would prove nothing")
	}

	u, err := resolveJobUser(other.Username, "")
	if err != nil {
		t.Fatalf("resolveJobUser: %v", err)
	}
	u.Home, u.WorkDir = home, home
	jobs := jobRuntime{user: u, env: newJobEnv(u, nil)}

	var out bytes.Buffer
	outcome := runner.Run(context.Background(),
		jobs.spec("pwd && echo written > from-the-job", 10*time.Second, nil), &out)

	if !outcome.OK() {
		t.Fatalf("outcome = %+v, output %q", outcome, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != home {
		t.Errorf("the job ran in %q, want its own home %q", got, home)
	}
	if _, err := os.Stat(filepath.Join(home, "from-the-job")); err != nil {
		t.Errorf("the job could not write in its working directory: %v", err)
	}
}

// tempTree returns a directory every account can traverse into, so that a test
// measures the permissions it sets up rather than the 0700 the testing package
// gives its own temporary directories.
func tempTree(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "agent-test")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}
	return base
}

func contains(env []string, entry string) bool {
	for _, e := range env {
		if e == entry {
			return true
		}
	}
	return false
}
