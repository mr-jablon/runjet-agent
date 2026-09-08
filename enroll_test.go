package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-jablon/runjet-agent/protocol"
	"github.com/mr-jablon/runjet-agent/signing"
)

// What this command exists to guarantee is a negative: the one-time token does
// not survive it. Everything below is some form of checking that.

func enrollRunjet(t *testing.T) (*testRunjet, string, *int) {
	t.Helper()
	ts := newTestRunjet(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		ts.record(r)
		writeSealed(t, w, ts.signer, enrollResponse{
			AgentID:   "agent-7",
			AgentName: "web-01",
			KeyID:     ts.signer.KeyID(),
			Protocol:  protocol.AgentProtocolVersion,
			PollWait:  "30s",
		})
	}))
	t.Cleanup(srv.Close)
	return ts, srv.URL, &calls
}

func keyFlag(ts *testRunjet) string {
	for id, pub := range ts.ring() {
		return id + ":" + signing.EncodeKey(pub)
	}
	return ""
}

func TestEnrollWritesTheIdentityAndSettingsWithoutTheToken(t *testing.T) {
	ts, url, _ := enrollRunjet(t)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	envFile := filepath.Join(dir, "etc", "agent.env")

	var out strings.Builder
	err := runEnroll([]string{
		"-url", url, "-key", keyFlag(ts), "-token", "ONE-TIME-SECRET",
		"-state-dir", stateDir, "-env-file", envFile,
	}, &out)
	if err != nil {
		t.Fatalf("runEnroll: %v\n%s", err, out.String())
	}

	identityRaw, err := os.ReadFile(filepath.Join(stateDir, "identity.json"))
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	var id identity
	if err := json.Unmarshal(identityRaw, &id); err != nil {
		t.Fatalf("identity is not JSON: %v", err)
	}
	if id.AgentID != "agent-7" || id.AgentName != "web-01" {
		t.Errorf("identity = %+v, want what the scheduler returned", id)
	}
	if _, err := signing.ParsePrivateKey(id.PrivateKey); err != nil {
		t.Errorf("the stored key is unusable: %v", err)
	}

	envRaw, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	for _, want := range []string{"RUNJET_URL=" + url, "AGENT_NAME=web-01", "RUNJET_PUBLIC_KEYS="} {
		if !strings.Contains(string(envRaw), want) {
			t.Errorf("env file is missing %q:\n%s", want, envRaw)
		}
	}

	// The point of the whole command. Nothing written down carries the token,
	// so there is nothing for an operator to remember to delete afterwards.
	for name, content := range map[string]string{
		"identity file": string(identityRaw),
		"env file":      string(envRaw),
		"its output":    out.String(),
	} {
		if strings.Contains(content, "ONE-TIME-SECRET") {
			t.Errorf("the enrollment token reached %s:\n%s", name, content)
		}
	}
}

// Both hold a secret, and the directory holds the secrets file beside them.
func TestEnrollWritesFilesThatAreNotWorldReadable(t *testing.T) {
	ts, url, _ := enrollRunjet(t)
	dir := t.TempDir()
	envFile := filepath.Join(dir, "etc", "agent.env")

	var out strings.Builder
	if err := runEnroll([]string{
		"-url", url, "-key", keyFlag(ts), "-token", "t",
		"-state-dir", filepath.Join(dir, "state"), "-env-file", envFile,
	}, &out); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	for path, want := range map[string]os.FileMode{
		filepath.Join(dir, "state", "identity.json"): 0o600,
		filepath.Join(dir, "state"):                  0o700,
		envFile:                                      0o600,
		filepath.Join(dir, "etc"):                    0o700,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %04o, want %04o", path, got, want)
		}
	}
}

// Overwriting could drop AGENT_PASS_ENV or AGENT_JOB_USER that somebody set on
// purpose, and nothing here can tell a stale file from a deliberate one.
func TestEnrollLeavesAnExistingSettingsFileAlone(t *testing.T) {
	ts, url, _ := enrollRunjet(t)
	dir := t.TempDir()
	envFile := filepath.Join(dir, "agent.env")
	const existing = "AGENT_PASS_ENV=JAVA_HOME\n"
	if err := os.WriteFile(envFile, []byte(existing), 0o600); err != nil {
		t.Fatalf("seed env file: %v", err)
	}

	var out strings.Builder
	if err := runEnroll([]string{
		"-url", url, "-key", keyFlag(ts), "-token", "t",
		"-state-dir", filepath.Join(dir, "state"), "-env-file", envFile,
	}, &out); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if string(got) != existing {
		t.Errorf("the existing file was rewritten:\n%s", got)
	}
	// Enrollment still happened, so the operator has to be told what the file
	// now needs rather than left with a half-finished install.
	if !strings.Contains(out.String(), "RUNJET_URL="+url) {
		t.Errorf("output does not say what the file needs:\n%s", out.String())
	}
}

// Re-enrolling would abandon a registration the scheduler still knows about,
// and burn a token to do it.
func TestEnrollRefusesAHostThatIsAlreadyEnrolled(t *testing.T) {
	ts, url, calls := enrollRunjet(t)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := (config{StateDir: stateDir}).saveIdentity(identity{
		AgentID: "agent-1", AgentName: "web-01", PrivateKey: encodePrivateKey(mustPrivateKey(t)),
	}); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	var out strings.Builder
	err := runEnroll([]string{
		"-url", url, "-key", keyFlag(ts), "-token", "t",
		"-state-dir", stateDir, "-env-file", filepath.Join(dir, "agent.env"),
	}, &out)

	if err == nil {
		t.Fatal("runEnroll re-enrolled a host that already had an identity")
	}
	if !strings.Contains(err.Error(), "Reset enrollment") {
		t.Errorf("error does not say how to start over:\n%v", err)
	}
	if *calls != 0 {
		t.Errorf("the scheduler was called %d times, so the token was spent anyway", *calls)
	}
}

// A mistyped key would otherwise burn the token and leave the agent unable to
// believe the answer it had just been given.
func TestEnrollRejectsAnUnusableKeyBeforeSpendingTheToken(t *testing.T) {
	_, url, calls := enrollRunjet(t)
	dir := t.TempDir()

	var out strings.Builder
	err := runEnroll([]string{
		"-url", url, "-key", "sched-1:!!!not-base64!!!", "-token", "t",
		"-state-dir", filepath.Join(dir, "state"), "-env-file", filepath.Join(dir, "agent.env"),
	}, &out)

	if err == nil {
		t.Fatal("runEnroll accepted an unusable key ring")
	}
	if *calls != 0 {
		t.Errorf("the scheduler was called %d times despite the key being unusable", *calls)
	}
}

func TestEnrollRequiresAURLAndAKey(t *testing.T) {
	for name, args := range map[string][]string{
		"no url": {"-key", "sched-1:x", "-token", "t"},
		"no key": {"-url", "https://scheduler.example", "-token", "t"},
	} {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			if err := runEnroll(args, &out); err == nil {
				t.Fatal("runEnroll accepted an incomplete invocation")
			}
		})
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	// Trailing newline is what a heredoc or an editor leaves behind, and a
	// token with one would simply be rejected by the scheduler.
	if err := os.WriteFile(file, []byte("  from-a-file\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	if got, err := readToken("inline", ""); err != nil || got != "inline" {
		t.Errorf("readToken(inline) = %q, %v", got, err)
	}
	if got, err := readToken("", file); err != nil || got != "from-a-file" {
		t.Errorf("readToken(file) = %q, %v, want it trimmed", got, err)
	}
	if _, err := readToken("inline", file); err == nil {
		t.Error("readToken accepted both -token and -token-file")
	}
	if _, err := readToken("", filepath.Join(dir, "absent")); err == nil {
		t.Error("readToken accepted a token file that does not exist")
	}
	if _, err := trimmedToken("   \n"); err == nil {
		t.Error("readToken accepted an empty token")
	}
}

func mustPrivateKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

// enroll is run once, by hand, by somebody standing at a terminal. Every way it
// can go wrong has to end in a sentence they can act on rather than a stack
// trace or, worse, a half-enrolled host.

func TestEnrollRejectsFlagsItDoesNotKnow(t *testing.T) {
	var out bytes.Buffer
	if err := runEnroll([]string{"-nonsense"}, &out); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
}

func TestEnrollRefusesTwoWaysToGiveTheToken(t *testing.T) {
	var out bytes.Buffer
	err := runEnroll([]string{
		"-url", "https://runjet.dev", "-key", testKeyRing(t),
		"-token", "inline", "-token-file", "/tmp/whatever",
	}, &out)
	if err == nil {
		t.Fatal("both -token and -token-file were accepted, so which one was spent is anybody's guess")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("error = %v, want it to say only one may be given", err)
	}
}

func TestEnrollReadsTheTokenFromAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  one-time-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readToken("", path)
	if err != nil {
		t.Fatalf("readToken: %v", err)
	}
	if got != "one-time-token" {
		t.Errorf("token = %q, want it trimmed", got)
	}

	if _, err := readToken("", filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a token file that is not there was accepted")
	} else if !strings.Contains(err.Error(), "read token file") {
		t.Errorf("error = %v, want it to name the file", err)
	}
}

// Stdin is the default so a token need never appear in the process list or in
// shell history.
func TestEnrollReadsTheTokenFromStdin(t *testing.T) {
	withStdin(t, "  fed-on-stdin\n")
	got, err := readToken("", "")
	if err != nil {
		t.Fatalf("readToken: %v", err)
	}
	if got != "fed-on-stdin" {
		t.Errorf("token = %q, want it read from stdin and trimmed", got)
	}

	withStdin(t, "   \n")
	if _, err := readToken("", ""); err == nil {
		t.Error("empty stdin was accepted as a token")
	} else if !strings.Contains(err.Error(), "no enrollment token") {
		t.Errorf("error = %v, want it to say how to supply one", err)
	}
}

// withStdin replaces os.Stdin for the length of one test.
func withStdin(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old; _ = f.Close() })
}

// The token is spent before the key is written. If writing fails, the operator
// has to hear about it — the token is burned either way, and a silent failure
// would leave them restarting an agent that can never authenticate.
func TestEnrollSurfacesAnIdentityItCouldNotWrite(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(blocked, []byte("a file, not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runEnroll([]string{
		"-url", "http://127.0.0.1:1", "-key", testKeyRing(t),
		"-token", "one-time", "-state-dir", blocked,
	}, &out)
	if err == nil {
		t.Fatal("enrolling into an unusable state directory reported success")
	}
}

func TestEnrollSurfacesAnUnreachableScheduler(t *testing.T) {
	var out bytes.Buffer
	err := runEnroll([]string{
		"-url", "http://127.0.0.1:1", "-key", testKeyRing(t),
		"-token", "one-time", "-state-dir", t.TempDir(),
		"-env-file", filepath.Join(t.TempDir(), "agent.env"),
	}, &out)
	if err == nil {
		t.Fatal("enrolling against a closed port reported success")
	}
}

// writeEnvFile decides whether a host's settings are safe to write. Both ways
// it can fail leave the operator with an enrolled agent and no configuration,
// so both have to say which path was the problem.
func TestWriteEnvFileReportsWhereItCouldNotWrite(t *testing.T) {
	t.Run("a path that cannot be examined", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "afile")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := writeEnvFile(filepath.Join(file, "agent.env"), "u", "k", "n"); err == nil {
			t.Fatal("a path through a regular file was accepted")
		}
	})

	t.Run("a directory that cannot be created", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root creates directories anywhere, so the failure cannot be staged")
		}
		dir := filepath.Join(t.TempDir(), "etc")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		if _, err := writeEnvFile(filepath.Join(dir, "sub", "agent.env"), "u", "k", "n"); err == nil {
			t.Fatal("writing into a directory that cannot be created reported success")
		}
	})

	t.Run("a file that cannot be written", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes into a read-only directory, so the failure cannot be staged")
		}
		dir := filepath.Join(t.TempDir(), "etc")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		if _, err := writeEnvFile(filepath.Join(dir, "agent.env"), "u", "k", "n"); err == nil {
			t.Fatal("writing into a read-only directory reported success")
		}
	})
}
