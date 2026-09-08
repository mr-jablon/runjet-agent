package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/signing"
)

// The agent's configuration decides two things that cannot be recovered from
// later: which scheduler it will believe, and where its private key lives. Both
// are covered here, along with the defaults an unconfigured agent falls back to.

func setAgentEnv(t *testing.T, values map[string]string) {
	t.Helper()
	for _, key := range reservedEnv {
		t.Setenv(key, "")
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

func testKeyRing(t *testing.T) string {
	t.Helper()
	pub, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return "sched-1:" + signing.EncodeKey(pub)
}

func TestLoadConfigRequiresARunjetURL(t *testing.T) {
	setAgentEnv(t, map[string]string{"RUNJET_PUBLIC_KEYS": testKeyRing(t)})

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig succeeded without RUNJET_URL")
	}
}

// Without a key to verify against, the agent would execute whatever any host
// that can reach it hands over. There is no safe default for this, so the
// absence has to stop startup and say why.
func TestLoadConfigRequiresRunjetPublicKeys(t *testing.T) {
	setAgentEnv(t, map[string]string{"RUNJET_URL": "https://scheduler.example"})

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig succeeded without RUNJET_PUBLIC_KEYS")
	}
	if !strings.Contains(err.Error(), "RUNJET_PUBLIC_KEYS") {
		t.Errorf("error %q does not name the missing setting", err)
	}
}

func TestLoadConfigRejectsAnUnusableKeyRing(t *testing.T) {
	for name, raw := range map[string]string{
		"not base64":  "sched-1:!!!",
		"no key id":   signing.EncodeKey(mustPublicKey(t)),
		"empty entry": ",",
	} {
		t.Run(name, func(t *testing.T) {
			setAgentEnv(t, map[string]string{
				"RUNJET_URL":         "https://scheduler.example",
				"RUNJET_PUBLIC_KEYS": raw,
			})

			if _, err := loadConfig(); err == nil {
				t.Fatalf("loadConfig accepted %q as a key ring", raw)
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	ring := testKeyRing(t)
	setAgentEnv(t, map[string]string{
		"RUNJET_URL":         "https://scheduler.example",
		"RUNJET_PUBLIC_KEYS": ring,
	})

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.StateDir != "/var/lib/runjet-agent" {
		t.Errorf("StateDir = %q, want the packaged default", cfg.StateDir)
	}
	if cfg.MaxParallel != 4 {
		t.Errorf("MaxParallel = %d, want 4", cfg.MaxParallel)
	}
	if cfg.PollWait != 30*time.Second {
		t.Errorf("PollWait = %s, want 30s", cfg.PollWait)
	}
	if len(cfg.RunjetKeys) != 1 {
		t.Errorf("RunjetKeys holds %d keys, want 1", len(cfg.RunjetKeys))
	}
}

// Several keys is how rotation works: the agent keeps trusting the old one until
// every dispatch is signed with the new.
func TestLoadConfigAcceptsSeveralRunjetKeys(t *testing.T) {
	setAgentEnv(t, map[string]string{
		"RUNJET_URL":         "https://scheduler.example",
		"RUNJET_PUBLIC_KEYS": testKeyRing(t) + ",sched-2:" + signing.EncodeKey(mustPublicKey(t)),
	})

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.RunjetKeys) != 2 {
		t.Fatalf("RunjetKeys holds %d keys, want 2", len(cfg.RunjetKeys))
	}
}

func TestLoadConfigReadsOverrides(t *testing.T) {
	setAgentEnv(t, map[string]string{
		"RUNJET_URL":         "https://scheduler.example",
		"RUNJET_PUBLIC_KEYS": testKeyRing(t),
		"ENROLLMENT_TOKEN":   "one-time-token",
		"AGENT_NAME":         "worker-01",
		"AGENT_STATE_DIR":    "/srv/agent",
		"AGENT_SECRETS_FILE": "/srv/agent/secrets.env",
		"AGENT_MAX_PARALLEL": "8",
		"AGENT_POLL_WAIT":    "45s",
	})

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.EnrollmentToken != "one-time-token" || cfg.Name != "worker-01" {
		t.Errorf("identity settings not applied: %+v", cfg)
	}
	if cfg.StateDir != "/srv/agent" || cfg.SecretsFile != "/srv/agent/secrets.env" {
		t.Errorf("path settings not applied: %+v", cfg)
	}
	if cfg.MaxParallel != 8 {
		t.Errorf("MaxParallel = %d, want 8", cfg.MaxParallel)
	}
	if cfg.PollWait != 45*time.Second {
		t.Errorf("PollWait = %s, want 45s", cfg.PollWait)
	}
}

func TestLoadConfigReadsPassEnv(t *testing.T) {
	setAgentEnv(t, map[string]string{
		"RUNJET_URL":         "https://scheduler.example",
		"RUNJET_PUBLIC_KEYS": testKeyRing(t),
		"AGENT_PASS_ENV":     "JAVA_HOME,HTTPS_PROXY",
	})

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.PassEnv) != 2 {
		t.Errorf("PassEnv = %v, want two names", cfg.PassEnv)
	}
}

// Naming one of the agent's own settings here would forward it to every job.
// That is a misconfiguration with no safe reading, so it stops the agent
// instead of being dropped and leaving the operator to wonder.
func TestLoadConfigRejectsPassEnvNamingItsOwnConfiguration(t *testing.T) {
	setAgentEnv(t, map[string]string{
		"RUNJET_URL":         "https://scheduler.example",
		"RUNJET_PUBLIC_KEYS": testKeyRing(t),
		"AGENT_PASS_ENV":     "ENROLLMENT_TOKEN",
	})

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig accepted AGENT_PASS_ENV=ENROLLMENT_TOKEN")
	}
	if !strings.Contains(err.Error(), "ENROLLMENT_TOKEN") {
		t.Errorf("error %q does not name the offending entry", err)
	}
}

// A poll wait that cannot be parsed is refused rather than defaulted: the value
// sizes the client's own HTTP timeout, and guessing at it would turn every poll
// into what looks like a network failure.
func TestLoadConfigRejectsABadPollWait(t *testing.T) {
	setAgentEnv(t, map[string]string{
		"RUNJET_URL":         "https://scheduler.example",
		"RUNJET_PUBLIC_KEYS": testKeyRing(t),
		"AGENT_POLL_WAIT":    "half a minute",
	})

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig accepted an unparseable AGENT_POLL_WAIT")
	}
}

// Parallelism is a comfort setting, so a nonsensical value falls back rather
// than blocking an agent from starting. Zero would stall it outright.
func TestLoadConfigFallsBackOnABadMaxParallel(t *testing.T) {
	for _, raw := range []string{"lots", "0", "-2"} {
		t.Run(raw, func(t *testing.T) {
			setAgentEnv(t, map[string]string{
				"RUNJET_URL":         "https://scheduler.example",
				"RUNJET_PUBLIC_KEYS": testKeyRing(t),
				"AGENT_MAX_PARALLEL": raw,
			})

			cfg, err := loadConfig()
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.MaxParallel != 4 {
				t.Errorf("MaxParallel = %d, want the default", cfg.MaxParallel)
			}
		})
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	cfg := config{StateDir: filepath.Join(t.TempDir(), "state")}
	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	want := identity{AgentID: "agent-1", AgentName: "worker-01", PrivateKey: encodePrivateKey(priv)}

	if err := cfg.saveIdentity(want); err != nil {
		t.Fatalf("saveIdentity: %v", err)
	}
	got, loaded, ok, err := cfg.loadIdentity()
	if err != nil {
		t.Fatalf("loadIdentity: %v", err)
	}
	if !ok {
		t.Fatal("loadIdentity reported no stored identity right after saving one")
	}
	if got.AgentID != want.AgentID || got.AgentName != want.AgentName {
		t.Errorf("identity = %+v, want %+v", got, want)
	}
	// The key has to come back usable, not merely present: it signs every
	// request the agent makes from here on.
	if !loaded.Equal(priv) {
		t.Error("the loaded private key does not match the one that was saved")
	}
}

// This file holds the one secret on the agent host. World-readable, it would
// let any local user impersonate the agent to the scheduler.
func TestSaveIdentityIsNotWorldReadable(t *testing.T) {
	cfg := config{StateDir: filepath.Join(t.TempDir(), "state")}
	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	if err := cfg.saveIdentity(identity{AgentID: "a", PrivateKey: encodePrivateKey(priv)}); err != nil {
		t.Fatalf("saveIdentity: %v", err)
	}

	file, err := os.Stat(cfg.identityPath())
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if perm := file.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity file mode = %04o, want 0600", perm)
	}
	dir, err := os.Stat(cfg.StateDir)
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Errorf("state dir mode = %04o, want 0700", perm)
	}
}

// A first run has no identity, and that is the signal to enrol — not an error.
func TestLoadIdentityWithoutAPreviousEnrollment(t *testing.T) {
	cfg := config{StateDir: filepath.Join(t.TempDir(), "state")}

	_, _, ok, err := cfg.loadIdentity()
	if err != nil {
		t.Fatalf("loadIdentity = %v, want nil for a first run", err)
	}
	if ok {
		t.Error("loadIdentity reported an identity in an empty state dir")
	}
}

// A corrupt identity must stop the agent. Falling through to enrolment would
// need a token nobody has, and silently discarding it would abandon the
// registration the scheduler still knows about.
func TestLoadIdentityRejectsACorruptFile(t *testing.T) {
	cases := map[string]string{
		"not json":      "{{{",
		"bad key":       `{"agentId":"a","agentName":"w","privateKey":"!!not base64!!"}`,
		"key too short": `{"agentId":"a","agentName":"w","privateKey":"c2hvcnQ="}`,
		"no key at all": `{"agentId":"a","agentName":"w"}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config{StateDir: t.TempDir()}
			if err := os.WriteFile(cfg.identityPath(), []byte(content), 0o600); err != nil {
				t.Fatalf("write identity: %v", err)
			}

			if _, _, ok, err := cfg.loadIdentity(); err == nil {
				t.Fatalf("loadIdentity accepted %s (ok=%v)", name, ok)
			}
		})
	}
}

func TestSaveIdentityWritesJSON(t *testing.T) {
	// The file is meant to be readable by an operator debugging an enrolment.
	cfg := config{StateDir: t.TempDir()}
	_, priv, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	if err := cfg.saveIdentity(identity{
		AgentID: "agent-1", AgentName: "worker-01", PrivateKey: encodePrivateKey(priv),
	}); err != nil {
		t.Fatalf("saveIdentity: %v", err)
	}

	raw, err := os.ReadFile(cfg.identityPath())
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	var parsed identity
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("identity file is not valid JSON: %v", err)
	}
	if parsed.AgentName != "worker-01" {
		t.Errorf("agentName = %q, want worker-01", parsed.AgentName)
	}
}

func mustPublicKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

// A state directory that cannot be read is not an agent that has never
// enrolled. Confusing the two would spend a fresh token and abandon a
// registration the scheduler still holds.
func TestLoadIdentityDistinguishesUnreadableFromAbsent(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(blocked, []byte("a file, not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{StateDir: blocked}

	_, _, ok, err := cfg.loadIdentity()
	if err == nil {
		t.Fatal("an unreadable state directory was reported as \"never enrolled\"")
	}
	if ok {
		t.Error("ok = true alongside an error")
	}
	if !strings.Contains(err.Error(), "read identity") {
		t.Errorf("error = %v, want it to say the identity could not be read", err)
	}
}

// The private key has nowhere to go. Silence here would leave an agent holding
// a key in memory that cannot survive a restart, on a token already spent.
func TestSaveIdentityReportsWhereItCouldNotWrite(t *testing.T) {
	t.Run("the state directory cannot be created", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "state")
		if err := os.WriteFile(blocked, []byte("a file, not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := config{StateDir: blocked}.saveIdentity(identity{AgentID: "a"})
		if err == nil {
			t.Fatal("saveIdentity reported success with no directory to write into")
		}
		if !strings.Contains(err.Error(), "create state dir") {
			t.Errorf("error = %v, want it to name the directory", err)
		}
	})

	t.Run("the file cannot be written", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes into a read-only directory, so the failure cannot be staged")
		}
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		err := config{StateDir: dir}.saveIdentity(identity{AgentID: "a"})
		if err == nil {
			t.Fatal("saveIdentity reported success although nothing was written")
		}
		if !strings.Contains(err.Error(), "write identity") {
			t.Errorf("error = %v, want it to say the identity could not be written", err)
		}
	})
}
