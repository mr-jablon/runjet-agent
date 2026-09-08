package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secret values live on the agent and nowhere else in the system, so this file
// is the only place they exist at all. Two things matter: the parsing must be
// literal, because a quietly trimmed value fails as a wrong password rather than
// as a parsing bug; and a name the agent cannot supply must fail the run rather
// than resolve to empty.

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func writeSecrets(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write secrets: %v", err)
	}
	return path
}

func TestLoadSecretsWithoutAFile(t *testing.T) {
	// An agent may keep everything in its own environment: no file configured is
	// a valid setup, not a missing one.
	s, err := loadSecrets("", discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets(\"\") = %v, want nil", err)
	}
	if s == nil {
		t.Fatal("loadSecrets returned no store")
	}
}

// A configured file that is not there is a different matter: it is a typo or a
// missing mount, and starting without the secrets would fail every run that
// needs them, one confusing failure at a time.
func TestLoadSecretsFailsOnAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.env")

	if _, err := loadSecrets(path, discardLogger()); err == nil {
		t.Fatal("loadSecrets accepted a path that does not exist")
	}
}

func TestLoadSecretsParsesEntries(t *testing.T) {
	path := writeSecrets(t, strings.Join([]string{
		"# a comment",
		"",
		"   ",
		"TOKEN=abc123",
		"  SPACED_KEY  =value",
		"EMPTY=",
		"WITH_EQUALS=a=b=c",
		"# TRAILING=comment is not an entry",
	}, "\n"))

	s, err := loadSecrets(path, discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	want := map[string]string{
		"TOKEN":       "abc123",
		"SPACED_KEY":  "value",
		"EMPTY":       "",
		"WITH_EQUALS": "a=b=c", // only the first '=' separates
	}
	for key, value := range want {
		if got, ok := s.values[key]; !ok || got != value {
			t.Errorf("values[%q] = %q, %v, want %q", key, got, ok, value)
		}
	}
	if len(s.values) != len(want) {
		t.Errorf("parsed %d entries, want %d: %v", len(s.values), len(want), s.values)
	}
}

// A secret may legitimately begin or end with a space. Trimming it would produce
// a failure that looks like a wrong credential rather than a parsing bug.
func TestLoadSecretsKeepsTheValueVerbatim(t *testing.T) {
	path := writeSecrets(t, "PADDED=  spaced value  \nQUOTED=\"quoted\"\n")

	s, err := loadSecrets(path, discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	if got := s.values["PADDED"]; got != "  spaced value  " {
		t.Errorf("PADDED = %q, want the surrounding spaces kept", got)
	}
	// Quotes are part of the value: this is not a shell, and stripping them
	// would make a password containing quotes impossible to express.
	if got := s.values["QUOTED"]; got != `"quoted"` {
		t.Errorf("QUOTED = %q, want the quotes kept", got)
	}
}

func TestLoadSecretsRejectsMalformedLines(t *testing.T) {
	cases := map[string]string{
		"no separator": "TOKEN=ok\nJUST_A_NAME\n",
		"empty key":    "TOKEN=ok\n=orphaned\n",
		"blank key":    "   =orphaned\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeSecrets(t, content)

			_, err := loadSecrets(path, discardLogger())
			if err == nil {
				t.Fatal("loadSecrets accepted a malformed file")
			}
			// The error names the file and line, because the operator is about to
			// go and look at it.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the file", err)
			}
		})
	}
}

// A world-readable secrets file is still usable — refusing to start would be a
// worse failure than the one being warned about — but it must not pass silently.
func TestLoadSecretsWarnsOnLoosePermissions(t *testing.T) {
	path := writeSecrets(t, "TOKEN=abc123\n")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if _, err := loadSecrets(path, logger); err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	if !strings.Contains(logged.String(), "readable by other users") {
		t.Errorf("no warning was logged for a 0644 secrets file: %q", logged.String())
	}
}

// Said once at startup rather than on every run that uses one, and only the
// names: an operator whose secret shows up verbatim in a log should have been
// told why before it happened, not by finding it there.
func TestLoadSecretsWarnsAboutValuesTooShortToMask(t *testing.T) {
	path := writeSecrets(t, "SHORT=prod\nLONG=long-enough-value\n")
	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if _, err := loadSecrets(path, logger); err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	out := logged.String()
	if !strings.Contains(out, "SHORT") {
		t.Errorf("nothing warned that SHORT cannot be masked: %q", out)
	}
	if strings.Contains(out, "prod") {
		t.Errorf("the warning printed the value it was warning about: %q", out)
	}
	if strings.Contains(out, "LONG") {
		t.Errorf("a value long enough to mask was named as unmaskable: %q", out)
	}
}

func TestResolveFromTheFile(t *testing.T) {
	path := writeSecrets(t, "TOKEN=abc123\nOTHER=xyz\n")
	s, err := loadSecrets(path, discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	env, err := s.resolve([]string{"TOKEN", "OTHER"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(env) != 2 || env[0] != "TOKEN=abc123" || env[1] != "OTHER=xyz" {
		t.Errorf("resolve = %v, want the requested names in order", env)
	}
}

// A systemd unit or a container can supply secrets without a file at all, so the
// agent's own environment is the fallback.
func TestResolveFallsBackToTheEnvironment(t *testing.T) {
	t.Setenv("FROM_ENV", "env-value")
	s, err := loadSecrets("", discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	env, err := s.resolve([]string{"FROM_ENV"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(env) != 1 || env[0] != "FROM_ENV=env-value" {
		t.Errorf("resolve = %v, want FROM_ENV from the environment", env)
	}
}

// AGENT_PASS_ENV refuses to forward the agent's own settings to a job, because
// forwarding one hands jobs the very thing the allowlist keeps from them. A
// dispatch naming one as a *secret* is the same request at the other door, and
// the store's copy of the environment is taken before scrubEnv empties it — so
// without this it would be the one place on the host still holding the token.
// The job account exists to keep these out of a command's reach; a signed
// dispatch must not be able to lift them out anyway.
func TestResolveWillNotHandBackTheAgentsOwnConfiguration(t *testing.T) {
	for _, name := range reservedEnv {
		t.Setenv(name, "the agent's own "+name)
	}
	s, err := loadSecrets("", discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	for _, name := range reservedEnv {
		if env, err := s.resolve([]string{name}); err == nil {
			t.Errorf("a dispatch asking for %s as a secret got it: %v", name, env)
		}
	}
}

// The environment is read once, at load, not per run. Runs resolve
// concurrently and the agent scrubs part of its own environment after startup,
// so a value that moves under a running agent would make two jobs asking for
// the same secret get different answers.
func TestResolveReadsTheEnvironmentAsItWasAtLoad(t *testing.T) {
	t.Setenv("FROM_ENV", "env-value")
	s, err := loadSecrets("", discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}
	os.Unsetenv("FROM_ENV")

	env, err := s.resolve([]string{"FROM_ENV"})
	if err != nil {
		t.Fatalf("resolve after the variable was removed: %v", err)
	}
	if len(env) != 1 || env[0] != "FROM_ENV=env-value" {
		t.Errorf("resolve = %v, want the value captured at load", env)
	}
}

// The file wins: it is the agent's explicit configuration, and an inherited
// variable of the same name would otherwise silently override it.
func TestResolvePrefersTheFileOverTheEnvironment(t *testing.T) {
	t.Setenv("TOKEN", "from-env")
	path := writeSecrets(t, "TOKEN=from-file\n")
	s, err := loadSecrets(path, discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	env, err := s.resolve([]string{"TOKEN"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if env[0] != "TOKEN=from-file" {
		t.Errorf("resolve = %v, want the file's value", env)
	}
}

// Substituting an empty value would be worse than useless: a backup would write
// to the wrong place, or an API call would quietly run unauthenticated, and the
// run would report success.
func TestResolveFailsOnAMissingSecret(t *testing.T) {
	path := writeSecrets(t, "KNOWN=ok\n")
	s, err := loadSecrets(path, discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	env, err := s.resolve([]string{"KNOWN", "ABSENT_ONE", "ABSENT_TWO"})
	if err == nil {
		t.Fatal("resolve succeeded with a name this agent cannot supply")
	}
	if env != nil {
		t.Errorf("resolve returned %v alongside an error", env)
	}
	// All of them are named at once: fixing one and rediscovering the next on
	// the following run is a slow way to learn what is missing.
	for _, name := range []string{"ABSENT_ONE", "ABSENT_TWO"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not mention %s", err, name)
		}
	}
}

func TestResolveWithNoNames(t *testing.T) {
	s, err := loadSecrets("", discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}

	env, err := s.resolve(nil)
	if err != nil {
		t.Fatalf("resolve(nil) = %v, want nil", err)
	}
	if len(env) != 0 {
		t.Errorf("resolve(nil) = %v, want no entries", env)
	}
}
