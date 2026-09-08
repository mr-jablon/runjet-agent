package main

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/mr-jablon/runjet-agent/runner"
)

// The job environment is the one place the agent's configuration could escape
// wholesale, so most of what these tests assert is what is *absent*. A leak
// here is silent: the job runs, the run succeeds, and the token is simply gone.

func hasKey(env []string, key string) bool {
	for _, entry := range env {
		if name, _, ok := strings.Cut(entry, "="); ok && name == key {
			return true
		}
	}
	return false
}

func TestNewJobEnvKeepsTheBaseSetAndDropsTheRest(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("LC_TIME", "cs_CZ.UTF-8")
	t.Setenv("RUNJET_PUBLIC_KEYS", "sched-1:key")
	t.Setenv("ENROLLMENT_TOKEN", "one-time")
	t.Setenv("AGENT_SECRETS_FILE", "/etc/runjet-agent/secrets")
	t.Setenv("JAVA_HOME", "/opt/java")

	base := newJobEnv(jobUser{}, nil).base

	for _, want := range []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "LC_TIME=cs_CZ.UTF-8"} {
		if !slices.Contains(base, want) {
			t.Errorf("base is missing %q: %v", want, base)
		}
	}
	// The agent's own settings are the point of the exercise.
	for _, key := range []string{"RUNJET_PUBLIC_KEYS", "ENROLLMENT_TOKEN", "AGENT_SECRETS_FILE"} {
		if hasKey(base, key) {
			t.Errorf("%s reached the job environment: %v", key, base)
		}
	}
	// And an unremarkable host variable is dropped too — closed by default is
	// what makes a setting added later safe without anyone revisiting this.
	if hasKey(base, "JAVA_HOME") {
		t.Errorf("JAVA_HOME was forwarded without being named: %v", base)
	}
}

func TestNewJobEnvForwardsNamedVariables(t *testing.T) {
	t.Setenv("JAVA_HOME", "/opt/java")
	t.Setenv("HTTPS_PROXY", "http://proxy:3128")
	t.Setenv("UNNAMED", "nope")

	base := newJobEnv(jobUser{}, []string{"JAVA_HOME", "HTTPS_PROXY"}).base

	for _, want := range []string{"JAVA_HOME=/opt/java", "HTTPS_PROXY=http://proxy:3128"} {
		if !slices.Contains(base, want) {
			t.Errorf("base is missing %q: %v", want, base)
		}
	}
	if hasKey(base, "UNNAMED") {
		t.Errorf("a variable nobody named was forwarded: %v", base)
	}
}

func TestForRunPutsSecretsLast(t *testing.T) {
	// Later entries win in the environment a process receives, so a value the
	// job asked for has to come after anything of the same name in the base.
	e := jobEnv{base: []string{"PATH=/bin", "TOKEN=from-base"}}

	env := e.forRun([]string{"TOKEN=from-secret"})

	if got := env[len(env)-1]; got != "TOKEN=from-secret" {
		t.Errorf("last entry = %q, want the secret", got)
	}
}

// AGENT_MAX_PARALLEL means several runs assemble their environment at once. If
// forRun handed back a slice backed by base, one run's secrets would land in
// another's — and the two jobs need not have asked for the same names.
func TestForRunDoesNotShareStorageBetweenRuns(t *testing.T) {
	e := jobEnv{base: []string{"PATH=/bin"}}

	first := e.forRun([]string{"FIRST=1"})
	second := e.forRun([]string{"SECOND=2"})

	if slices.Contains(first, "SECOND=2") {
		t.Errorf("the second run's secret appeared in the first: %v", first)
	}
	if slices.Contains(second, "FIRST=1") {
		t.Errorf("the first run's secret appeared in the second: %v", second)
	}
}

func TestParsePassEnvReadsExactNames(t *testing.T) {
	names, err := parsePassEnv("  JAVA_HOME , ,HTTPS_PROXY  ")
	if err != nil {
		t.Fatalf("parsePassEnv: %v", err)
	}
	if !slices.Equal(names, []string{"JAVA_HOME", "HTTPS_PROXY"}) {
		t.Errorf("names = %v, want the two entries with the blank dropped", names)
	}
}

func TestParsePassEnvEmpty(t *testing.T) {
	names, err := parsePassEnv("")
	if err != nil {
		t.Fatalf("parsePassEnv(\"\") = %v, want nil", err)
	}
	if len(names) != 0 {
		t.Errorf("names = %v, want none", names)
	}
}

// Forwarding one of these on purpose would hand jobs the very thing the
// allowlist exists to keep from them, so it stops the agent rather than
// quietly working.
func TestParsePassEnvRejectsTheAgentsOwnSettings(t *testing.T) {
	for _, name := range []string{"ENROLLMENT_TOKEN", "RUNJET_PUBLIC_KEYS", "AGENT_SECRETS_FILE"} {
		t.Run(name, func(t *testing.T) {
			_, err := parsePassEnv("JAVA_HOME," + name)
			if err == nil {
				t.Fatalf("parsePassEnv accepted %s", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error %q does not name the offending entry", err)
			}
		})
	}
}

// A glob reads as precise and forwards whatever is called that next year. Since
// it would otherwise match nothing at all, refusing it is also the only way the
// operator finds out.
func TestParsePassEnvRejectsPatterns(t *testing.T) {
	for _, raw := range []string{"AWS_*", "LC_?", "A[BC]"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := parsePassEnv(raw); err == nil {
				t.Fatalf("parsePassEnv accepted %q as a name", raw)
			}
		})
	}
}

// Once configuration has been read, the copy the kernel keeps serves nothing —
// and a job sharing the agent's user can read it straight out of /proc.
func TestScrubEnvRemovesEveryReservedName(t *testing.T) {
	for _, key := range reservedEnv {
		t.Setenv(key, "value")
	}

	scrubEnv()

	for _, key := range reservedEnv {
		if _, ok := os.LookupEnv(key); ok {
			t.Errorf("%s survived scrubEnv", key)
		}
	}
}

// The boundary itself, exercised end to end through the pieces the agent wires
// together — a real command, the real composition, the real secret store.
//
// OTHER_SECRET is the one that matters most: a value sitting in the agent's own
// environment used to reach every job whether it had asked for it or not, which
// left "a job names what it needs" true only of the secrets file.
func TestAJobSeesTheBaseSetItsOwnSecretsAndNothingElse(t *testing.T) {
	t.Setenv("ENROLLMENT_TOKEN", "one-time-token")
	t.Setenv("RUNJET_PUBLIC_KEYS", "sched-1:trusted-key")
	t.Setenv("DB_PASSWORD", "hunter2")
	t.Setenv("OTHER_SECRET", "not-for-this-job")

	secrets, err := loadSecrets("", discardLogger())
	if err != nil {
		t.Fatalf("loadSecrets: %v", err)
	}
	jobs := newJobEnv(jobUser{}, nil)
	scrubEnv()

	env, err := secrets.resolve([]string{"DB_PASSWORD"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var out bytes.Buffer
	outcome := runner.Run(context.Background(), runner.Spec{
		Command: "env",
		Environ: jobs.forRun(env),
	}, &out)
	if !outcome.OK() {
		t.Fatalf("outcome = %+v, want OK", outcome)
	}

	if !strings.Contains(out.String(), "DB_PASSWORD=hunter2") {
		t.Errorf("the secret the job declared never arrived:\n%s", out.String())
	}
	for _, absent := range []string{"one-time-token", "trusted-key", "not-for-this-job"} {
		if strings.Contains(out.String(), absent) {
			t.Errorf("%q reached the job command:\n%s", absent, out.String())
		}
	}
}

// Every name the agent configures itself with has to be scrubbed and refused in
// AGENT_PASS_ENV. Reading them off the struct is what keeps a setting added
// later from being covered by neither.
func TestReservedNamesCoverTheAgentsConfiguration(t *testing.T) {
	for _, key := range []string{
		"RUNJET_URL", "RUNJET_PUBLIC_KEYS", "ENROLLMENT_TOKEN", "AGENT_NAME",
		"AGENT_STATE_DIR", "AGENT_SECRETS_FILE", "AGENT_MAX_PARALLEL", "AGENT_POLL_WAIT",
		"AGENT_PASS_ENV", "AGENT_JOB_USER", "AGENT_JOB_GROUP",
	} {
		if !slices.Contains(reservedEnv, key) {
			t.Errorf("%s is read by loadConfig but is not reserved: it would reach jobs", key)
		}
	}
}
