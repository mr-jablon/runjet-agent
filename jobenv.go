package main

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mr-jablon/runjet-agent/runner"
)

// This file draws the line between the agent and the commands it runs.
//
// A job used to inherit the agent's entire environment, so `env` inside any job
// printed the scheduler URL, the key the agent trusts, the path to its secrets
// file, and — when it had not been cleaned up after enrollment — the enrollment
// token itself. Secrets supplied through the agent's own environment reached
// every job whether it had asked for them or not, which left "a job names what
// it needs" true only of the file.
//
// What a command receives is now assembled here and nowhere else.

// reservedEnv are the names the agent reads its own configuration from. They
// are removed from the process environment once startup is done, and refused in
// AGENT_PASS_ENV: forwarding one on purpose would undo the boundary.
var reservedEnv = []string{
	"RUNJET_URL",
	"RUNJET_PUBLIC_KEYS",
	"ENROLLMENT_TOKEN",
	"AGENT_NAME",
	"AGENT_STATE_DIR",
	"AGENT_SECRETS_FILE",
	"AGENT_MAX_PARALLEL",
	"AGENT_POLL_WAIT",
	"AGENT_PASS_ENV",
	"AGENT_JOB_USER",
	"AGENT_JOB_GROUP",
}

// passthroughEnv is what a job inherits by default: enough for a command to
// behave the way it would in a shell on this host, and nothing that describes
// the agent.
var passthroughEnv = []string{"PATH", "TZ", "LANG"}

// accountEnv describes the account a command runs under. These are derived from
// the job's own user rather than inherited, because the agent's HOME points at
// its state directory — the one place jobs are being kept out of, and a
// confusing thing for `cd ~` to land in.
var accountEnv = []string{"HOME", "USER", "LOGNAME", "SHELL"}

// localePrefix is forwarded as a group. LC_ALL, LC_TIME, LC_COLLATE and the
// rest change how commands sort and format, and a job that behaves one way by
// hand and another under the agent is an expensive surprise.
const localePrefix = "LC_"

// jobEnv is the environment job commands run with.
//
// It is built once, at startup, and it is complete: a run gets exactly this
// plus the secrets it declared. Since nothing arrives by inheritance, a setting
// added to the agent later cannot reach a job by default — it has to be named.
type jobEnv struct {
	base []string
}

// newJobEnv snapshots what jobs may see. Entries keep the order os.Environ
// reports them in, so the result is stable across calls.
func newJobEnv(u jobUser, pass []string) jobEnv {
	want := make(map[string]bool, len(passthroughEnv)+len(pass))
	for _, key := range passthroughEnv {
		want[key] = true
	}
	for _, key := range pass {
		want[key] = true
	}
	// Only inherited while jobs share the agent's account, where inherited and
	// derived describe the same user anyway.
	if !u.separate() {
		for _, key := range accountEnv {
			want[key] = true
		}
	}

	var base []string
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if want[key] || strings.HasPrefix(key, localePrefix) {
			base = append(base, entry)
		}
	}
	if u.separate() {
		base = append(base,
			"HOME="+u.Home,
			"USER="+u.Name,
			"LOGNAME="+u.Name,
			// The runner executes through `sh`, so this is what the command is
			// actually running under — more accurate than the agent user's
			// login shell would have been.
			"SHELL=/bin/sh",
		)
	}
	return jobEnv{base: base}
}

// forRun returns the environment for a single run. Secrets come last so a value
// the job asked for wins over anything of the same name in the base.
func (e jobEnv) forRun(secrets []string) []string {
	env := make([]string, 0, len(e.base)+len(secrets))
	env = append(env, e.base...)
	return append(env, secrets...)
}

// jobRuntime is how commands run on this host: who they run as, and what they
// can see. Both are settled once, at startup, and every run is assembled from
// them in one place so the two cannot drift apart.
type jobRuntime struct {
	user jobUser
	env  jobEnv
}

func (r jobRuntime) spec(command string, timeout time.Duration, secrets []string) runner.Spec {
	return runner.Spec{
		Command: command,
		Timeout: timeout,
		Environ: r.env.forRun(secrets),
		User:    r.user.Cred,
		Dir:     r.user.WorkDir,
	}
}

// parsePassEnv reads AGENT_PASS_ENV: exact variable names, comma separated,
// that this host needs its jobs to receive.
//
// Patterns are refused rather than quietly matching nothing. A glob is how an
// allowlist decays back into a leak — AWS_* reads as precise and forwards
// whatever is named that way a year from now.
func parsePassEnv(raw string) ([]string, error) {
	var names []string
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, "*?[") {
			return nil, fmt.Errorf("AGENT_PASS_ENV entry %q looks like a pattern: list exact names, "+
				"since a glob also forwards whatever is called that later", name)
		}
		if slices.Contains(reservedEnv, name) {
			return nil, fmt.Errorf("AGENT_PASS_ENV names %s, which is this agent's own configuration: "+
				"forwarding it hands jobs the very thing the allowlist keeps from them", name)
		}
		names = append(names, name)
	}
	return names, nil
}

// scrubEnv removes the agent's own configuration from the process environment.
//
// Everything has been read into memory by the time this runs, so what remains
// is a copy that serves nothing and that a job can still reach — by reading
// /proc/<pid>/environ for as long as it shares the agent's user, or through
// inheritance if the runner ever regressed. Not having it there is free.
func scrubEnv() {
	for _, key := range reservedEnv {
		os.Unsetenv(key)
	}
}
