package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
)

// secretStore resolves the secret names a job asks for into environment entries.
//
// Values live here and nowhere else in the system: the scheduler stores only
// names, and only names travel in a dispatch. That is the whole point of the
// design — a compromised control plane cannot hand out what it never held.
type secretStore struct {
	values map[string]string
	// env is the agent's environment as it stood when this store was built,
	// less the agent's own configuration.
	//
	// The fallback below reads this rather than calling os.Getenv per run, so
	// the answer is fixed at startup. Runs resolve concurrently and the agent
	// scrubs part of its own environment once configuration is loaded; what a
	// job is handed should depend on how the agent was set up, not on when its
	// run happened to begin.
	env    map[string]string
	logger *slog.Logger
}

// loadSecrets reads an optional KEY=value file. Missing file is not an error:
// an agent may keep everything in its own environment instead.
//
// Parsing is deliberately literal. The key is trimmed, the value is taken
// verbatim after the first '=', because a secret may legitimately begin or end
// with a space and quietly trimming it would produce a failure that looks like
// a wrong password rather than a parsing bug.
func loadSecrets(path string, logger *slog.Logger) (*secretStore, error) {
	s := &secretStore{values: map[string]string{}, env: environMap(), logger: logger}
	if path == "" {
		return s, nil
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("AGENT_SECRETS_FILE %q does not exist", path)
	}
	if err != nil {
		return nil, fmt.Errorf("stat secrets file: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		logger.Warn("secrets file is readable by other users on this host",
			"path", path, "mode", fmt.Sprintf("%04o", mode), "want", "0600")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open secrets file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=value", path, line)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("%s:%d: empty key", path, line)
		}
		s.values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read secrets file: %w", err)
	}
	logger.Info("secrets loaded", "path", path, "count", len(s.values))
	// Said once, at startup, rather than on every run that uses one: a value
	// this short cannot be masked in run output without starring out ordinary
	// text, so it will appear in logs verbatim. Only the names are logged.
	if short := s.tooShortToMask(); len(short) > 0 {
		logger.Warn("some secrets are too short to mask in run output and will appear in it verbatim",
			"secrets", short, "minLength", minMaskedLength)
	}
	return s, nil
}

// tooShortToMask names the configured secrets whose values the redactor will
// not mask, sorted so the warning reads the same across restarts.
//
// Only file-based secrets can be checked here. An agent supplying secrets
// through its own environment gives the store no way to tell which of its
// variables are secret, so those meet the same rule unannounced.
func (s *secretStore) tooShortToMask() []string {
	var short []string
	for name, value := range s.values {
		if len(value) < minMaskedLength {
			short = append(short, name)
		}
	}
	slices.Sort(short)
	return short
}

// resolve turns the names a job asked for into environment entries.
//
// A name this agent cannot supply fails the run. Substituting an empty value
// would be worse than useless: a backup would write to the wrong place, or an
// API call would quietly run unauthenticated, and the run would report success.
func (s *secretStore) resolve(names []string) ([]string, error) {
	env := make([]string, 0, len(names))
	var missing []string
	for _, name := range names {
		value, ok := s.values[name]
		if !ok {
			// Fall back to the agent's own environment, which is how a systemd
			// unit or a container can supply secrets without a file. Its own
			// configuration is not in there — see environMap.
			value, ok = s.env[name]
		}
		if !ok {
			missing = append(missing, name)
			continue
		}
		env = append(env, name+"="+value)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("this agent has no value for %s", strings.Join(missing, ", "))
	}
	return env, nil
}

// environMap copies the process environment into a map, leaving out the names
// the agent configures itself with. Callers hold the copy so that scrubEnv can
// empty the real one without taking their data with it.
//
// The omission is the point. This copy is taken *before* scrubEnv runs, so
// without it the store would be the one place on the host still holding
// ENROLLMENT_TOKEN and the rest of the agent's own settings — and resolve hands
// back whatever a dispatch names. AGENT_PASS_ENV already refuses to forward
// these for exactly that reason; a dispatch that asks for one as a secret is
// the same request arriving by the other door, and the job account exists to
// keep those values out of a command's reach.
func environMap() map[string]string {
	entries := os.Environ()
	env := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || slices.Contains(reservedEnv, key) {
			continue
		}
		env[key] = value
	}
	return env
}
