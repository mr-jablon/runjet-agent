package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mr-jablon/runjet-agent/signing"
)

// The one-time token used to be pasted into agent.env by hand, and the install
// ended with an instruction to go back and delete the line once it had been
// spent — precisely the kind of step that gets left undone, leaving a dead
// credential on disk on every host in the fleet.
//
// `runjet-agent enroll` spends it instead. The token arrives as an argument,
// is exchanged immediately, and what gets written is only what the agent needs
// from then on. It never reaches disk at all.

// enrollUsage is printed for -h and for a malformed invocation. The command is
// run once per host, by hand, so the example matters more than the flag list.
const enrollUsage = `Usage: runjet-agent enroll -url URL -key KEYS [-token TOKEN]

Enrols this host and writes what the agent needs to start. Runjet's
"Register agent" dialog produces the whole command.

  runjet-agent enroll \
    -url https://runjet.dev \
    -key sched-1:BASE64KEY \
    -token ONE-TIME-TOKEN

The token is spent during enrollment and is not written anywhere. It appears in
this host's process list while the command runs; -token-file, or feeding it on
stdin, avoids even that.

Flags:
`

func runEnroll(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(out)
	var (
		url       = fs.String("url", "", "scheduler URL")
		keys      = fs.String("key", "", "scheduler public keys to trust, as id:base64[,id:base64]")
		token     = fs.String("token", "", "one-time enrollment token")
		tokenFile = fs.String("token-file", "", "read the enrollment token from this file instead")
		stateDir  = fs.String("state-dir", defaultStateDir, "where the agent keeps its identity")
		envFile   = fs.String("env-file", defaultEnvFile, "environment file to write")
	)
	fs.Usage = func() {
		fmt.Fprint(out, enrollUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *keys == "" {
		fs.Usage()
		return errors.New("-url and -key are both required")
	}

	// Parsed before anything is spent: a mistyped key would otherwise burn the
	// token and leave the agent unable to believe the answer it just got.
	ring, err := signing.ParseKeyRing(*keys)
	if err != nil {
		return err
	}
	secret, err := readToken(*token, *tokenFile)
	if err != nil {
		return err
	}

	cfg := config{StateDir: *stateDir}
	if _, _, enrolled, err := cfg.loadIdentity(); err != nil {
		return err
	} else if enrolled {
		return fmt.Errorf("%s already holds an identity, so this host is enrolled\n"+
			"\tRe-enrolling would abandon a registration the scheduler still knows about. To\n"+
			"\tstart over, use Reset enrollment in the UI — it revokes the old key and issues\n"+
			"\ta new token — then remove this file", cfg.identityPath())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, priv, err := newClient(*url, ring).enroll(ctx, secret, version)
	if err != nil {
		return err
	}
	if err := cfg.saveIdentity(identity{
		AgentID:    res.AgentID,
		AgentName:  res.AgentName,
		PrivateKey: encodePrivateKey(priv),
	}); err != nil {
		return err
	}

	fmt.Fprintf(out, "Enrolled as %s (%s).\n", res.AgentName, res.AgentID)
	fmt.Fprintf(out, "Key written to %s.\n", cfg.identityPath())

	written, err := writeEnvFile(*envFile, *url, *keys, res.AgentName)
	if err != nil {
		return err
	}
	if written {
		fmt.Fprintf(out, "Settings written to %s.\n\nStart it:\n  systemctl enable --now runjet-agent\n", *envFile)
		return nil
	}
	// Overwriting could drop AGENT_PASS_ENV, AGENT_JOB_USER or a secrets path
	// somebody set on purpose, and this command has no way to tell a stale file
	// from a deliberate one.
	fmt.Fprintf(out, "\n%s already exists and was left alone. It needs:\n\n%s\n", *envFile,
		envFileBody(*url, *keys, res.AgentName))
	return nil
}

// readToken takes the token from wherever it was offered. Stdin is the default
// so that a token need never appear in the process list or in shell history.
func readToken(inline, file string) (string, error) {
	switch {
	case inline != "" && file != "":
		return "", errors.New("give -token or -token-file, not both")
	case inline != "":
		return inline, nil
	case file != "":
		raw, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return trimmedToken(string(raw))
	default:
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		return trimmedToken(string(raw))
	}
}

func trimmedToken(raw string) (string, error) {
	if token := strings.TrimSpace(raw); token != "" {
		return token, nil
	}
	return "", errors.New("no enrollment token: pass -token, -token-file, or feed it on stdin")
}

// writeEnvFile creates the environment file, reporting false when one was
// already there and has been left as it is.
func writeEnvFile(path, url, keys, name string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("check %s: %w", path, err)
	}

	// The directory holds this file and, conventionally, the secrets file
	// beside it, so it is not world-readable either.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(envFileBody(url, keys, name)), 0o600); err != nil {
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, nil
}

func envFileBody(url, keys, name string) string {
	return fmt.Sprintf(`# Written by `+"`runjet-agent enroll`"+`.
#
# There is no ENROLLMENT_TOKEN here on purpose: it was spent during enrollment
# and is of no further use. See agent.env.example for the optional settings.
RUNJET_URL=%s
RUNJET_PUBLIC_KEYS=%s
AGENT_NAME=%s
`, url, keys, name)
}
