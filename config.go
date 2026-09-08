package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/mr-jablon/runjet-agent/signing"
)

// Where the packaging puts things. `enroll` writes both, and the running agent
// reads the first; the second arrives as systemd's EnvironmentFile.
const (
	defaultStateDir = "/var/lib/runjet-agent"
	defaultEnvFile  = "/etc/runjet-agent/agent.env"
)

// config is everything an agent needs to reach its scheduler and to decide
// whether to believe it.
type config struct {
	RunjetURL       string
	RunjetKeys      signing.KeyRing // scheduler keys this agent will trust
	EnrollmentToken string          // first run only
	Name            string
	StateDir        string
	SecretsFile     string   // optional KEY=value file; values never leave this host
	PassEnv         []string // extra variable names job commands may inherit
	JobUser         string   // account job commands run as; empty runs them as the agent
	JobGroup        string   // only consulted when JobUser is a numeric id
	MaxParallel     int
	PollWait        time.Duration
}

// identity is what enrollment produces: who this agent is, and the private key
// it signs with. It is written to the state directory and never transmitted.
type identity struct {
	AgentID    string `json:"agentId"`
	AgentName  string `json:"agentName"`
	PrivateKey string `json:"privateKey"`
}

func loadConfig() (config, error) {
	cfg := config{
		RunjetURL:       getenv("RUNJET_URL", ""),
		EnrollmentToken: os.Getenv("ENROLLMENT_TOKEN"),
		Name:            getenv("AGENT_NAME", ""),
		StateDir:        getenv("AGENT_STATE_DIR", defaultStateDir),
		SecretsFile:     os.Getenv("AGENT_SECRETS_FILE"),
		MaxParallel:     getint("AGENT_MAX_PARALLEL", 4),
	}
	if cfg.RunjetURL == "" {
		return config{}, fmt.Errorf("RUNJET_URL is required")
	}

	raw := os.Getenv("RUNJET_PUBLIC_KEYS")
	if raw == "" {
		return config{}, fmt.Errorf("RUNJET_PUBLIC_KEYS is required: without it the agent " +
			"cannot tell its scheduler from anyone else who can reach it")
	}
	keys, err := signing.ParseKeyRing(raw)
	if err != nil {
		return config{}, err
	}
	cfg.RunjetKeys = keys

	wait, err := time.ParseDuration(getenv("AGENT_POLL_WAIT", "30s"))
	if err != nil {
		return config{}, fmt.Errorf("invalid AGENT_POLL_WAIT: %w", err)
	}
	cfg.PollWait = wait

	// Refused rather than defaulted: an operator who names something here has a
	// job that needs it, and silently dropping the setting would surface as
	// that job failing for no visible reason.
	pass, err := parsePassEnv(os.Getenv("AGENT_PASS_ENV"))
	if err != nil {
		return config{}, err
	}
	cfg.PassEnv = pass

	// LookupEnv rather than a default, because unset and set-to-empty mean
	// different things here: unset gets the account the packaging creates,
	// while an explicit empty value is how an operator says "run jobs as this
	// agent" and accepts what that costs.
	cfg.JobUser = defaultJobUser
	if raw, ok := os.LookupEnv("AGENT_JOB_USER"); ok {
		cfg.JobUser = raw
	}
	cfg.JobGroup = os.Getenv("AGENT_JOB_GROUP")
	return cfg, nil
}

func (c config) identityPath() string { return filepath.Join(c.StateDir, "identity.json") }

// loadIdentity reads a previous enrollment, reporting ok=false when this agent
// has never enrolled.
func (c config) loadIdentity() (identity, ed25519.PrivateKey, bool, error) {
	raw, err := os.ReadFile(c.identityPath())
	if os.IsNotExist(err) {
		return identity{}, nil, false, nil
	}
	if err != nil {
		return identity{}, nil, false, fmt.Errorf("read identity: %w", err)
	}
	var id identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return identity{}, nil, false, fmt.Errorf("parse identity: %w", err)
	}
	priv, err := signing.ParsePrivateKey(id.PrivateKey)
	if err != nil {
		return identity{}, nil, false, fmt.Errorf("identity key: %w", err)
	}
	return id, priv, true, nil
}

// saveIdentity persists the enrollment result. The file holds a private key, so
// it is created 0600 and the directory 0700 — this is the one secret on the
// agent host and it must not be world-readable.
func (c config) saveIdentity(id identity) error {
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.identityPath(), raw, 0o600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getint(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}

// encodePrivateKey renders the agent's private key for its identity file.
func encodePrivateKey(priv ed25519.PrivateKey) string {
	return signing.EncodeKey(priv)
}
