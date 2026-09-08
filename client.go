package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mr-jablon/runjet-agent/protocol"
	"github.com/mr-jablon/runjet-agent/signing"
)

// client speaks the agent protocol: it signs everything it sends and verifies
// everything it is told to run.
type client struct {
	// jobUser and jobIsolated describe how this host runs commands, sent on
	// every request the way the version is.
	jobUser     string
	jobIsolated bool

	baseURL string
	http    *http.Client
	keys    signing.KeyRing
	signer  *signing.Signer
	agentID string
}

// enrollTimeout bounds the one request an enrollment makes. It is generous
// because it is run by hand, once, and a person is watching it.
const enrollTimeout = 60 * time.Second

// pollSlack is how much longer than the wait it asked for the agent will hold a
// poll open. Enough for the request and the answer to cross a slow link, and
// short enough that a scheduler which simply stopped replying is noticed. A var
// so tests can shrink it; nothing else assigns to it.
var pollSlack = 30 * time.Second

func newClient(baseURL string, keys signing.KeyRing) *client {
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		keys:    keys,
		// No Timeout on the client, deliberately. It is one number for every
		// request, and the long poll's length is not fixed: the control plane
		// raises it through Limits, and pollWaitFor honours the longer of the
		// two. A timeout sized from this host's own setting would then cut
		// every poll short, each one reported as a network failure — and since
		// the raised wait is only replaced by a *successful* poll, the agent
		// would never receive work again. Every call carries its own deadline
		// instead, and poll derives one from the wait it was actually given.
		http: &http.Client{},
	}
}

// authenticate installs the identity used to sign subsequent requests.
func (c *client) authenticate(agentID string, priv ed25519.PrivateKey) error {
	signer, err := signing.NewSigner(agentID, priv)
	if err != nil {
		return err
	}
	c.signer = signer
	c.agentID = agentID
	return nil
}

type enrollRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"publicKey"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

type enrollResponse struct {
	AgentID   string `json:"agentId"`
	AgentName string `json:"agentName"`
	KeyID     string `json:"keyId"`
	Protocol  int    `json:"protocol"`
	PollWait  string `json:"pollWait"`
}

// enroll exchanges a one-time token for a registered keypair.
//
// The keypair is generated here and the private half never leaves this host —
// the scheduler only ever learns the public part. The response is verified
// against the configured scheduler key before any of it is believed, so an
// impostor cannot complete enrollment even if it can intercept the request.
func (c *client) enroll(ctx context.Context, token, version string) (enrollResponse, ed25519.PrivateKey, error) {
	pub, priv, err := signing.GenerateKey()
	if err != nil {
		return enrollResponse{}, nil, fmt.Errorf("generate keypair: %w", err)
	}

	body, err := json.Marshal(enrollRequest{
		Token:     token,
		PublicKey: signing.EncodeKey(pub),
		Version:   version,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	})
	if err != nil {
		return enrollResponse{}, nil, err
	}

	// Enrollment is one request against a scheduler that may not be there, run
	// by hand at an install, so it needs a deadline of its own: the caller's
	// context is a signal handler's and waits forever.
	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return enrollResponse{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Protocol-Version", strconv.Itoa(protocol.AgentProtocolVersion))

	raw, err := c.do(req)
	if err != nil {
		return enrollResponse{}, nil, err
	}

	var env signing.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return enrollResponse{}, nil, fmt.Errorf("decode enrollment envelope: %w", err)
	}
	var out enrollResponse
	if err := c.keys.Open(env, &out); err != nil {
		return enrollResponse{}, nil, fmt.Errorf("enrollment response is not from a trusted scheduler: %w", err)
	}
	if out.Protocol != protocol.AgentProtocolVersion {
		return enrollResponse{}, nil, fmt.Errorf("scheduler speaks protocol %d, this agent speaks %d",
			out.Protocol, protocol.AgentProtocolVersion)
	}
	return out, priv, nil
}

type workResponse struct {
	Dispatches []signing.Envelope `json:"dispatches"`
	Cancel     []signing.Envelope `json:"cancel"`
	Limits     *signing.Envelope  `json:"limits"`
}

// poll waits for work, returning the dispatches the scheduler signed. Every
// item is verified here; anything that fails verification is refused outright
// rather than executed and reported as a failure.
// work is one poll's answer: what to start, and what to stop.
type work struct {
	dispatches []protocol.Dispatch
	cancels    []protocol.Cancel
	// limits is nil when the server said nothing — an older one, or this agent
	// speaking a version that predates them. The agent then keeps its own
	// settings, which is exactly what it did before they existed.
	limits *protocol.Limits
}

func (c *client) poll(ctx context.Context, wait time.Duration) (work, error) {
	// The deadline follows the wait this poll was given, not the one this host
	// was configured with, so a wait the control plane raised is answered
	// rather than abandoned.
	ctx, cancel := context.WithTimeout(ctx, wait+pollSlack)
	defer cancel()

	path := "/agent/work?wait=" + strconv.Itoa(int(wait.Seconds()))
	req, err := c.signedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return work{}, err
	}
	raw, err := c.do(req)
	if err != nil {
		return work{}, err
	}

	var out workResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return work{}, fmt.Errorf("decode work response: %w", err)
	}

	var w work
	w.dispatches = make([]protocol.Dispatch, 0, len(out.Dispatches))
	for _, env := range out.Dispatches {
		var d protocol.Dispatch
		if err := c.keys.Open(env, &d); err != nil {
			return work{}, fmt.Errorf("refusing unverifiable dispatch: %w", err)
		}
		if d.Protocol != protocol.AgentProtocolVersion {
			return work{}, fmt.Errorf("dispatch speaks protocol %d, this agent speaks %d",
				d.Protocol, protocol.AgentProtocolVersion)
		}
		if !d.ExpiresAt.IsZero() && time.Now().After(d.ExpiresAt) {
			return work{}, fmt.Errorf("refusing dispatch for run %s: expired at %s", d.RunID, d.ExpiresAt)
		}
		w.dispatches = append(w.dispatches, d)
	}

	// Verified exactly as strictly as a dispatch. Being asked to *stop* doing
	// something looks harmless next to being asked to start, which is why it is
	// worth saying that it is not: an unverified stop is a way to silence
	// somebody's scheduled work from outside.
	for _, env := range out.Cancel {
		var cn protocol.Cancel
		if err := c.keys.Open(env, &cn); err != nil {
			return work{}, fmt.Errorf("refusing unverifiable cancellation: %w", err)
		}
		if cn.Protocol != protocol.AgentProtocolVersion {
			return work{}, fmt.Errorf("cancellation speaks protocol %d, this agent speaks %d",
				cn.Protocol, protocol.AgentProtocolVersion)
		}
		if !cn.ExpiresAt.IsZero() && time.Now().After(cn.ExpiresAt) {
			return work{}, fmt.Errorf("refusing cancellation for run %s: expired at %s",
				cn.RunID, cn.ExpiresAt)
		}
		w.cancels = append(w.cancels, cn)
	}

	// Verified like everything else. Raising a cap is the interesting forgery
	// rather than lowering one: an unverified ceiling would let whoever sits on
	// the wire use this host's own agent to exhaust it.
	if out.Limits != nil {
		var lim protocol.Limits
		if err := c.keys.Open(*out.Limits, &lim); err != nil {
			return work{}, fmt.Errorf("refusing unverifiable limits: %w", err)
		}
		if lim.Protocol != protocol.AgentProtocolVersion {
			return work{}, fmt.Errorf("limits speak protocol %d, this agent speaks %d",
				lim.Protocol, protocol.AgentProtocolVersion)
		}
		if lim.ExpiresAt.IsZero() || time.Now().Before(lim.ExpiresAt) {
			w.limits = &lim
		}
	}
	return w, nil
}

// signedRequest builds a request carrying the signature headers the scheduler
// verifies. The nonce is fresh per request, which is what makes a captured
// request useless to replay.
func (c *client) signedRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	if c.signer == nil {
		return nil, fmt.Errorf("agent is not enrolled")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce)
	timestamp := time.Now().Unix()

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Agent-Id", c.agentID)
	req.Header.Set("X-Nonce", encodedNonce)
	req.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Protocol-Version", strconv.Itoa(protocol.AgentProtocolVersion))
	// Sent on every request so an upgrade shows up without re-enrolling. It sits
	// outside the signature deliberately: it is a self-reported label that
	// nothing is decided by, not an authorisation input.
	req.Header.Set("X-Agent-Version", version)
	// What this host runs commands as, so the agent list can show it. Reported
	// and never obeyed: the account is the operator's decision, and Runjet's
	// part is to make an unsafe one visible rather than to correct it.
	if c.jobUser != "" {
		req.Header.Set("X-Agent-Job-User", c.jobUser)
		req.Header.Set("X-Agent-Job-Isolated", strconv.FormatBool(c.jobIsolated))
	}
	req.Header.Set("X-Signature", c.signer.Sign(signing.Request{
		Method:    method,
		Path:      path,
		Timestamp: timestamp,
		Nonce:     encodedNonce,
		Body:      body,
	}))
	return req, nil
}

func (c *client) do(req *http.Request) ([]byte, error) {
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, res.Status, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
