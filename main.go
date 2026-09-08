// Command agent runs jobs handed out by a Runjet control plane.
//
// It holds no inbound port: it dials out, waits on a long poll, and executes
// only what carries a valid signature from a scheduler key it was configured
// to trust.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mr-jablon/runjet-agent/protocol"
	"github.com/mr-jablon/runjet-agent/runner"
)

// version is reported at enrollment so the UI can flag outdated agents. It is
// stamped in at build time; "dev" marks a binary that did not go through
// build.sh, which is worth being able to tell apart in the field.
var version = "dev"

// pollBackoff is how long to wait after a failed poll. Enough to stop hammering
// a scheduler that is down or restarting, short enough to recover promptly.
const pollBackoff = 5 * time.Second

func main() {
	// Enrolment is a one-off, run by hand during an install, and it talks to a
	// person rather than to a log collector — so it gets plain output and an
	// exit status instead of the JSON the long-running agent emits.
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		if err := runEnroll(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
			os.Exit(1)
		}
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	secrets, err := loadSecrets(cfg.SecretsFile, logger)
	if err != nil {
		return err
	}

	who, err := resolveJobUser(cfg.JobUser, cfg.JobGroup)
	if err != nil {
		return err
	}
	if err := who.verify(ctx); err != nil {
		return err
	}
	if !who.separate() {
		logger.Warn("job commands run as this agent's own user, so they can read its private key " +
			"and its secrets file; set AGENT_JOB_USER to separate them")
	} else if who.WorkDir == "" {
		logger.Warn("the job account has no home directory, so commands run in the agent's "+
			"working directory and a job writing a relative path will fail; create it to give "+
			"jobs somewhere to work",
			"user", who.Name, "home", who.Home)
	}

	// Ordering matters here. Both of these take their copy of the environment,
	// and scrubbing empties the original — so anything that reads it has to
	// have read it by now.
	jobs := jobRuntime{user: who, env: newJobEnv(who, cfg.PassEnv)}
	scrubEnv()

	c := newClient(cfg.RunjetURL, cfg.RunjetKeys)
	// Reported on every request from here on, so the agent list can say what
	// this host runs commands as. `who.Name` is empty when jobs run as the
	// agent, and the effective account is then the agent's own — which is the
	// case worth showing, so it is resolved rather than left blank.
	c.jobUser, c.jobIsolated = jobAccount(who)
	id, err := ensureEnrolled(ctx, cfg, c, logger)
	if err != nil {
		return err
	}
	logger.Info("agent ready",
		"agent", id.AgentName, "id", id.AgentID,
		"runjet", cfg.RunjetURL, "maxParallel", cfg.MaxParallel,
		"jobUser", who.Name, "passEnv", cfg.PassEnv)

	pollLoop(ctx, cfg, c, secrets, jobs, logger)

	logger.Info("agent stopped")
	return nil
}

// ensureEnrolled reuses a previous enrollment, or performs a first one.
func ensureEnrolled(ctx context.Context, cfg config, c *client, logger *slog.Logger) (identity, error) {
	id, priv, ok, err := cfg.loadIdentity()
	if err != nil {
		return identity{}, err
	}
	if ok {
		return id, c.authenticate(id.AgentID, priv)
	}

	if cfg.EnrollmentToken == "" {
		return identity{}, errors.New("no stored identity and no ENROLLMENT_TOKEN: " +
			"register this agent in Runjet and pass the one-time token it issues")
	}
	logger.Info("enrolling with runjet", "runjet", cfg.RunjetURL)

	res, priv, err := c.enroll(ctx, cfg.EnrollmentToken, version)
	if err != nil {
		return identity{}, err
	}
	id = identity{
		AgentID:    res.AgentID,
		AgentName:  res.AgentName,
		PrivateKey: encodePrivateKey(priv),
	}
	if err := cfg.saveIdentity(id); err != nil {
		return identity{}, err
	}
	logger.Info("enrolled", "agent", id.AgentName, "id", id.AgentID, "runjetKey", res.KeyID)
	return id, c.authenticate(id.AgentID, priv)
}

// pollLoop is the agent's whole life: ask for work, run it, ask again.
func pollLoop(ctx context.Context, cfg config, c *client, secrets *secretStore, jobs jobRuntime, logger *slog.Logger) {
	var (
		wg      sync.WaitGroup
		room    = newSlots(cfg.MaxParallel)
		running = newInflight()
		wait    = cfg.PollWait
	)
	defer wg.Wait()

	for ctx.Err() == nil {
		w, err := c.poll(ctx, wait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("poll failed", "err", err, "retryIn", pollBackoff.String())
			select {
			case <-time.After(pollBackoff):
			case <-ctx.Done():
				return
			}
			continue
		}

		// The ceilings first, so the work in this same answer is bounded by
		// them rather than by whatever the last poll said.
		if w.limits != nil {
			before := room.current()
			room.setRemote(w.limits.MaxParallel)
			if after := room.current(); after != before {
				logger.Info("runjet changed how much runs at once",
					"was", before, "now", after)
			}
			if d, err := time.ParseDuration(w.limits.PollWait); err == nil {
				wait = pollWaitFor(cfg.PollWait, d)
			}
		}

		// Stops before starts. A poll that carries both is one where the
		// control plane wants something to end and something else to begin, and
		// doing them the other way round would hold the ending behind a free
		// slot the cancellation is about to release.
		for _, cn := range w.cancels {
			if running.cancel(cn.RunID, cn.Reason) {
				logger.Warn("run stopped by runjet", "run", cn.RunID, "reason", cn.Reason)
			}
		}

		for _, d := range w.dispatches {
			wg.Add(1)
			go func(d protocol.Dispatch) {
				defer wg.Done()
				// Waiting for room happens here and never in the loop above.
				// A poll loop blocked at the cap stops asking for work, and a
				// cancellation is the thing most likely to free the slot it is
				// waiting for — so blocking there means the agent can only be
				// unstuck by the very run it has been asked to stop. It waits
				// out of the way instead, and the loop keeps polling.
				if !room.acquire(ctx) {
					return
				}
				defer room.release()
				execute(ctx, c, d, secrets, jobs, running, logger)
			}(d)
		}
	}
}

// execute runs one verified dispatch and reports it.
//
// Reporting uses a context detached from the poll loop's, so a shutdown
// arriving mid-run still records the outcome instead of leaving the run to be
// swept up as orphaned.
func execute(ctx context.Context, c *client, d protocol.Dispatch, secrets *secretStore,
	jobs jobRuntime, running *inflight, logger *slog.Logger) {

	// The run gets a context of its own so the control plane can end this one
	// without ending the others, and cancelling it kills the process group the
	// same way the timeout does — runner.Run has never cared which of the two
	// arrived.
	ctx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	control, forget := running.add(d.RunID, stopRun)
	defer forget()

	timeout, err := time.ParseDuration(d.Timeout)
	if err != nil {
		timeout = 0
	}
	// A fresh deadline per report, never one shared across the run: the timeout
	// bounds a single HTTP request, and a context built before the command
	// starts is long expired by the time the verdict is sent — which loses
	// exactly the report the detached context exists to protect. Heartbeats and
	// output flushes already build their own for the same reason.
	report := func(body statusBody) error {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
		defer cancel()
		return c.reportStatus(rctx, d.RunID, body)
	}

	if err := report(statusBody{State: "running"}); err != nil {
		// The scheduler will not accept output or a verdict for a run it does
		// not think we hold, so there is nothing useful to do but stop.
		logger.Error("could not claim run, skipping", "run", d.RunID, "err", err)
		return
	}

	// Resolve after claiming, so a missing secret is reported as a failed run
	// rather than left for the sweeper to blame on a silent agent.
	env, err := secrets.resolve(d.Secrets)
	if err != nil {
		logger.Error("cannot run job, secret unavailable", "job", d.JobName, "run", d.RunID, "err", err)
		if err := report(statusBody{
			State: "finished", Success: false, Error: err.Error(),
		}); err != nil {
			logger.Error("could not report missing secret", "run", d.RunID, "err", err)
		}
		return
	}
	logger.Info("run started", "job", d.JobName, "run", d.RunID,
		"timeout", d.Timeout, "secrets", len(d.Secrets))

	streamCtx, stopStream := context.WithCancel(context.WithoutCancel(ctx))
	out := newOutputStreamer(c, d.RunID, func(err error) {
		logger.Warn("output upload failed", "run", d.RunID, "err", err)
	})
	// Masking sits on the way *into* the stream, so a value the agent injected
	// never reaches the scheduler at all — not in a chunk, not in transit, not
	// masked-but-recoverable. Built from this run's secrets only.
	masked := newRedactor(secretValues(env), out)
	var streaming sync.WaitGroup
	streaming.Add(1)
	go func() {
		defer streaming.Done()
		out.run(streamCtx)
	}()

	stopBeat := make(chan struct{})
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopBeat:
				return
			case <-ticker.C:
				beat, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
				if err := c.heartbeat(beat, d.RunID); err != nil {
					logger.Warn("heartbeat failed", "run", d.RunID, "err", err)
				}
				cancel()
			}
		}
	}()

	outcome := runner.Run(ctx, jobs.spec(d.Command, timeout, env), masked)
	// Read before phrasing: a cancelled context cannot say who cancelled it, and
	// "Runjet stopped this because it was over the plan's limit" and "the agent
	// was shutting down" mean opposite things to whoever opens the run.
	stopped := control.stoppedBecause()

	close(stopBeat)
	// Before stopStream, not after: the redactor may be holding the tail of the
	// last line, and the streamer's final flush is what ships it.
	if err := masked.Close(); err != nil {
		logger.Warn("could not flush the end of the output", "run", d.RunID, "err", err)
	}
	stopStream()
	streaming.Wait() // let the tail of the output land before the verdict

	status := statusBody{State: "finished", Success: outcome.OK(), ExitCode: outcome.ExitCode}
	if !outcome.OK() {
		status.Error = masked.Redact(describe(outcome, timeout, stopped))
	}
	if err := report(status); err != nil {
		logger.Error("could not report outcome", "run", d.RunID, "err", err)
		return
	}
	if outcome.OK() {
		logger.Info("run finished", "job", d.JobName, "run", d.RunID, "status", "success")
		return
	}
	logger.Warn("run finished", "job", d.JobName, "run", d.RunID,
		"status", "failed", "reason", string(outcome.Reason), "stopped", stopped,
		"err", outcome.Err)
}

// describe phrases a failed outcome for the run record. A bare "signal: killed"
// says nothing about why the process died.
// stopped is why the control plane asked for this run to end, empty when it did
// not ask. It takes precedence over the agent's own reading: a cancelled context
// looks identical whoever cancelled it, and the run record has to say which.
func describe(o runner.Outcome, timeout time.Duration, stopped string) string {
	if stopped != "" && (o.Reason == runner.ReasonCancelled || o.Reason == runner.ReasonStalled) {
		return stopped
	}
	switch o.Reason {
	case runner.ReasonTimeout:
		return fmt.Sprintf("timed out after %s, process group killed", timeout)
	case runner.ReasonCancelled:
		return "killed by agent shutdown"
	case runner.ReasonStalled:
		return fmt.Sprintf("command exited but left a background process holding its output; gave up after %s",
			runner.WaitDelay)
	default:
		return o.Err.Error()
	}
}
