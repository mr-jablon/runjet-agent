package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// flushSize and flushInterval bound how far output can lag behind the
	// command. The old in-process writer wrote per Write call, which over a
	// network would be one request per line — batching is what makes a live
	// log tail affordable when the writer is on another machine.
	flushSize     = 8 << 10
	flushInterval = 500 * time.Millisecond

	// heartbeatInterval must sit comfortably inside the scheduler's lease so a
	// single lost beat does not orphan a healthy run.
	heartbeatInterval = 30 * time.Second

	// uploadTimeout bounds one chunk. The http.Client holds no timeout of its
	// own — it could not, with a long poll whose length the control plane
	// moves — so each upload carries this one, or a command writing into a
	// scheduler that has stopped answering would hold the flush forever.
	uploadTimeout = 30 * time.Second
)

// reportTimeout bounds one status request, not a run. A var so tests can shrink
// it; nothing else assigns to it.
var reportTimeout = 30 * time.Second

// reportStatus tells the scheduler a run has started or finished.
func (c *client) reportStatus(ctx context.Context, runID string, body statusBody) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := c.signedRequest(ctx, http.MethodPost, "/agent/runs/"+runID+"/status", raw)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

type statusBody struct {
	State   string `json:"state"`
	Success bool   `json:"success"`
	Error   string `json:"error"`
	// ExitCode is what the command ended with, omitted when it did not end with
	// one — killed by the timeout, cancelled at shutdown, or never started.
	//
	// A pointer and `omitempty` together, because zero is a real exit code and
	// the most common one: a value type would send 0 for a run that was killed,
	// which is precisely the confusion this field exists to remove. Omitting it
	// is also what makes the change additive — a server that does not read it
	// is unaffected, and this agent talking to one is too.
	ExitCode *int `json:"exitCode,omitempty"`
}

// heartbeat renews a run's lease.
func (c *client) heartbeat(ctx context.Context, runID string) error {
	req, err := c.signedRequest(ctx, http.MethodPost, "/agent/runs/"+runID+"/heartbeat", []byte("{}"))
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

// sendChunk uploads one sequenced chunk, returning the sequence number to
// resend from when the scheduler says we are ahead of it.
func (c *client) sendChunk(ctx context.Context, runID string, seq int, data string) (int, error) {
	raw, err := json.Marshal(map[string]any{"seq": seq, "data": data})
	if err != nil {
		return 0, err
	}
	req, err := c.signedRequest(ctx, http.MethodPost, "/agent/runs/"+runID+"/output", raw)
	if err != nil {
		return 0, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusConflict {
		var conflict struct {
			ExpectedSeq int `json:"expectedSeq"`
		}
		if err := json.NewDecoder(res.Body).Decode(&conflict); err != nil {
			return 0, fmt.Errorf("decode sequence conflict: %w", err)
		}
		return conflict.ExpectedSeq, errSequenceGap
	}
	if res.StatusCode >= 300 {
		return 0, fmt.Errorf("POST output: %s", res.Status)
	}
	return seq + 1, nil
}

// errSequenceGap signals that the scheduler is missing earlier output.
var errSequenceGap = fmt.Errorf("output sequence gap")

// outputStreamer buffers a command's output and ships it in sequenced chunks.
//
// It never blocks the command: a failed upload is logged and the chunk dropped
// rather than propagated back into the process's stdout, because losing part of
// a log is a much smaller problem than wedging the job that produces it.
type outputStreamer struct {
	client *client
	runID  string
	onErr  func(error)

	// send serialises uploads. seq is claimed for the length of a send and
	// reused when it fails, which is only safe while nothing else can claim it
	// meanwhile — see flush.
	send sync.Mutex

	mu      sync.Mutex
	pending strings.Builder
	seq     int
}

func newOutputStreamer(c *client, runID string, onErr func(error)) *outputStreamer {
	return &outputStreamer{client: c, runID: runID, onErr: onErr}
}

func (o *outputStreamer) Write(p []byte) (int, error) {
	o.mu.Lock()
	o.pending.Write(p)
	full := o.pending.Len() >= flushSize
	o.mu.Unlock()

	if full {
		o.flush(context.Background())
	}
	return len(p), nil
}

// flush ships whatever has accumulated. Sending happens outside o.mu so a slow
// network cannot stall the command writing into us.
//
// One upload at a time, though. Two flushes can be in the air at once — the
// buffer-full flush from Write, and the one on the timer — and the sequence
// number is only written back after the round trip, so both would send
// different chunks under the same number. The scheduler takes the first and
// rejects the second as a duplicate, and a piece of somebody's job log
// disappears without anything failing.
func (o *outputStreamer) flush(ctx context.Context) {
	o.send.Lock()
	defer o.send.Unlock()

	o.mu.Lock()
	if o.pending.Len() == 0 {
		o.mu.Unlock()
		return
	}
	data := o.pending.String()
	o.pending.Reset()
	seq := o.seq
	o.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()

	next, err := o.client.sendChunk(ctx, o.runID, seq, data)
	if err == errSequenceGap {
		// The scheduler is behind us; there is nothing useful to resend, since
		// the missing chunk is already gone. Realign and keep going rather than
		// wedging the stream.
		o.mu.Lock()
		o.seq = next
		o.mu.Unlock()
		o.onErr(fmt.Errorf("output sequence realigned to %d", next))
		return
	}
	if err != nil {
		o.onErr(err)
		return
	}
	o.mu.Lock()
	o.seq = next
	o.mu.Unlock()
}

// run flushes on a timer until ctx is cancelled, then one final time.
func (o *outputStreamer) run(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			o.flush(ctx)
		case <-ctx.Done():
			// The command is done; ship the tail with a fresh context, because
			// the one that was cancelled cannot carry a request.
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			o.flush(flushCtx)
			return
		}
	}
}
