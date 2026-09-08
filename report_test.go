package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-jablon/runjet-agent/runner"
)

// The streamer sits between a running command and the network, and its one hard
// rule is that it never blocks the command: losing part of a log is a much
// smaller problem than wedging the job that produces it. The tests cover that,
// plus the sequencing the scheduler uses to reassemble output.

// chunkRecorder collects the output chunks an agent uploads.
type chunkRecorder struct {
	mu     sync.Mutex
	chunks []outputRequest
	// conflictUntil answers the next n uploads with a sequence conflict.
	conflictUntil int
	expectedSeq   int
	status        int // when non-zero, every upload fails with this status
}

type outputRequest struct {
	Seq  int    `json:"seq"`
	Data string `json:"data"`
}

func (c *chunkRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in outputRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status != 0 {
		http.Error(w, "nope", c.status)
		return
	}
	if c.conflictUntil > 0 {
		c.conflictUntil--
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]int{"expectedSeq": c.expectedSeq})
		return
	}
	c.chunks = append(c.chunks, in)
	w.WriteHeader(http.StatusNoContent)
}

func (c *chunkRecorder) recorded() []outputRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]outputRequest(nil), c.chunks...)
}

func streamerFor(t *testing.T, rec *chunkRecorder) (*outputStreamer, *[]error) {
	t.Helper()
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, rec)

	var (
		mu     sync.Mutex
		failed []error
	)
	s := newOutputStreamer(c, "run-1", func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failed = append(failed, err)
	})
	return s, &failed
}

func TestOutputStreamerBuffersUntilFlushed(t *testing.T) {
	// Writing per Write call would be one request per line of output. Batching is
	// what makes a live log tail affordable when the writer is on another machine.
	rec := &chunkRecorder{}
	s, _ := streamerFor(t, rec)

	if _, err := s.Write([]byte("a short line\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := rec.recorded(); len(got) != 0 {
		t.Fatalf("a small write was uploaded immediately: %+v", got)
	}

	s.flush(context.Background())

	got := rec.recorded()
	if len(got) != 1 || got[0].Data != "a short line\n" || got[0].Seq != 0 {
		t.Fatalf("chunks = %+v, want one chunk at seq 0", got)
	}
}

// A command producing a lot of output must not have it all held until the run
// ends, or a long job would show nothing for hours.
func TestOutputStreamerFlushesWhenTheBufferFills(t *testing.T) {
	rec := &chunkRecorder{}
	s, _ := streamerFor(t, rec)

	if _, err := s.Write([]byte(strings.Repeat("x", flushSize+1))); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := rec.recorded()
	if len(got) != 1 {
		t.Fatalf("chunks = %d, want the full buffer shipped without an explicit flush", len(got))
	}
	if len(got[0].Data) != flushSize+1 {
		t.Errorf("chunk is %d bytes, want %d", len(got[0].Data), flushSize+1)
	}
}

// Two flushes can overlap: one from Write when the buffer fills, one from the
// timer. The sequence number is written back only after the round trip, so
// without serialising the sends both would ship a different chunk under the
// same number — the scheduler keeps the first, refuses the second as a
// duplicate, and that piece of the job's log is gone with nothing having
// failed. Silent loss in somebody's run log is worth a lock.
func TestOutputStreamerNeverReusesASequenceNumberWhenFlushesOverlap(t *testing.T) {
	rec := &slowChunkRecorder{delay: 300 * time.Millisecond}
	ts := newTestRunjet(t)
	s := newOutputStreamer(enrolledClient(t, ts, rec), "run-1", func(error) {})

	// The first flush is inline in Write and stays in the air for the delay.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := s.Write([]byte(strings.Repeat("a", flushSize+1))); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()

	// More output arrives while it is still in flight, and a second flush goes
	// looking for it — which is what the timer in run does every 500ms.
	time.Sleep(50 * time.Millisecond)
	if _, err := s.Write([]byte("arrived mid-upload\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.flush(context.Background())
	}()
	wg.Wait()

	got := rec.recorded()
	seen := map[int]int{}
	for _, chunk := range got {
		seen[chunk.Seq]++
	}
	for seq, n := range seen {
		if n > 1 {
			t.Errorf("sequence %d was sent %d times: two flushes claimed it and one chunk is lost", seq, n)
		}
	}
	if len(got) != 2 {
		t.Fatalf("chunks = %+v, want both to arrive", got)
	}
	if got[0].Seq != 0 || got[1].Seq != 1 {
		t.Errorf("sequences = %d, %d; want 0 then 1", got[0].Seq, got[1].Seq)
	}
}

// slowChunkRecorder holds each upload open, which is what lets a second flush
// start while the first is still going.
type slowChunkRecorder struct {
	chunkRecorder
	delay time.Duration
}

func (c *slowChunkRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	time.Sleep(c.delay)
	c.chunkRecorder.ServeHTTP(w, r)
}

func TestOutputStreamerNumbersChunksInOrder(t *testing.T) {
	// The sequence is how the scheduler tells a resend from new output, so it
	// must advance by exactly one per accepted chunk.
	rec := &chunkRecorder{}
	s, _ := streamerFor(t, rec)

	for _, line := range []string{"one\n", "two\n", "three\n"} {
		if _, err := s.Write([]byte(line)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		s.flush(context.Background())
	}

	got := rec.recorded()
	if len(got) != 3 {
		t.Fatalf("chunks = %+v, want 3", got)
	}
	for i, chunk := range got {
		if chunk.Seq != i {
			t.Errorf("chunk %d has seq %d, want %d", i, chunk.Seq, i)
		}
	}
}

func TestOutputStreamerSkipsAnEmptyFlush(t *testing.T) {
	// A timer tick during a silent stretch of a job must not cost a request.
	rec := &chunkRecorder{}
	s, _ := streamerFor(t, rec)

	s.flush(context.Background())

	if got := rec.recorded(); len(got) != 0 {
		t.Fatalf("an empty flush sent %+v", got)
	}
}

// The scheduler is missing earlier output and there is nothing useful to resend,
// since the missing chunk is already gone. Realigning keeps the rest of the log
// flowing instead of wedging the stream on a chunk that no longer exists.
func TestOutputStreamerRealignsAfterASequenceGap(t *testing.T) {
	rec := &chunkRecorder{conflictUntil: 1, expectedSeq: 5}
	s, failures := streamerFor(t, rec)

	if _, err := s.Write([]byte("lost\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	s.flush(context.Background())

	if got := rec.recorded(); len(got) != 0 {
		t.Fatalf("the conflicting chunk was recorded: %+v", got)
	}
	if len(*failures) != 1 || !strings.Contains((*failures)[0].Error(), "realigned") {
		t.Errorf("failures = %v, want one realignment notice", *failures)
	}

	if _, err := s.Write([]byte("next\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	s.flush(context.Background())

	got := rec.recorded()
	if len(got) != 1 || got[0].Seq != 5 {
		t.Fatalf("chunks = %+v, want the next chunk at the scheduler's seq 5", got)
	}
}

// An upload that fails is reported and dropped. Propagating it back into the
// command's stdout would break the job over a logging problem.
func TestOutputStreamerReportsAFailedUploadWithoutBlocking(t *testing.T) {
	rec := &chunkRecorder{status: http.StatusInternalServerError}
	s, failures := streamerFor(t, rec)

	n, err := s.Write([]byte("output\n"))
	if err != nil || n != len("output\n") {
		t.Fatalf("Write = %d, %v — the command must never see an upload failure", n, err)
	}
	s.flush(context.Background())

	if len(*failures) != 1 {
		t.Fatalf("failures = %v, want the failure reported once", *failures)
	}
	// The sequence must not advance past a chunk the scheduler never took, or
	// the next upload would look like a gap.
	s.mu.Lock()
	seq := s.seq
	s.mu.Unlock()
	if seq != 0 {
		t.Errorf("seq = %d after a failed upload, want 0", seq)
	}
}

// run() ships the tail after the command is done. Its context is already
// cancelled by then, so the final flush has to use a fresh one or the last of
// the output would never land.
func TestOutputStreamerFlushesTheTailAfterCancellation(t *testing.T) {
	rec := &chunkRecorder{}
	s, _ := streamerFor(t, rec)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.run(ctx)
	}()

	if _, err := s.Write([]byte("the last line\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}

	got := rec.recorded()
	if len(got) != 1 || got[0].Data != "the last line\n" {
		t.Fatalf("chunks = %+v, want the tail shipped on shutdown", got)
	}
}

func TestReportStatusAndHeartbeatAreSigned(t *testing.T) {
	ts := newTestRunjet(t)
	var seen []recordedRequest
	var mu sync.Mutex
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ts.record(r)
		if err := ts.verifySignature(r, body); err != nil {
			t.Errorf("%s %s did not verify: %v", r.Method, r.URL.Path, err)
		}
		mu.Lock()
		seen = append(seen, recordedRequest{Method: r.Method, Path: r.URL.Path, Body: body})
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	ctx := context.Background()

	if err := c.reportStatus(ctx, "run-1", statusBody{State: "running"}); err != nil {
		t.Fatalf("reportStatus: %v", err)
	}
	if err := c.heartbeat(ctx, "run-1"); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("recorded %d requests, want 2", len(seen))
	}
	if seen[0].Path != "/agent/runs/run-1/status" {
		t.Errorf("status posted to %q", seen[0].Path)
	}
	if !strings.Contains(string(seen[0].Body), `"state":"running"`) {
		t.Errorf("status body = %s, want the reported state", seen[0].Body)
	}
	if seen[1].Path != "/agent/runs/run-1/heartbeat" {
		t.Errorf("heartbeat posted to %q", seen[1].Path)
	}
}

func TestReportStatusSurfacesARefusal(t *testing.T) {
	// A 409 means the scheduler no longer thinks this agent holds the run —
	// swallowing it would leave the agent streaming into a void.
	ts := newTestRunjet(t)
	c := enrolledClient(t, ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		http.Error(w, `{"error":"run is not in a state this agent can report on"}`, http.StatusConflict)
	}))

	err := c.reportStatus(context.Background(), "run-1", statusBody{State: "running"})
	if err == nil {
		t.Fatal("reportStatus treated a 409 as success")
	}
}

// A bare "signal: killed" says nothing about why the process died, and the run
// record is all an operator has to go on afterwards.
func TestDescribe(t *testing.T) {
	cases := []struct {
		name    string
		outcome runner.Outcome
		timeout time.Duration
		want    string
	}{
		{
			"timeout names the cap",
			runner.Outcome{Reason: runner.ReasonTimeout},
			90 * time.Second,
			"timed out after 1m30s",
		},
		{
			"cancellation blames the shutdown, not the job",
			runner.Outcome{Reason: runner.ReasonCancelled},
			0,
			"killed by agent shutdown",
		},
		{
			"a stalled run explains the background process",
			runner.Outcome{Reason: runner.ReasonStalled},
			0,
			"background process holding its output",
		},
		{
			"an ordinary failure passes the error through",
			runner.Outcome{Reason: runner.ReasonExit, Err: errors.New("exit status 3")},
			0,
			"exit status 3",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := describe(c.outcome, c.timeout, "")
			if !strings.Contains(got, c.want) {
				t.Errorf("describe = %q, want it to mention %q", got, c.want)
			}
		})
	}
}
