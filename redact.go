package main

import (
	"io"
	"slices"
	"strings"
)

// Secret values are masked here, on the agent, before any output leaves the
// host — never in the control plane, which would have to hold the values to do
// it and is the one thing the whole secrets design refuses.
//
// This is a net for accidents, not a boundary. `set -x` in a shell script,
// `curl -v` printing an Authorization header, a stack trace carrying a DSN: the
// cases where a value ends up in a log because nobody meant it to. A job that
// wants its secret out can still `echo $SECRET | base64`, and no amount of
// matching literals will stop it. What stops that is the job not being able to
// reach anything it was not given.

// mask replaces a secret wherever it appears.
const mask = "***"

// minMaskedLength is the shortest value worth masking.
//
// A secret whose value is "prod" or "8080" would star out half a log, and an
// operator who cannot read their own output learns to distrust the feature
// rather than the value. The agent names what it skipped instead.
const minMaskedLength = 5

// redactor masks known values in a stream on its way out.
//
// Write and Close are not safe to call concurrently, and do not need to be:
// os/exec funnels a command's stdout and stderr through a single goroutine when
// both are the same writer, and Close happens after runner.Run has returned.
type redactor struct {
	out    io.Writer
	values []string // longest first, deduplicated, none shorter than minMaskedLength
	maxLen int
	tail   []byte
}

// newRedactor masks values in whatever is written to it before passing it on.
//
// Callers pass the values resolved for one run, never everything the agent
// holds. The wider version reads as more protective and hands a job an oracle:
// print candidate strings, see which come back masked, and confirm a value that
// was never granted. Scoped to the run, a job can only probe what it already
// has.
func newRedactor(values []string, out io.Writer) *redactor {
	r := &redactor{out: out}
	for _, v := range values {
		if len(v) < minMaskedLength || slices.Contains(r.values, v) {
			continue
		}
		r.values = append(r.values, v)
		r.maxLen = max(r.maxLen, len(v))
	}
	// Longest first, so a value that contains another is masked whole rather
	// than left as a recognisable "***def".
	slices.SortFunc(r.values, func(a, b string) int { return len(b) - len(a) })
	return r
}

func (r *redactor) Write(p []byte) (int, error) {
	if len(r.values) == 0 {
		return r.out.Write(p)
	}

	buf := make([]byte, 0, len(r.tail)+len(p))
	buf = append(buf, r.tail...)
	buf = append(buf, p...)

	keep := r.partialSuffix(buf)
	if n := len(buf) - keep; n > 0 {
		if _, err := r.out.Write([]byte(r.Redact(string(buf[:n])))); err != nil {
			return 0, err
		}
	}
	r.tail = buf[len(buf)-keep:]

	// The caller's write is fully consumed even when part of it is held: those
	// bytes are in hand, not lost. Reporting a short count would look like a
	// failed write to os/exec and tear down the command for no reason.
	return len(p), nil
}

// Close emits whatever was held back. It must run before the output stream is
// closed, or the tail of a command's last line never ships.
func (r *redactor) Close() error {
	if len(r.tail) == 0 {
		return nil
	}
	tail := r.tail
	r.tail = nil
	_, err := r.out.Write([]byte(r.Redact(string(tail))))
	return err
}

// Redact masks values in a complete string. It is for text that does not travel
// through the stream — a run's error message, say — where there is no boundary
// to worry about.
func (r *redactor) Redact(s string) string {
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, mask)
	}
	return s
}

// partialSuffix reports how many bytes at the end of buf could be the beginning
// of a value that has not finished arriving.
//
// Output is streamed in chunks, so a secret can land across two writes — "s3c"
// ending one and "r3t" starting the next. Masking each chunk on its own would
// miss it completely, which is the usual way a hand-rolled redactor leaks.
// Holding those bytes back until the rest arrives is what closes it.
//
// For ordinary log text the answer is zero, so nothing is delayed: only output
// that genuinely stops mid-value waits, and Close releases it regardless.
func (r *redactor) partialSuffix(buf []byte) int {
	longest := min(r.maxLen-1, len(buf))
	for n := longest; n > 0; n-- {
		suffix := string(buf[len(buf)-n:])
		for _, v := range r.values {
			if len(v) > n && strings.HasPrefix(v, suffix) {
				return n
			}
		}
	}
	return 0
}

// secretValues pulls the values out of resolved KEY=value entries, which is
// what a run's redactor is built from.
func secretValues(env []string) []string {
	values := make([]string, 0, len(env))
	for _, entry := range env {
		if _, value, ok := strings.Cut(entry, "="); ok {
			values = append(values, value)
		}
	}
	return values
}
