package main

import (
	"bytes"
	"strings"
	"testing"
)

// Most of these are about the streaming boundary. Masking a whole string is
// easy and would pass a naive test; output arrives in chunks, and a value split
// across two of them is the case a hand-rolled redactor gets wrong.

func writeAll(t *testing.T, r *redactor, parts ...string) {
	t.Helper()
	for _, part := range parts {
		n, err := r.Write([]byte(part))
		if err != nil {
			t.Fatalf("Write(%q): %v", part, err)
		}
		// os/exec treats a short write as a failure and tears the command
		// down, so held-back bytes must still be reported as consumed.
		if n != len(part) {
			t.Fatalf("Write(%q) = %d, want %d", part, n, len(part))
		}
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// The one that matters. Neither half contains the value, so masking each chunk
// on its own would ship both and leak it in two pieces.
func TestRedactorMasksAValueSplitAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"s3cr3t-value"}, &out)

	writeAll(t, r, "before s3cr", "3t-value after\n")

	if got := out.String(); got != "before *** after\n" {
		t.Errorf("output = %q, want the value masked across the split", got)
	}
}

// The pathological version of the same thing: a value arriving one byte at a
// time never appears whole in any single write.
func TestRedactorMasksAValueArrivingByteByByte(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"s3cr3t-value"}, &out)

	parts := strings.Split("x s3cr3t-value y", "")
	writeAll(t, r, parts...)

	if got := out.String(); got != "x *** y" {
		t.Errorf("output = %q, want the value masked", got)
	}
}

// Holding bytes back must not delay a live log. Ordinary text shares no prefix
// with a secret, so it ships on the write that produced it.
func TestRedactorDoesNotDelayOrdinaryOutput(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"s3cr3t-value"}, &out)

	if _, err := r.Write([]byte("step one done\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if got := out.String(); got != "step one done\n" {
		t.Errorf("after one write out holds %q, want the line already shipped", got)
	}
}

// A value the run did not receive passes through untouched. Masking everything
// the agent holds would let a job print candidates and watch which come back
// starred, confirming a value it was never given.
func TestRedactorLeavesValuesThisRunDidNotGet(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"mine-is-secret"}, &out)

	writeAll(t, r, "mine-is-secret and someone-elses-secret\n")

	got := out.String()
	if strings.Contains(got, "mine-is-secret") {
		t.Errorf("this run's own value survived: %q", got)
	}
	if !strings.Contains(got, "someone-elses-secret") {
		t.Errorf("a value this run never received was masked, which is an oracle: %q", got)
	}
}

// A short value would star out ordinary text — "prod" appears in paths, hosts
// and log lines — and an operator who cannot read their output stops trusting
// the masking rather than the value.
func TestRedactorLeavesValuesTooShortToMask(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"prod", "long-enough-value"}, &out)

	writeAll(t, r, "deploying to prod with long-enough-value\n")

	if got := out.String(); got != "deploying to prod with ***\n" {
		t.Errorf("output = %q, want only the long value masked", got)
	}
}

// One value containing another must be masked whole. Shortest-first would leave
// a recognisable remainder behind the mask.
func TestRedactorMasksTheLongestValueFirst(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"token-abc", "token-abc-extended"}, &out)

	writeAll(t, r, "value: token-abc-extended\n")

	if got := out.String(); got != "value: ***\n" {
		t.Errorf("output = %q, want the whole longer value masked", got)
	}
}

func TestRedactorFlushesTheTailOnClose(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"s3cr3t-value"}, &out)

	// Ends on a partial value, so the redactor is still holding it: a command
	// whose last line has no newline must not lose its tail.
	if _, err := r.Write([]byte("trailing s3cr")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := out.String(); got != "trailing s3cr" {
		t.Errorf("output = %q, want the held bytes released", got)
	}
}

func TestRedactorWithoutValuesPassesEverythingThrough(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(nil, &out)

	writeAll(t, r, "nothing to hide\n")

	if got := out.String(); got != "nothing to hide\n" {
		t.Errorf("output = %q, want it unchanged", got)
	}
}

// A run's error message goes up a different path from the output stream, and a
// command's failure text is exactly where a credential tends to surface.
func TestRedactMasksAStringOutsideTheStream(t *testing.T) {
	r := newRedactor([]string{"s3cr3t-value"}, &bytes.Buffer{})

	if got := r.Redact(`curl failed: token=s3cr3t-value rejected`); strings.Contains(got, "s3cr3t-value") {
		t.Errorf("Redact = %q, want the value masked", got)
	}
}

// Two names holding the same value is ordinary — a password reused by an app
// and its migration tool — and must not mask twice or reorder unpredictably.
func TestRedactorDeduplicatesValues(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor([]string{"same-value-here", "same-value-here"}, &out)

	if len(r.values) != 1 {
		t.Fatalf("values = %v, want one entry", r.values)
	}
	writeAll(t, r, "a same-value-here b\n")
	if got := out.String(); got != "a *** b\n" {
		t.Errorf("output = %q", got)
	}
}

func TestSecretValuesTakesOnlyTheValues(t *testing.T) {
	// Values may contain '=' themselves, so only the first one separates.
	got := secretValues([]string{"TOKEN=abc123", "DSN=user=me;pass=x"})

	if len(got) != 2 || got[0] != "abc123" || got[1] != "user=me;pass=x" {
		t.Errorf("secretValues = %q, want the values after the first '='", got)
	}
}
