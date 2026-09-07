// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

func TestDebugRetryState(t *testing.T) {
	var waits []time.Duration
	state := &debugRetryState{wait: func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		return nil
	}}
	if err := state.beforeAttempt(context.Background()); err != nil {
		t.Fatal(err)
	}
	state.failed()
	if err := state.beforeAttempt(context.Background()); err != nil {
		t.Fatal(err)
	}
	state.failed()
	if err := state.beforeAttempt(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []time.Duration{time.Second, 1500 * time.Millisecond}; !slices.Equal(waits, want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}

	for state.delay < debugBackoffMax {
		state.failed()
	}
	state.failed()
	if state.delay != debugBackoffMax {
		t.Fatalf("capped delay = %s, want %s", state.delay, debugBackoffMax)
	}
	state.verified()
	if state.delay != 0 {
		t.Fatalf("verified delay = %s, want zero", state.delay)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	state = &debugRetryState{delay: time.Hour, wait: waitForDebugRetry}
	if err := state.beforeAttempt(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait error = %v, want context.Canceled", err)
	}
}

// TestDefaultScanBudget covers every form and padding fallback without wall-
// clock sleeps. A nonresponsive peer is the longest default failure schedule.
func TestDefaultScanBudget(t *testing.T) {
	restoreProbeGlobals(t)
	*retries = 3
	*timeout = 500 * time.Millisecond
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			var elapsed time.Duration
			var waits []time.Duration
			attempts := 0
			probeRoundTrip = func(_ context.Context, _ []byte, timeout time.Duration, _ string) ([]byte, time.Duration, time.Time, error) {
				attempts++
				elapsed += timeout
				return nil, 0, time.Time{}, errors.New("peer did not respond")
			}
			state := &debugRetryState{wait: func(_ context.Context, delay time.Duration) error {
				waits = append(waits, delay)
				elapsed += delay
				return nil
			}}
			for _, plan := range defaultProbePlans(roughtime.SchemeEd25519) {
				if transport == "tcp" && plan.version == protocol.VersionGoogle {
					continue
				}
				if result := probe(context.Background(), make([]byte, ed25519.PublicKeySize), plan, transport, state); result.err == nil {
					t.Fatal("nonresponsive peer marked supported")
				}
			}
			wantAttempts := 78
			if transport == "tcp" {
				wantAttempts = 39
			}
			if attempts != wantAttempts || len(waits) != attempts-1 {
				t.Fatalf("attempts=%d waits=%d, want %d attempts and a shared wait before every retry", attempts, len(waits), wantAttempts)
			}
			for i, delay := range waits {
				want := debugBackoffMax
				if i < 3 {
					want = []time.Duration{time.Second, 1500 * time.Millisecond, 2250 * time.Millisecond}[i]
				}
				if delay != want {
					t.Fatalf("wait %d = %s, want %s", i, delay, want)
				}
			}
			if elapsed >= defaultScanTimeout {
				t.Fatalf("default sweep needs %s, exceeding scan timeout %s", elapsed, defaultScanTimeout)
			}
		})
	}
}

func TestProbeFallsBackToStandardSizedUDP(t *testing.T) {
	restoreProbeGlobals(t)
	*retries = 1
	*timeout = time.Second

	rootSK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	onlineSK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	rootPK := rootSK.Public().(ed25519.PublicKey)
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	cert, err := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}

	var sizes []int
	probeRoundTrip = func(_ context.Context, request []byte, _ time.Duration, transport string) ([]byte, time.Duration, time.Time, error) {
		if transport != "udp" {
			t.Fatalf("transport = %q, want udp", transport)
		}
		sizes = append(sizes, len(request))
		if len(request) == 1024 {
			return nil, 0, time.Time{}, errors.New("strict peer ignored legacy-sized request")
		}
		parsed, err := protocol.ParseRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		if want := []protocol.Version{protocol.VersionDraft11}; !slices.Equal(parsed.Versions, want) {
			t.Fatalf("versions = %v, want %v", parsed.Versions, want)
		}
		if want := protocol.ComputeSRV(rootPK); !bytes.Equal(parsed.SRV, want) {
			t.Fatalf("SRV = %x, want %x", parsed.SRV, want)
		}
		replies, err := protocol.CreateReplies(protocol.VersionDraft11, []protocol.Request{*parsed}, now, time.Second, cert)
		if err != nil {
			t.Fatal(err)
		}
		return replies[0], 20 * time.Millisecond, now, nil
	}

	var waits []time.Duration
	state := &debugRetryState{wait: func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		return nil
	}}
	plan := probePlan{version: protocol.VersionDraft11, label: "draft-11", short: "draft-11"}
	result := probe(context.Background(), rootPK, plan, "udp", state)
	if result.err != nil {
		t.Fatalf("probe failed: %v", resultError(result))
	}
	if want := []int{1024, 1036}; !slices.Equal(sizes, want) {
		t.Fatalf("request sizes = %v, want %v", sizes, want)
	}
	if want := []time.Duration{time.Second}; !slices.Equal(waits, want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	if len(result.request) != 1036 {
		t.Fatalf("verified request size = %d, want 1036", len(result.request))
	}
	if state.delay != 0 {
		t.Fatalf("verified probe did not reset retry state: %+v", state)
	}
}

func TestProbeSharesBackoffAcrossForms(t *testing.T) {
	restoreProbeGlobals(t)
	*retries = 1
	*timeout = time.Second
	probeRoundTrip = func(context.Context, []byte, time.Duration, string) ([]byte, time.Duration, time.Time, error) {
		return nil, 0, time.Time{}, errors.New("unavailable")
	}

	var waits []time.Duration
	state := &debugRetryState{wait: func(_ context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		return nil
	}}
	rootPK := make([]byte, ed25519.PublicKeySize)
	first := probePlan{version: protocol.VersionDraft12, label: "draft-14+", short: "draft-14+"}
	second := probePlan{version: protocol.VersionGoogle, label: "Google", short: "Google"}
	if result := probe(context.Background(), rootPK, first, "udp", state); result.err == nil {
		t.Fatal("first form unexpectedly succeeded")
	}
	if result := probe(context.Background(), rootPK, second, "udp", state); result.err == nil {
		t.Fatal("second form unexpectedly succeeded")
	}
	if want := []time.Duration{time.Second}; !slices.Equal(waits, want) {
		t.Fatalf("cross-form waits = %v, want %v", waits, want)
	}
}

func TestProbeRetainsInvalidReplyAcrossLaterTimeout(t *testing.T) {
	restoreProbeGlobals(t)
	*retries = 2
	*timeout = time.Second

	reply := bytes.Repeat([]byte{0xa5}, 1200)
	receivedAt := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	calls := 0
	probeRoundTrip = func(_ context.Context, _ []byte, _ time.Duration, _ string) ([]byte, time.Duration, time.Time, error) {
		calls++
		if calls == 1 {
			return reply, 25 * time.Millisecond, receivedAt, nil
		}
		return nil, 0, time.Time{}, errors.New("later timeout")
	}
	state := &debugRetryState{wait: func(context.Context, time.Duration) error { return nil }}
	plan := probePlan{version: protocol.VersionDraft12, label: "draft-14+", short: "draft-14+"}
	result := probe(context.Background(), make([]byte, ed25519.PublicKeySize), plan, "udp", state)

	if result.err == nil || !strings.Contains(result.err.Error(), "verify:") {
		t.Fatalf("retained error = %v, want verification error", result.err)
	}
	if result.transportErr == nil || !strings.Contains(result.transportErr.Error(), "later timeout") {
		t.Fatalf("later transport error = %v, want timeout", result.transportErr)
	}
	if !bytes.Equal(result.reply, reply) || result.rtt != 25*time.Millisecond || !result.localNow.Equal(receivedAt) {
		t.Fatalf("retained evidence changed: reply=%d bytes rtt=%s local=%s", len(result.reply), result.rtt, result.localNow)
	}

	result.err = errors.New("bad\x1b\nverification")
	output := captureStdout(t, func() { printDiagnostic(result) })
	ampAt := strings.Index(output, "Amplification:   VIOLATED")
	verificationAt := strings.Index(output, "Verification:    failed:")
	if ampAt < 0 || verificationAt < 0 || ampAt > verificationAt {
		t.Fatalf("amplification diagnostic must precede verification failure:\n%s", output)
	}
	if strings.Contains(output, "\x1b") || strings.Contains(output, "bad\nverification") {
		t.Fatalf("verification error was not sanitized:\n%q", output)
	}
	if !strings.Contains(output, "Later transport: failed: later timeout") {
		t.Fatalf("later transport evidence missing:\n%s", output)
	}
}

func restoreProbeGlobals(t *testing.T) {
	t.Helper()
	oldRetries, oldTimeout, oldRoundTrip := *retries, *timeout, probeRoundTrip
	t.Cleanup(func() {
		*retries = oldRetries
		*timeout = oldTimeout
		probeRoundTrip = oldRoundTrip
	})
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = writer
	fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = oldStdout
	out, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
