// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// TestResponseInSync covers closed boundaries, asymmetric delay uncertainty,
// and invalid timing metadata.
func TestResponseInSync(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name string
		r    *roughtime.Response
		want bool
	}{
		{"nil", nil, false},
		{"left boundary", &roughtime.Response{LocalNow: base, RTT: 2 * time.Second, Midpoint: base.Add(time.Second), Radius: time.Second}, true},
		{"right boundary", &roughtime.Response{LocalNow: base, RTT: 2 * time.Second, Midpoint: base.Add(-3 * time.Second), Radius: time.Second}, true},
		{"one nanosecond gap", &roughtime.Response{LocalNow: base, RTT: 2 * time.Second, Midpoint: base.Add(time.Second + time.Nanosecond), Radius: time.Second}, false},
		// The RTT-center estimate is two seconds outside a one-second radius,
		// but the possible local exchange interval overlaps the server window.
		{"asymmetric delay", &roughtime.Response{LocalNow: base, RTT: 4 * time.Second, Midpoint: base.Add(-4 * time.Second), Radius: time.Second}, true},
		{"negative radius", &roughtime.Response{LocalNow: base, Radius: -1}, false},
		{"negative RTT", &roughtime.Response{LocalNow: base, RTT: -1}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseInSync(tc.r); got != tc.want {
				t.Fatalf("responseInSync = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPrintTableSuppressesSummaryOnCausalFailure ensures invalid causal data
// cannot precede or accompany a corrected-time recommendation.
func TestPrintTableSuppressesSummaryOnCausalFailure(t *testing.T) {
	result := successfulResult()
	var printErr error
	out := captureStdout(t, func() {
		printErr = printTable([]roughtime.Result{result}, &roughtime.Proof{}, 0)
	})
	if printErr == nil || !strings.Contains(printErr.Error(), "chain verify") {
		t.Fatalf("printTable error = %v", printErr)
	}
	if !strings.Contains(out, "Chain:              FAILED") {
		t.Fatalf("output lacks causal failure: %q", out)
	}
	if strings.Contains(out, "Consensus drift") || strings.Contains(out, "Corrected local") {
		t.Fatalf("causal failure emitted corrected-time summary: %q", out)
	}
}

// TestPrintTableStrictCompleteness checks per-probe accounting while locking
// down the legacy partial-result availability policy.
func TestPrintTableStrictCompleteness(t *testing.T) {
	success := successfulResult()
	failure := roughtime.Result{
		Server: success.Server,
		Err:    errors.New("timeout"),
	}
	var strictErr error
	strictOut := captureStdout(t, func() {
		strictErr = printTable([]roughtime.Result{failure, success}, nil, 2)
	})
	if strictErr == nil || !strings.Contains(strictErr.Error(), "incomplete two-pass") {
		t.Fatalf("strict incomplete error = %v", strictErr)
	}
	if !strings.Contains(strictOut, "1/2 probes responded") || !strings.Contains(strictOut, "Measurement:        FAILED") {
		t.Fatalf("strict output = %q", strictOut)
	}
	if strings.Contains(strictOut, "Consensus drift") {
		t.Fatalf("incomplete measurement emitted summary: %q", strictOut)
	}

	var legacyErr error
	legacyOut := captureStdout(t, func() {
		legacyErr = printTable([]roughtime.Result{failure, success}, nil, 0)
	})
	if legacyErr != nil {
		t.Fatalf("legacy partial error = %v", legacyErr)
	}
	if !strings.Contains(legacyOut, "Consensus drift") {
		t.Fatalf("legacy partial output lost summary: %q", legacyOut)
	}
}

// TestResultAddressFailureIsExplicit ensures a configured endpoint is not
// misreported as the endpoint that failed.
func TestResultAddressFailureIsExplicit(t *testing.T) {
	result := roughtime.Result{Server: roughtime.Server{Addresses: []roughtime.Address{{Transport: "udp", Address: "first.example:2002"}}}}
	got := resultAddress(result)
	if !strings.Contains(got, "unknown") || !strings.Contains(got, "configured") {
		t.Fatalf("resultAddress(failure) = %q", got)
	}
}

// TestDurationSpreadSaturates covers a mathematically positive spread too large
// for time.Duration.
func TestDurationSpreadSaturates(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	if got := durationSpread(-time.Millisecond, maxDuration); got != maxDuration {
		t.Fatalf("durationSpread overflow = %v", got)
	}
	if got := durationSpread(-time.Second, time.Second); got != 2*time.Second {
		t.Fatalf("durationSpread ordinary = %v", got)
	}
}

// successfulResult returns a fixed response for output tests.
func successfulResult() roughtime.Result {
	server := roughtime.Server{
		Name:      "success",
		PublicKey: []byte("root"),
		Addresses: []roughtime.Address{{Transport: "udp", Address: "success.example:2002"}},
	}
	address := server.Addresses[0]
	response := &roughtime.Response{
		Server:   server,
		Address:  address,
		Midpoint: time.Unix(1_700_000_000, 0),
		Radius:   time.Second,
		RTT:      20 * time.Millisecond,
		LocalNow: time.Unix(1_700_000_000, 0),
	}
	return roughtime.Result{Server: server, Address: address, Response: response}
}

// captureStdout returns the text printed by fn.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- string(data)
	}()
	defer func() { os.Stdout = original }()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	out := <-done
	_ = reader.Close()
	return out
}

// TestCausalEvidenceSaved checks that saved evidence retains an authenticated
// contradiction.
func TestCausalEvidenceSaved(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	rootPK, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	cert, err := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Wipe()
	chain := &protocol.Chain{}
	for _, mid := range []time.Time{now, now.Add(-time.Minute)} {
		link, err := chain.NextRequest([]protocol.Version{protocol.Version1}, rootPK, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		req, err := protocol.ParseRequest(link.Request)
		if err != nil {
			t.Fatal(err)
		}
		replies, err := protocol.CreateReplies(protocol.Version1, []protocol.Request{*req}, mid, time.Second, cert)
		if err != nil {
			t.Fatal(err)
		}
		link.Response = replies[0]
		chain.Append(link)
	}
	report, err := chain.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := roughtime.ParseProof(report)
	if err != nil {
		t.Fatal(err)
	}
	output := captureStdout(t, func() {
		if err := printChainStatus(proof); !errors.Is(err, protocol.ErrCausalOrder) {
			t.Fatalf("missing causal error: %v", err)
		}
	})
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("evidence files: %v %v", files, err)
	}
	if !strings.Contains(output, files[0].Name()) {
		t.Fatal("saved evidence path not printed")
	}
	saved, err := os.ReadFile(filepath.Join(dir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := roughtime.ParseProof(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(); !errors.Is(err, protocol.ErrCausalOrder) {
		t.Fatalf("saved evidence did not preserve authenticated contradiction: %v", err)
	}
	output = captureStdout(t, func() { _ = printChainStatus(&roughtime.Proof{}) })
	files, err = os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("malformed input created evidence")
	}
	if strings.Contains(output, "Evidence saved") {
		t.Fatal("reported evidence for malformed proof")
	}
}
