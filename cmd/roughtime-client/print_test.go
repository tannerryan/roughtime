// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
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
