// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// TestProofMarshalGzipPropagatesError verifies MarshalGzip surfaces errors from
// MalfeasanceReport.
func TestProofMarshalGzipPropagatesError(t *testing.T) {
	p := &Proof{chain: &protocol.Chain{}}
	if _, err := p.MarshalGzip(); err == nil {
		t.Fatal("MarshalGzip on empty chain should error")
	}
}

// TestNextBackoffMultiplyAndClamp verifies nextBackoff multiplies by
// retryBackoffFactor and clamps at retryBackoffMax.
func TestNextBackoffMultiplyAndClamp(t *testing.T) {
	if got, want := nextBackoff(time.Second), time.Duration(float64(time.Second)*retryBackoffFactor); got != want {
		t.Fatalf("nextBackoff(1s) = %s, want %s", got, want)
	}
	if got := nextBackoff(retryBackoffMax); got != retryBackoffMax {
		t.Fatalf("nextBackoff(max) = %s, want clamp to %s", got, retryBackoffMax)
	}
	if got := nextBackoff(retryBackoffMax * 2); got != retryBackoffMax {
		t.Fatalf("nextBackoff(2*max) = %s, want clamp to %s", got, retryBackoffMax)
	}
}

// TestBuildResponseAmplificationOK verifies buildResponse sets AmplificationOK
// correctly across UDP and TCP cases.
func TestBuildResponseAmplificationOK(t *testing.T) {
	cases := []struct {
		name      string
		transport string
		reqLen    int
		replyLen  int
		want      bool
	}{
		{"udp reply fits", "udp", 1024, 1024, true},
		{"udp reply oversized", "udp", 100, 200, false},
		{"udp case insensitive", "UDP", 100, 200, false},
		{"tcp always ok", "tcp", 100, 200, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := buildResponse(
				Server{},
				Address{Transport: c.transport},
				make([]byte, c.reqLen),
				make([]byte, c.replyLen),
				time.Time{}, 0, 0, time.Time{},
			)
			if r.AmplificationOK != c.want {
				t.Fatalf("AmplificationOK = %v, want %v", r.AmplificationOK, c.want)
			}
		})
	}
}
