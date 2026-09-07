// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMetricsRegistry covers counters and build/certificate metadata.
func TestMetricsRegistry(t *testing.T) {
	requestsReceived.reset()
	requestsResponded.reset()
	requestsDropped.reset()
	incReceived(transportUDP, schemeEd25519)
	incResponded(transportTCP, schemeMLDSA44, 2)
	incDropped(transportTCP, dropFraming)
	now := time.Unix(1_700_000_000, 0)
	noteCertProvisioned(schemeEd25519, []byte{1}, []byte{2}, now.Add(time.Hour), now)
	noteCertRotation(schemeEd25519)

	var out bytes.Buffer
	writeRegistry(&out)
	for _, want := range []string{
		`roughtime_requests_received_total{transport="udp",scheme="ed25519"} 1`,
		`roughtime_requests_responded_total{transport="tcp",scheme="mldsa44"} 2`,
		`roughtime_requests_dropped_total{transport="tcp",reason="framing"} 1`,
		`roughtime_cert_info{scheme="ed25519",online_pubkey="01",root_pubkey="02"} 1`,
		"roughtime_build_info",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("registry missing %q", want)
		}
	}
}

// TestMetricsHandlers covers endpoint methods, statuses, and bodies.
func TestMetricsHandlers(t *testing.T) {
	tests := []struct {
		name, method, path string
		handler            http.HandlerFunc
		status             int
		body               string
	}{
		{"metrics", http.MethodGet, "/metrics", handleMetrics, http.StatusOK, "roughtime_build_info"},
		{"health", http.MethodGet, "/healthz", handleHealthz, http.StatusOK, "ok\n"},
		{"method", http.MethodPost, "/metrics", handleMetrics, http.StatusMethodNotAllowed, "method not allowed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.handler(recorder, httptest.NewRequest(test.method, test.path, nil))
			if recorder.Code != test.status || !strings.Contains(recorder.Body.String(), test.body) {
				t.Fatalf("status/body = %d, %q", recorder.Code, recorder.Body.String())
			}
		})
	}
}
