// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMetricsShutdownClosesPartialRequest checks cleanup after the shutdown
// timeout.
func TestMetricsShutdownClosesPartialRequest(t *testing.T) {
	edPath, _ := withSeedFile(t)
	withFlagGlobals(t, edPath, "", "error", 2002, 0)
	done, cancel, address := startServeForTest(t)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /metrics HTTP/1.1\r\nHost: ")); err != nil {
		t.Fatal(err)
	}
	// A complete request confirms that the listener has accepted connections.
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	client.CloseIdleConnections()
	cancel()
	if err := awaitTest(t, done, 4*time.Second, "metrics shutdown"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if n, err := conn.Read(buf[:]); err == nil || n != 0 {
		t.Fatalf("partial request remained open: n=%d error=%v", n, err)
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("shutdown left the partial request open")
	}
}

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
