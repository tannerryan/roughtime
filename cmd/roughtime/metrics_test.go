// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestEscapeHelp verifies escapeHelp escapes backslash and newline per the
// Prometheus text exposition format.
func TestEscapeHelp(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain text", "plain text"},
		{`with \backslash`, `with \\backslash`},
		{"with\nnewline", `with\nnewline`},
		{`both \and` + "\n" + "more", `both \\and\nmore`},
	}
	for _, tc := range cases {
		if got := escapeHelp(tc.in); got != tc.want {
			t.Errorf("escapeHelp(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEscapeLabel verifies escapeLabel escapes backslash, double-quote, and
// newline per the Prometheus text exposition format.
func TestEscapeLabel(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{"a\nb", `a\nb`},
		{`a\b"c` + "\n" + "d", `a\\b\"c\nd`},
	}
	for _, tc := range cases {
		if got := escapeLabel(tc.in); got != tc.want {
			t.Errorf("escapeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestFormatValue verifies formatValue prefers integer rendering for whole
// numbers within int64's safe range and falls back to shortest-round-trip
// floats otherwise.
func TestFormatValue(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{1.5, "1.5"},
		{1e20, "1e+20"},
		{math.NaN(), "NaN"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
	}
	for _, tc := range cases {
		got := formatValue(tc.in)
		if math.IsNaN(tc.in) {
			if got != "NaN" {
				t.Errorf("formatValue(NaN) = %q, want NaN", got)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("formatValue(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCounterRegisterAndAdd verifies labeled counter pre-registration and
// per-series accounting.
func TestCounterRegisterAndAdd(t *testing.T) {
	c := newCounter("test_metric_total", "test help", "k1", "k2")
	a := c.register("v1", "v2")
	b := c.register("v3", "v4")
	a.Add(2)
	a.Add(1)
	b.Add(5)
	if got := c.total(); got != 8 {
		t.Errorf("total = %d, want 8", got)
	}
	c.reset()
	if got := c.total(); got != 0 {
		t.Errorf("total after reset = %d, want 0", got)
	}
}

// TestCounterRegisterPanicsOnLabelMismatch verifies register() panics when the
// label-value count does not match the declared label-name count.
func TestCounterRegisterPanicsOnLabelMismatch(t *testing.T) {
	c := newCounter("test_metric_total", "h", "k1", "k2")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on label-count mismatch")
		}
	}()
	_ = c.register("only_one")
}

// TestGaugeSetLoad verifies gaugeSeries.Set/Load round-trip arbitrary float64
// values, that an un-Set series reports !ok, and that gauge.writeTo skips
// un-Set series.
func TestGaugeSetLoad(t *testing.T) {
	g := newGauge("test_gauge", "h", "k")
	s := g.register("v")
	if _, ok := s.Load(); ok {
		t.Fatal("Load before Set returned ok=true")
	}
	var buf bytes.Buffer
	g.writeTo(&buf)
	if strings.Contains(buf.String(), "test_gauge{") {
		t.Errorf("gauge emitted a sample before Set:\n%s", buf.String())
	}

	values := []float64{0, 1, -1, 1.5, math.MaxFloat64, math.SmallestNonzeroFloat64, math.Inf(1), math.Inf(-1)}
	for _, v := range values {
		s.Set(v)
		got, ok := s.Load()
		if !ok {
			t.Errorf("Load after Set returned ok=false")
		}
		if got != v && !(math.IsNaN(v) && math.IsNaN(got)) {
			t.Errorf("gauge round-trip: set %v got %v", v, got)
		}
	}
}

// TestInfoGaugeMutableLabels verifies an infoGauge series exposes nothing
// before Set, and exposes the most recent label values after each Set.
func TestInfoGaugeMutableLabels(t *testing.T) {
	g := newInfoGauge("test_info", "h", "scheme", "key")
	s := g.register()

	var buf bytes.Buffer
	g.writeTo(&buf)
	if strings.Contains(buf.String(), "test_info{") {
		t.Errorf("info gauge emitted a sample before Set:\n%s", buf.String())
	}

	s.Set("ed25519", "abcd")
	buf.Reset()
	g.writeTo(&buf)
	// labels render in alphabetical key order
	want := `test_info{key="abcd",scheme="ed25519"} 1`
	if !strings.Contains(buf.String(), want) {
		t.Errorf("missing %q in:\n%s", want, buf.String())
	}

	s.Set("ed25519", "ef00")
	buf.Reset()
	g.writeTo(&buf)
	if strings.Contains(buf.String(), `key="abcd"`) {
		t.Errorf("stale label after second Set:\n%s", buf.String())
	}
	want2 := `test_info{key="ef00",scheme="ed25519"} 1`
	if !strings.Contains(buf.String(), want2) {
		t.Errorf("missing %q in:\n%s", want2, buf.String())
	}
}

// TestWriteSampleDeterministicLabelOrder verifies labels render in alphabetical
// key order regardless of declaration order.
func TestWriteSampleDeterministicLabelOrder(t *testing.T) {
	var buf bytes.Buffer
	writeSample(&buf, "m", []string{"zeta", "alpha", "mu"}, []string{"z", "a", "m"}, 1)
	got := buf.String()
	want := `m{alpha="a",mu="m",zeta="z"} 1` + "\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestCounterFnReadsExternalAtomic verifies counterFn samples its source at
// scrape time, not at registration time.
func TestCounterFnReadsExternalAtomic(t *testing.T) {
	var src atomic.Uint64
	c := newCounterFn("test_external_total", "h", func() uint64 { return src.Load() })

	src.Store(7)
	var buf bytes.Buffer
	c.writeTo(&buf)
	if !strings.Contains(buf.String(), "test_external_total 7") {
		t.Errorf("expected sample value 7 in:\n%s", buf.String())
	}

	src.Store(42)
	buf.Reset()
	c.writeTo(&buf)
	if !strings.Contains(buf.String(), "test_external_total 42") {
		t.Errorf("expected sample value 42 in:\n%s", buf.String())
	}
}

// TestIncReceivedRespondedDropped verifies the increment helpers route to the
// expected pre-registered series. Uses pre/post deltas so the test is
// independent of any real-traffic counters incremented by other tests.
func TestIncReceivedRespondedDropped(t *testing.T) {
	udpEdBefore := receivedSeries[transportUDP][schemeEd25519].Load()
	tcpPQBefore := receivedSeries[transportTCP][schemeMLDSA44].Load()
	tcpEdRespondedBefore := respondedSeries[transportTCP][schemeEd25519].Load()
	// dropUndersize is UDP-only and always registered; dropQueue is gated by
	// udpHasQueue and is nil on platforms with the inline UDP fast path.
	udpUndersizeBefore := droppedSeries[transportUDP][dropUndersize].Load()
	tcpFramingBefore := droppedSeries[transportTCP][dropFraming].Load()
	receivedTotalBefore := requestsReceived.total()
	udpUndersizeViaHelperBefore := droppedFor(transportUDP, dropUndersize)

	incReceived(transportUDP, schemeEd25519)
	incReceived(transportUDP, schemeEd25519)
	incReceived(transportTCP, schemeMLDSA44)

	if got := receivedSeries[transportUDP][schemeEd25519].Load() - udpEdBefore; got != 2 {
		t.Errorf("UDP/ed25519 received delta = %d, want 2", got)
	}
	if got := receivedSeries[transportTCP][schemeMLDSA44].Load() - tcpPQBefore; got != 1 {
		t.Errorf("TCP/mldsa44 received delta = %d, want 1", got)
	}
	// UDP is Ed25519-only; the mldsa44 series under transport=udp must not
	// exist, and incReceived for that combination must be a no-op.
	if _, ok := receivedSeries[transportUDP][schemeMLDSA44]; ok {
		t.Error("unexpected UDP+mldsa44 series registered")
	}
	incReceived(transportUDP, schemeMLDSA44) // no-op, must not panic

	incResponded(transportTCP, schemeEd25519, 3)
	if got := respondedSeries[transportTCP][schemeEd25519].Load() - tcpEdRespondedBefore; got != 3 {
		t.Errorf("TCP/ed25519 responded delta = %d, want 3", got)
	}

	incDropped(transportUDP, dropUndersize)
	incDropped(transportTCP, dropFraming)
	if got := droppedSeries[transportUDP][dropUndersize].Load() - udpUndersizeBefore; got != 1 {
		t.Errorf("UDP/undersize dropped delta = %d, want 1", got)
	}
	if got := droppedSeries[transportTCP][dropFraming].Load() - tcpFramingBefore; got != 1 {
		t.Errorf("TCP/framing dropped delta = %d, want 1", got)
	}

	if got := requestsReceived.total() - receivedTotalBefore; got != 3 {
		t.Errorf("requestsReceived total delta = %d, want 3", got)
	}
	if got := droppedFor(transportUDP, dropUndersize) - udpUndersizeViaHelperBefore; got != 1 {
		t.Errorf("droppedFor(udp, undersize) delta = %d, want 1", got)
	}
}

// TestNoteCertRotation verifies noteCertRotation increments only the named
// scheme's counter.
func TestNoteCertRotation(t *testing.T) {
	edBefore := certMetricsFor(schemeEd25519).rotations.Load()
	pqBefore := certMetricsFor(schemeMLDSA44).rotations.Load()
	noteCertRotation(schemeEd25519)
	noteCertRotation(schemeEd25519)
	noteCertRotation(schemeMLDSA44)
	if got := certMetricsFor(schemeEd25519).rotations.Load() - edBefore; got != 2 {
		t.Errorf("ed rotations delta = %d, want 2", got)
	}
	if got := certMetricsFor(schemeMLDSA44).rotations.Load() - pqBefore; got != 1 {
		t.Errorf("pq rotations delta = %d, want 1", got)
	}
}

// TestUDPDroppedReasonsRegistered verifies UDP drop reasons match what the
// listener can actually produce; unreachable series would be misleading.
func TestUDPDroppedReasonsRegistered(t *testing.T) {
	want := map[dropReason]bool{
		dropUndersize: true,
		dropParse:     true,
		dropVersion:   true,
		dropSRV:       true,
		dropBatchErr:  true,
		dropWrite:     true,
	}
	if udpHasQueue {
		want[dropQueue] = true
	}
	for reason := range droppedSeries[transportUDP] {
		if !want[reason] {
			t.Errorf("unexpected UDP drop reason registered: %q", reason)
		}
		delete(want, reason)
	}
	for reason := range want {
		t.Errorf("missing UDP drop reason: %q", reason)
	}
}

// TestTCPDroppedReasonsRegistered verifies TCP drop reasons match what the
// listener can actually produce.
func TestTCPDroppedReasonsRegistered(t *testing.T) {
	want := map[dropReason]bool{
		dropFraming:  true,
		dropRead:     true,
		dropOversize: true,
		dropParse:    true,
		dropVersion:  true,
		dropConfig:   true,
		dropSRV:      true,
		dropQueue:    true,
		dropBatchErr: true,
		dropWrite:    true,
	}
	for reason := range droppedSeries[transportTCP] {
		if !want[reason] {
			t.Errorf("unexpected TCP drop reason registered: %q", reason)
		}
		delete(want, reason)
	}
	for reason := range want {
		t.Errorf("missing TCP drop reason: %q", reason)
	}
}

// TestNoteCertProvisioned verifies cert_info, cert_expiry, and cert_provisioned
// are populated for both schemes.
func TestNoteCertProvisioned(t *testing.T) {
	cases := []struct {
		scheme string
		online []byte
		root   []byte
	}{
		{schemeEd25519, []byte{0xde, 0xad, 0xbe, 0xef}, []byte{0xfe, 0xed, 0xfa, 0xce}},
		{schemeMLDSA44, []byte{0xab, 0xcd}, []byte{0x12, 0x34}},
	}
	for _, tc := range cases {
		t.Run(tc.scheme, func(t *testing.T) {
			exp := time.Unix(1_700_000_000, 0)
			prov := time.Unix(1_699_000_000, 0)
			noteCertProvisioned(tc.scheme, tc.online, tc.root, exp, prov)

			sm := certMetricsFor(tc.scheme)
			got, ok := sm.expiry.Load()
			if !ok || got != float64(exp.Unix()) {
				t.Errorf("%s cert expiry = %v ok=%v, want %v ok=true", tc.scheme, got, ok, exp.Unix())
			}
			got, ok = sm.provisioned.Load()
			if !ok || got != float64(prov.Unix()) {
				t.Errorf("%s cert provisioned = %v ok=%v, want %v ok=true", tc.scheme, got, ok, prov.Unix())
			}
			var buf bytes.Buffer
			certInfo.writeTo(&buf)
			// labels render in alphabetical key order
			want := fmt.Sprintf(`roughtime_cert_info{online_pubkey=%q,root_pubkey=%q,scheme=%q} 1`,
				hex.EncodeToString(tc.online), hex.EncodeToString(tc.root), tc.scheme)
			if !strings.Contains(buf.String(), want) {
				t.Errorf("missing %q in:\n%s", want, buf.String())
			}
		})
	}
}

// TestNoteCertProvisionedPanicsOnUnknownScheme verifies the helper rejects an
// unknown scheme constant; this catches refactor mistakes at boot.
func TestNoteCertProvisionedPanicsOnUnknownScheme(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on unknown scheme")
		}
	}()
	noteCertProvisioned("nosuchscheme", nil, nil, time.Now(), time.Now())
}

// TestRegistryWriteOutputsAllRegisteredMetrics verifies every metric appears in
// writeRegistry output with both # HELP and # TYPE banners.
func TestRegistryWriteOutputsAllRegisteredMetrics(t *testing.T) {
	var buf bytes.Buffer
	writeRegistry(&buf)
	out := buf.String()
	for _, m := range registry {
		var name string
		switch x := m.(type) {
		case *counter:
			name = x.name
		case *counterFn:
			name = x.name
		case *gauge:
			name = x.name
		case *infoGauge:
			name = x.name
		default:
			t.Fatalf("unhandled metric type %T", m)
		}
		if !strings.Contains(out, "# HELP "+name) {
			t.Errorf("missing HELP for %s", name)
		}
		if !strings.Contains(out, "# TYPE "+name) {
			t.Errorf("missing TYPE for %s", name)
		}
	}
}

// TestHandleMetricsContentTypeAndBody verifies the /metrics handler emits the
// Prometheus text content type and a body containing at least one declared
// metric.
func TestHandleMetricsContentTypeAndBody(t *testing.T) {
	rr := newResponseRecorder()
	handleMetrics(rr, mustRequest(t, http.MethodGet, "/metrics"))
	if rr.code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.code)
	}
	if got := rr.header.Get("Content-Type"); got != metricsContentType {
		t.Errorf("Content-Type = %q, want %q", got, metricsContentType)
	}
	body := rr.body.String()
	if !strings.Contains(body, "# TYPE roughtime_panics_total counter") {
		t.Errorf("body missing panics TYPE banner:\n%s", body)
	}
}

// TestHandleMetricsHEADReturnsNoBody verifies HEAD /metrics returns headers and
// no body.
func TestHandleMetricsHEADReturnsNoBody(t *testing.T) {
	rr := newResponseRecorder()
	handleMetrics(rr, mustRequest(t, http.MethodHead, "/metrics"))
	if rr.code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.code)
	}
	if rr.body.Len() != 0 {
		t.Errorf("HEAD body = %d bytes, want 0", rr.body.Len())
	}
}

// TestRecoverHTTPBumpsStatsPanics verifies the recoverHTTP middleware absorbs a
// panic from a handler, increments statsPanics, and does not propagate.
func TestRecoverHTTPBumpsStatsPanics(t *testing.T) {
	before := statsPanics.Load()
	h := recoverHTTP(zap.NewNop(), "test handler", http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))
	rr := newResponseRecorder()
	h.ServeHTTP(rr, mustRequest(t, http.MethodGet, "/x"))
	if got := statsPanics.Load() - before; got != 1 {
		t.Errorf("statsPanics delta = %d, want 1", got)
	}
}

// TestHandleMetricsRejectsPOST verifies non-GET/HEAD requests get a 405 with an
// Allow header.
func TestHandleMetricsRejectsPOST(t *testing.T) {
	rr := newResponseRecorder()
	handleMetrics(rr, mustRequest(t, http.MethodPost, "/metrics"))
	if rr.code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.code)
	}
	if got := rr.header.Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q", got, "GET, HEAD")
	}
}

// TestHandleHealthz verifies /healthz returns 200 and a short body.
func TestHandleHealthz(t *testing.T) {
	rr := newResponseRecorder()
	handleHealthz(rr, mustRequest(t, http.MethodGet, "/healthz"))
	if rr.code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.code)
	}
	if got := strings.TrimSpace(rr.body.String()); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

// TestHandleHealthzRejectsPOST verifies /healthz only accepts GET and HEAD.
func TestHandleHealthzRejectsPOST(t *testing.T) {
	rr := newResponseRecorder()
	handleHealthz(rr, mustRequest(t, http.MethodPost, "/healthz"))
	if rr.code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.code)
	}
}

// TestListenMetricsBindError verifies listenMetrics returns an error when the
// requested address is already in use.
func TestListenMetricsBindError(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold port: %v", err)
	}
	defer holder.Close()

	addr := holder.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := listenMetrics(ctx, addr); err == nil {
		t.Fatal("expected bind error, got nil")
	}
}

// TestListenMetricsServesScrape verifies an end-to-end scrape against the live
// listener returns the registry contents.
func TestListenMetricsServesScrape(t *testing.T) {
	pickPort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	addr := pickPort.Addr().String()
	_ = pickPort.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		done <- listenMetrics(ctx, addr)
	})

	// poll until the listener is reachable
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			resp, err = http.Get("http://" + addr + "/metrics")
			if err == nil {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		cancel()
		<-done
		wg.Wait()
		t.Fatal("metrics endpoint never came up")
		return
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		<-done
		wg.Wait()
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("roughtime_build_info")) {
		cancel()
		<-done
		wg.Wait()
		t.Fatalf("scrape missing build_info:\n%s", body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("listenMetrics returned: %v", err)
	}
	wg.Wait()
}

// TestListenMetricsGracefulShutdownWithActiveScraper verifies a scrape in
// flight at shutdown completes cleanly and the listener returns within the
// shutdown grace window.
func TestListenMetricsGracefulShutdownWithActiveScraper(t *testing.T) {
	pickPort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	addr := pickPort.Addr().String()
	_ = pickPort.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- listenMetrics(ctx, addr) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// fire a scrape in a goroutine, then cancel ctx mid-flight; the response
	// should still arrive and listenMetrics should return within the grace
	// window
	scrapeDone := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			scrapeDone <- err
			return
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		scrapeDone <- nil
	}()

	// cancel after a brief delay so the scrape is likely in flight
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-scrapeDone:
		if err != nil {
			t.Errorf("scrape failed: %v", err)
		}
	case <-time.After(metricsShutdownTimeout + time.Second):
		t.Fatal("scrape did not complete during graceful shutdown")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("listenMetrics returned: %v", err)
		}
	case <-time.After(metricsShutdownTimeout + time.Second):
		t.Fatal("listenMetrics did not return within shutdown grace window")
	}
}

// FuzzEscapeHelp verifies escapeHelp never produces output containing an
// unescaped backslash or raw newline.
func FuzzEscapeHelp(f *testing.F) {
	f.Add("plain")
	f.Add(`with \ backslash`)
	f.Add("with\nnewline")
	f.Add(`mixed \\ and ` + "\n" + `more`)
	f.Fuzz(func(t *testing.T, s string) {
		out := escapeHelp(s)
		// every backslash must precede an escaped character
		for i := 0; i < len(out); i++ {
			c := out[i]
			if c == '\n' {
				t.Fatalf("raw newline in escaped help: %q", out)
			}
			if c == '\\' {
				if i+1 >= len(out) {
					t.Fatalf("trailing backslash in escaped help: %q", out)
				}
				next := out[i+1]
				if next != '\\' && next != 'n' {
					t.Fatalf("invalid escape \\%c in: %q", next, out)
				}
				i++
			}
		}
	})
}

// FuzzEscapeLabel verifies escapeLabel never produces output containing an
// unescaped backslash, double-quote, or raw newline.
func FuzzEscapeLabel(f *testing.F) {
	f.Add("plain")
	f.Add(`with "quote"`)
	f.Add(`with \ backslash`)
	f.Add("with\nnewline")
	f.Add(`mixed \"\` + "\n" + `more`)
	f.Fuzz(func(t *testing.T, s string) {
		out := escapeLabel(s)
		for i := 0; i < len(out); i++ {
			c := out[i]
			if c == '\n' {
				t.Fatalf("raw newline in escaped label: %q", out)
			}
			if c == '"' {
				t.Fatalf("raw double-quote in escaped label: %q", out)
			}
			if c == '\\' {
				if i+1 >= len(out) {
					t.Fatalf("trailing backslash in escaped label: %q", out)
				}
				next := out[i+1]
				if next != '\\' && next != '"' && next != 'n' {
					t.Fatalf("invalid escape \\%c in: %q", next, out)
				}
				i++
			}
		}
	})
}

// FuzzFormatValue verifies formatValue never panics and never returns the empty
// string for any float64.
func FuzzFormatValue(f *testing.F) {
	f.Add(float64(0))
	f.Add(1.5)
	f.Add(-1.5)
	f.Add(math.MaxFloat64)
	f.Add(math.SmallestNonzeroFloat64)
	f.Fuzz(func(t *testing.T, v float64) {
		out := formatValue(v)
		if out == "" {
			t.Fatalf("formatValue(%v) returned empty string", v)
		}
	})
}

// responseRecorder is a minimal http.ResponseWriter for handler unit tests.
type responseRecorder struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: http.Header{}, code: http.StatusOK}
}
func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *responseRecorder) WriteHeader(c int)           { r.code = c }

// mustRequest constructs an http.Request or fails the test.
func mustRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, path, err)
	}
	return req
}
