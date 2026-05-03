// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

// dropReason is the "reason" label value for requests_dropped_total.
type dropReason string

// Drop reasons. UDP cannot produce framing/read; TCP cannot produce undersize.
// Everything else applies to both transports.
const (
	// dropFraming is a TCP header magic, length, or parse failure.
	dropFraming dropReason = "framing"
	// dropRead is a TCP body short-read or read timeout.
	dropRead dropReason = "read"
	// dropOversize is a packet whose declared body length exceeds the cap.
	dropOversize dropReason = "oversize"
	// dropUndersize is a UDP packet shorter than minRequestSize.
	dropUndersize dropReason = "undersize"
	// dropParse is a request body parse failure.
	dropParse dropReason = "parse"
	// dropVersion is a version negotiation failure.
	dropVersion dropReason = "version"
	// dropConfig is a TCP route mismatch: negotiated scheme not configured.
	dropConfig dropReason = "config"
	// dropSRV is an SRV tag that does not address a configured root key.
	dropSRV dropReason = "srv"
	// dropQueue is a batcher queue saturation past the submit wait.
	dropQueue dropReason = "queue"
	// dropBatchErr is a batch-level signing or oversize-reply failure.
	dropBatchErr dropReason = "batch_err"
	// dropWrite is a failed socket write of a fully signed reply.
	dropWrite dropReason = "write"
)

// counter is a labeled monotonic counter. Series are registered at init and the
// slice is read-only thereafter.
type counter struct {
	// name is the metric name.
	name string
	// help renders in the # HELP line.
	help string
	// labelNames is the order register expects values.
	labelNames []string
	// series holds one entry per registered label tuple.
	series []*counterSeries
}

// counterSeries is one (label-tuple, value) sample.
type counterSeries struct {
	// labelValues align with the parent counter's labelNames.
	labelValues []string
	// val is the per-series counter.
	val atomic.Uint64
}

// newCounter constructs a counter; labels may be empty for an un-labeled one.
func newCounter(name, help string, labels ...string) *counter {
	return &counter{name: name, help: help, labelNames: labels}
}

// (counter) register reserves a series and returns its atomic counter; must be
// called from init.
func (c *counter) register(values ...string) *atomic.Uint64 {
	if len(values) != len(c.labelNames) {
		panic(fmt.Sprintf("metrics: counter %s expects %d label values, got %d", c.name, len(c.labelNames), len(values)))
	}
	s := &counterSeries{labelValues: append([]string(nil), values...)}
	c.series = append(c.series, s)
	return &s.val
}

// (counter) total sums every series.
func (c *counter) total() uint64 {
	var n uint64
	for _, s := range c.series {
		n += s.val.Load()
	}
	return n
}

// (counter) reset zeroes every series; for tests.
func (c *counter) reset() {
	for _, s := range c.series {
		s.val.Store(0)
	}
}

// (counter) writeTo renders the counter in text exposition format.
func (c *counter) writeTo(w io.Writer) {
	writeHelpType(w, c.name, "counter", c.help)
	for _, s := range c.series {
		writeSample(w, c.name, c.labelNames, s.labelValues, float64(s.val.Load()))
	}
}

// gauge is a labeled gauge holding float64 values via the IEEE-754 bit pattern
// in an atomic.Uint64.
type gauge struct {
	name       string
	help       string
	labelNames []string
	series     []*gaugeSeries
}

// gaugeSeries is one (label-tuple, value) sample; un-Set series are skipped at
// scrape time so an unconfigured scheme doesn't render a default-zero sample.
type gaugeSeries struct {
	labelValues []string
	bits        atomic.Uint64
	set         atomic.Bool
}

// (gaugeSeries) Set publishes v.
func (s *gaugeSeries) Set(v float64) {
	s.bits.Store(math.Float64bits(v))
	s.set.Store(true)
}

// (gaugeSeries) Load returns the current value and whether it has been Set.
func (s *gaugeSeries) Load() (float64, bool) {
	if !s.set.Load() {
		return 0, false
	}
	return math.Float64frombits(s.bits.Load()), true
}

// newGauge constructs a gauge.
func newGauge(name, help string, labels ...string) *gauge {
	return &gauge{name: name, help: help, labelNames: labels}
}

// (gauge) register reserves a series; must be called from init.
func (g *gauge) register(values ...string) *gaugeSeries {
	if len(values) != len(g.labelNames) {
		panic(fmt.Sprintf("metrics: gauge %s expects %d label values, got %d", g.name, len(g.labelNames), len(values)))
	}
	s := &gaugeSeries{labelValues: append([]string(nil), values...)}
	g.series = append(g.series, s)
	return s
}

// (gauge) writeTo renders every Set series; never-Set series are skipped.
func (g *gauge) writeTo(w io.Writer) {
	writeHelpType(w, g.name, "gauge", g.help)
	for _, s := range g.series {
		if v, ok := s.Load(); ok {
			writeSample(w, g.name, g.labelNames, s.labelValues, v)
		}
	}
}

// infoGauge always reports 1; the signal is in label values, which may rotate
// at runtime. Multiple series per metric supported.
type infoGauge struct {
	name       string
	help       string
	labelNames []string
	series     []*infoSeries
}

// infoSeries is one series within an infoGauge with its own label snapshot.
type infoSeries struct {
	// parent enables label-count validation in Set.
	parent *infoGauge
	// state is the current label-value snapshot; nil before Set is called.
	state atomic.Pointer[[]string]
}

// newInfoGauge constructs an infoGauge.
func newInfoGauge(name, help string, labels ...string) *infoGauge {
	return &infoGauge{name: name, help: help, labelNames: labels}
}

// (infoGauge) register reserves a series; must be called from init.
func (g *infoGauge) register() *infoSeries {
	s := &infoSeries{parent: g}
	g.series = append(g.series, s)
	return s
}

// (infoSeries) Set publishes label values atomically; values is copied so the
// caller may mutate it.
func (s *infoSeries) Set(values ...string) {
	if len(values) != len(s.parent.labelNames) {
		panic(fmt.Sprintf("metrics: infoGauge %s expects %d label values, got %d", s.parent.name, len(s.parent.labelNames), len(values)))
	}
	cp := append([]string(nil), values...)
	s.state.Store(&cp)
}

// (infoGauge) writeTo renders every Set series; never-Set series are skipped.
func (g *infoGauge) writeTo(w io.Writer) {
	writeHelpType(w, g.name, "gauge", g.help)
	for _, s := range g.series {
		if vals := s.state.Load(); vals != nil {
			writeSample(w, g.name, g.labelNames, *vals, 1)
		}
	}
}

// counterFn is an un-labeled counter sampled from fn at scrape time, so the
// existing atomic.Uint64 counters can be exposed without duplicating state.
type counterFn struct {
	name string
	help string
	fn   func() uint64
}

// newCounterFn constructs a counterFn.
func newCounterFn(name, help string, fn func() uint64) *counterFn {
	return &counterFn{name: name, help: help, fn: fn}
}

// (counterFn) writeTo renders the counter in text exposition format.
func (c *counterFn) writeTo(w io.Writer) {
	writeHelpType(w, c.name, "counter", c.help)
	writeSample(w, c.name, nil, nil, float64(c.fn()))
}

// exporter is a metric capable of writing its own samples.
type exporter interface {
	writeTo(w io.Writer)
}

// registry is the metrics list rendered by /metrics; populated at init.
var registry []exporter

// addMetric appends m to the registry; init-only.
func addMetric(m exporter) { registry = append(registry, m) }

// Labeled counters; every valid label tuple is pre-registered in
// initLabeledSeries so increment sites can index a flat map lock-free.
var (
	requestsReceived = newCounter(
		"roughtime_requests_received_total",
		"Validated requests, by transport and scheme.",
		"transport", "scheme",
	)
	requestsResponded = newCounter(
		"roughtime_requests_responded_total",
		"Replies written to the wire, by transport and scheme.",
		"transport", "scheme",
	)
	requestsDropped = newCounter(
		"roughtime_requests_dropped_total",
		"Requests dropped before reply, by transport and reason.",
		"transport", "reason",
	)
	certRotations = newCounter(
		"roughtime_cert_rotations_total",
		"Online certificate rotations, by scheme.",
		"scheme",
	)
)

// Un-labeled counters sampled from the existing atomic.Uint64s so the source of
// truth stays at the increment site.
var (
	panicsRecovered = newCounterFn(
		"roughtime_panics_total",
		"Goroutine panics recovered.",
		func() uint64 { return statsPanics.Load() },
	)
	ampSuppressed = newCounterFn(
		"roughtime_udp_amp_suppressed_total",
		"UDP replies suppressed to prevent amplification.",
		func() uint64 { return statsAmpDropped.Load() },
	)
	tcpAccepted = newCounterFn(
		"roughtime_tcp_accepted_total",
		"TCP connections accepted.",
		func() uint64 { return statsTCPAccepted.Load() },
	)
	tcpRejected = newCounterFn(
		"roughtime_tcp_rejected_total",
		"TCP connections rejected at the connection cap.",
		func() uint64 { return statsTCPRejected.Load() },
	)
	tcpCompleted = newCounterFn(
		"roughtime_tcp_completed_total",
		"TCP request/reply round-trips completed.",
		func() uint64 { return statsTCPCompleted.Load() },
	)
	batches = newCounterFn(
		"roughtime_batches_total",
		"Signing batches flushed.",
		func() uint64 { return statsBatches.Load() },
	)
	batchedRequests = newCounterFn(
		"roughtime_batched_reqs_total",
		"Requests included in flushed batches.",
		func() uint64 { return statsBatchedReqs.Load() },
	)
	batchErrors = newCounterFn(
		"roughtime_batch_errs_total",
		"Batches that failed to sign.",
		func() uint64 { return statsBatchErrs.Load() },
	)
)

// Gauges and info gauges.
var (
	certExpiry = newGauge(
		"roughtime_cert_expiry_timestamp_seconds",
		"Unix time when the active certificate expires, by scheme.",
		"scheme",
	)
	certProvisioned = newGauge(
		"roughtime_cert_provisioned_timestamp_seconds",
		"Unix time when the active certificate was last provisioned, by scheme.",
		"scheme",
	)
	buildInfo = newInfoGauge(
		"roughtime_build_info",
		"Build metadata.",
		"version", "go_version",
	)
	certInfo = newInfoGauge(
		"roughtime_cert_info",
		"Active certificate metadata, by scheme.",
		"scheme", "online_pubkey", "root_pubkey",
	)
)

// schemeCertMetrics bundles the per-scheme cert lifecycle series.
type schemeCertMetrics struct {
	rotations   *atomic.Uint64
	expiry      *gaugeSeries
	provisioned *gaugeSeries
	info        *infoSeries
}

// Pre-registered series pointers used directly by increment-site helpers; the
// stored *atomic.Uint64 avoids a per-event map lookup on the hot path.
var (
	// receivedSeries[transport][scheme] = atomic counter pointer.
	receivedSeries map[string]map[string]*atomic.Uint64
	// respondedSeries[transport][scheme] = atomic counter pointer.
	respondedSeries map[string]map[string]*atomic.Uint64
	droppedSeries   map[string]map[dropReason]*atomic.Uint64
	// certMetricsByScheme[scheme] holds rotations/expiry/provisioned/info
	// series for that scheme.
	certMetricsByScheme map[string]*schemeCertMetrics
	buildInfoSeries     *infoSeries
)

// Label constants — bare strings would invite typos at increment sites.
const (
	schemeEd25519 = "ed25519"
	schemeMLDSA44 = "mldsa44"
	transportUDP  = "udp"
	transportTCP  = "tcp"
)

// schemeForVersion maps a wire version to its scheme label.
func schemeForVersion(v protocol.Version) string {
	if v == protocol.VersionMLDSA44 {
		return schemeMLDSA44
	}
	return schemeEd25519
}

// init wires every metric into the registry and pre-registers each valid label
// tuple. Build info is set here; other gauges are populated by serve.
func init() {
	addMetric(requestsReceived)
	addMetric(requestsResponded)
	addMetric(requestsDropped)
	addMetric(certRotations)
	addMetric(panicsRecovered)
	addMetric(ampSuppressed)
	addMetric(tcpAccepted)
	addMetric(tcpRejected)
	addMetric(tcpCompleted)
	addMetric(batches)
	addMetric(batchedRequests)
	addMetric(batchErrors)
	addMetric(certExpiry)
	addMetric(certProvisioned)
	addMetric(buildInfo)
	addMetric(certInfo)

	initLabeledSeries()

	buildInfoSeries.Set(version.Version, runtime.Version())
}

// initLabeledSeries pre-registers an atomic for every valid label tuple.
func initLabeledSeries() {
	// UDP carries Ed25519 only; ML-DSA-44 is TCP-exclusive.
	receivedSeries = map[string]map[string]*atomic.Uint64{
		transportUDP: {
			schemeEd25519: requestsReceived.register(transportUDP, schemeEd25519),
		},
		transportTCP: {
			schemeEd25519: requestsReceived.register(transportTCP, schemeEd25519),
			schemeMLDSA44: requestsReceived.register(transportTCP, schemeMLDSA44),
		},
	}
	respondedSeries = map[string]map[string]*atomic.Uint64{
		transportUDP: {
			schemeEd25519: requestsResponded.register(transportUDP, schemeEd25519),
		},
		transportTCP: {
			schemeEd25519: requestsResponded.register(transportTCP, schemeEd25519),
			schemeMLDSA44: requestsResponded.register(transportTCP, schemeMLDSA44),
		},
	}

	// UDP can't produce framing/read (TCP-only) or oversize (kernel truncates);
	// TCP can't produce undersize. udpHasQueue gates dropQueue per-platform.
	udpReasons := []dropReason{dropUndersize, dropParse, dropVersion, dropSRV, dropBatchErr, dropWrite}
	if udpHasQueue {
		udpReasons = append(udpReasons, dropQueue)
	}
	tcpReasons := []dropReason{dropFraming, dropRead, dropOversize, dropParse, dropVersion, dropConfig, dropSRV, dropQueue, dropBatchErr, dropWrite}
	droppedSeries = map[string]map[dropReason]*atomic.Uint64{
		transportUDP: {},
		transportTCP: {},
	}
	for _, r := range udpReasons {
		droppedSeries[transportUDP][r] = requestsDropped.register(transportUDP, string(r))
	}
	for _, r := range tcpReasons {
		droppedSeries[transportTCP][r] = requestsDropped.register(transportTCP, string(r))
	}

	certMetricsByScheme = map[string]*schemeCertMetrics{}
	for _, scheme := range []string{schemeEd25519, schemeMLDSA44} {
		certMetricsByScheme[scheme] = &schemeCertMetrics{
			rotations:   certRotations.register(scheme),
			expiry:      certExpiry.register(scheme),
			provisioned: certProvisioned.register(scheme),
			info:        certInfo.register(),
		}
	}
	buildInfoSeries = buildInfo.register()
}

// incReceived bumps requests_received_total by one.
func incReceived(transport, scheme string) {
	if c := receivedSeries[transport][scheme]; c != nil {
		c.Add(1)
	}
}

// incResponded bumps requests_responded_total by n.
func incResponded(transport, scheme string, n uint64) {
	if c := respondedSeries[transport][scheme]; c != nil {
		c.Add(n)
	}
}

// incDropped bumps requests_dropped_total by one.
func incDropped(transport string, reason dropReason) {
	if c := droppedSeries[transport][reason]; c != nil {
		c.Add(1)
	}
}

// droppedFor returns requests_dropped_total for one (transport, reason); used
// by shutdown logs that surface per-reason totals.
func droppedFor(transport string, reason dropReason) uint64 {
	if c := droppedSeries[transport][reason]; c != nil {
		return c.Load()
	}
	return 0
}

// certMetricsFor returns the cert lifecycle series for scheme; panics on
// unknown so a refactor mistake fails fast.
func certMetricsFor(scheme string) *schemeCertMetrics {
	sm, ok := certMetricsByScheme[scheme]
	if !ok {
		panic(fmt.Sprintf("metrics: unknown scheme %q", scheme))
	}
	return sm
}

// noteCertProvisioned publishes the post-provision metric snapshot for scheme.
func noteCertProvisioned(scheme string, onlinePK, rootPK []byte, expiry, provisionedAt time.Time) {
	sm := certMetricsFor(scheme)
	sm.info.Set(scheme, hex.EncodeToString(onlinePK), hex.EncodeToString(rootPK))
	sm.expiry.Set(float64(expiry.Unix()))
	sm.provisioned.Set(float64(provisionedAt.Unix()))
}

// noteCertRotation bumps cert_rotations_total for scheme.
func noteCertRotation(scheme string) {
	certMetricsFor(scheme).rotations.Add(1)
}

// writeRegistry renders every registered metric to w.
func writeRegistry(w io.Writer) {
	for _, m := range registry {
		m.writeTo(w)
	}
}

// writeHelpType emits the # HELP and # TYPE banner.
func writeHelpType(w io.Writer, name, kind, help string) {
	_, _ = io.WriteString(w, "# HELP ")
	_, _ = io.WriteString(w, name)
	_, _ = io.WriteString(w, " ")
	_, _ = io.WriteString(w, escapeHelp(help))
	_, _ = io.WriteString(w, "\n# TYPE ")
	_, _ = io.WriteString(w, name)
	_, _ = io.WriteString(w, " ")
	_, _ = io.WriteString(w, kind)
	_, _ = io.WriteString(w, "\n")
}

// writeSample emits one sample; nil/empty labels produce an un-labeled sample.
// Labels render in alphabetical key order for deterministic output.
func writeSample(w io.Writer, name string, labelNames, labelValues []string, value float64) {
	_, _ = io.WriteString(w, name)
	if len(labelNames) > 0 {
		_, _ = io.WriteString(w, "{")
		idx := make([]int, len(labelNames))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(i, j int) bool { return labelNames[idx[i]] < labelNames[idx[j]] })
		for i, k := range idx {
			if i > 0 {
				_, _ = io.WriteString(w, ",")
			}
			_, _ = io.WriteString(w, labelNames[k])
			_, _ = io.WriteString(w, `="`)
			_, _ = io.WriteString(w, escapeLabel(labelValues[k]))
			_, _ = io.WriteString(w, `"`)
		}
		_, _ = io.WriteString(w, "}")
	}
	_, _ = io.WriteString(w, " ")
	_, _ = io.WriteString(w, formatValue(value))
	_, _ = io.WriteString(w, "\n")
}

// formatValue renders v: integers up to 2^53 without a decimal point, others as
// the shortest round-trippable float.
func formatValue(v float64) string {
	if math.IsNaN(v) {
		return "NaN"
	}
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if math.IsInf(v, -1) {
		return "-Inf"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1<<53 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// escapeHelp escapes \ and newline per the Prometheus text format.
func escapeHelp(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	return r.Replace(s)
}

// escapeLabel escapes \, " and newline per the Prometheus text format.
func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}
