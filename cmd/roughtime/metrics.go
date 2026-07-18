// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

// dropReason classifies why a request was discarded.
type dropReason uint8

// Drop-reason constants index [dropCounters].
const (
	// dropFraming indicates invalid TCP framing.
	dropFraming dropReason = iota
	// dropRead indicates a transport read failure.
	dropRead
	// dropOversize indicates an oversized request.
	dropOversize
	// dropUndersize indicates an undersized UDP request.
	dropUndersize
	// dropParse indicates an invalid protocol message.
	dropParse
	// dropVersion indicates failed version negotiation.
	dropVersion
	// dropConfig indicates unavailable scheme configuration.
	dropConfig
	// dropSRV indicates a server-binding mismatch.
	dropSRV
	// dropQueue indicates queue backpressure.
	dropQueue
	// dropBatchErr indicates reply-creation failure.
	dropBatchErr
	// dropWrite indicates a transport write failure.
	dropWrite
	// dropReasonCount is the number of counted reasons.
	dropReasonCount
	// dropNone is the success sentinel.
	dropNone = dropReasonCount
)

// dropNames maps counted reasons to metric labels.
var dropNames = [...]string{
	"framing", "read", "oversize", "undersize", "parse", "version",
	"config", "srv", "queue", "batch_err", "write",
}

// Metric label values.
const (
	// schemeEd25519 is the Ed25519 label.
	schemeEd25519 = "ed25519"
	// schemeMLDSA44 is the ML-DSA-44 label.
	schemeMLDSA44 = "mldsa44"
	// transportUDP is the UDP label.
	transportUDP = "udp"
	// transportTCP is the TCP label.
	transportTCP = "tcp"
)

// requestCounters stores totals for supported transport/scheme pairs.
type requestCounters struct {
	udpEd, tcpEd, tcpPQ atomic.Uint64
}

// total returns the aggregate count.
func (c *requestCounters) total() uint64 {
	return c.udpEd.Load() + c.tcpEd.Load() + c.tcpPQ.Load()
}

// dropCounters stores totals by transport and reason.
type dropCounters struct {
	udp [dropReasonCount]atomic.Uint64
	tcp [dropReasonCount]atomic.Uint64
}

// total returns all classified drops.
func (c *dropCounters) total() uint64 {
	var total uint64
	for i := range dropReasonCount {
		total += c.udp[i].Load() + c.tcp[i].Load()
	}
	return total
}

var (
	// requestsReceived counts validated requests.
	requestsReceived requestCounters
	// requestsResponded counts replies written successfully.
	requestsResponded requestCounters
	// requestsDropped counts classified drops.
	requestsDropped dropCounters
	// udpReceivedEd aliases the hot-path UDP Ed25519 receive counter.
	udpReceivedEd = &requestsReceived.udpEd
	// udpRespondedEd aliases the hot-path UDP Ed25519 response counter.
	udpRespondedEd = &requestsResponded.udpEd
	// statsWorkerExits counts unexpected UDP worker exits.
	statsWorkerExits atomic.Uint64
)

// schemeForVersion returns a version's signing-scheme label.
func schemeForVersion(v protocol.Version) string {
	if v == protocol.VersionMLDSA44 {
		return schemeMLDSA44
	}
	return schemeEd25519
}

// requestCounter returns the counter for a supported transport/scheme pair.
func requestCounter(c *requestCounters, transport, scheme string) *atomic.Uint64 {
	switch {
	case transport == transportUDP && scheme == schemeEd25519:
		return &c.udpEd
	case transport == transportTCP && scheme == schemeEd25519:
		return &c.tcpEd
	case transport == transportTCP && scheme == schemeMLDSA44:
		return &c.tcpPQ
	default:
		return nil
	}
}

// incReceived records one validated request.
func incReceived(transport, scheme string) {
	if counter := requestCounter(&requestsReceived, transport, scheme); counter != nil {
		counter.Add(1)
	}
}

// incResponded records successfully written replies.
func incResponded(transport, scheme string, n uint64) {
	if counter := requestCounter(&requestsResponded, transport, scheme); counter != nil {
		counter.Add(n)
	}
}

// dropCounter returns the counter for a valid transport/reason pair.
func dropCounter(transport string, reason dropReason) *atomic.Uint64 {
	if reason >= dropReasonCount {
		return nil
	}
	if transport == transportTCP {
		return &requestsDropped.tcp[reason]
	}
	if transport == transportUDP {
		return &requestsDropped.udp[reason]
	}
	return nil
}

// incDropped records one classified request drop.
func incDropped(transport string, reason dropReason) {
	if counter := dropCounter(transport, reason); counter != nil {
		counter.Add(1)
	}
}

// droppedFor returns the count for a transport/reason pair.
func droppedFor(transport string, reason dropReason) uint64 {
	if counter := dropCounter(transport, reason); counter != nil {
		return counter.Load()
	}
	return 0
}

// certMetric stores certificate metrics for one scheme.
type certMetric struct {
	rotations atomic.Uint64
	state     atomic.Pointer[certMetricState]
}

// certMetricState is an immutable certificate metadata snapshot.
type certMetricState struct {
	onlinePK, rootPK string
	expiry           int64
	provisioned      int64
}

// certMetrics stores certificate metrics by signing scheme.
var certMetrics = map[string]*certMetric{
	schemeEd25519: {},
	schemeMLDSA44: {},
}

// noteCertProvisioned publishes active certificate metadata.
func noteCertProvisioned(scheme string, onlinePK, rootPK []byte, expiry, provisioned time.Time) {
	if metric := certMetrics[scheme]; metric != nil {
		metric.state.Store(&certMetricState{
			onlinePK: hex.EncodeToString(onlinePK), rootPK: hex.EncodeToString(rootPK),
			expiry: expiry.Unix(), provisioned: provisioned.Unix(),
		})
	}
}

// noteCertRotation records one online-certificate rotation.
func noteCertRotation(scheme string) {
	if metric := certMetrics[scheme]; metric != nil {
		metric.rotations.Add(1)
	}
}

// writeRegistry writes the complete Prometheus registry.
func writeRegistry(w io.Writer) {
	writeMeta(w, "roughtime_requests_received_total", "counter", "Validated requests, by transport and scheme.")
	writeRequestSamples(w, "roughtime_requests_received_total", &requestsReceived)
	writeMeta(w, "roughtime_requests_responded_total", "counter", "Replies written to the wire, by transport and scheme.")
	writeRequestSamples(w, "roughtime_requests_responded_total", &requestsResponded)

	writeMeta(w, "roughtime_requests_dropped_total", "counter", "Classified request drops, by transport and reason.")
	udpReasons := []dropReason{dropUndersize, dropOversize, dropParse, dropVersion, dropSRV, dropBatchErr, dropWrite}
	if udpHasQueue {
		udpReasons = append(udpReasons, dropQueue)
	}
	for _, reason := range udpReasons {
		writeUint(w, "roughtime_requests_dropped_total", fmt.Sprintf(`transport="udp",reason="%s"`, dropNames[reason]), requestsDropped.udp[reason].Load())
	}
	for _, reason := range []dropReason{dropFraming, dropRead, dropOversize, dropParse, dropVersion, dropConfig, dropSRV, dropQueue, dropBatchErr, dropWrite} {
		writeUint(w, "roughtime_requests_dropped_total", fmt.Sprintf(`transport="tcp",reason="%s"`, dropNames[reason]), requestsDropped.tcp[reason].Load())
	}

	writeMeta(w, "roughtime_cert_rotations_total", "counter", "Online certificate rotations, by scheme.")
	for _, scheme := range []string{schemeEd25519, schemeMLDSA44} {
		writeUint(w, "roughtime_cert_rotations_total", `scheme="`+scheme+`"`, certMetrics[scheme].rotations.Load())
	}
	writePlainCounters(w)

	writeMeta(w, "roughtime_cert_expiry_timestamp_seconds", "gauge", "Unix time when the active certificate expires, by scheme.")
	for _, scheme := range []string{schemeEd25519, schemeMLDSA44} {
		if state := certMetrics[scheme].state.Load(); state != nil {
			writeInt(w, "roughtime_cert_expiry_timestamp_seconds", `scheme="`+scheme+`"`, state.expiry)
		}
	}
	writeMeta(w, "roughtime_cert_provisioned_timestamp_seconds", "gauge", "Unix time when the active certificate was last provisioned, by scheme.")
	for _, scheme := range []string{schemeEd25519, schemeMLDSA44} {
		if state := certMetrics[scheme].state.Load(); state != nil {
			writeInt(w, "roughtime_cert_provisioned_timestamp_seconds", `scheme="`+scheme+`"`, state.provisioned)
		}
	}

	writeMeta(w, "roughtime_build_info", "gauge", "Build metadata.")
	_, _ = fmt.Fprintf(w, "roughtime_build_info{version=\"%s\",go_version=\"%s\"} 1\n", escapeLabel(version.Version), escapeLabel(runtime.Version()))
	writeMeta(w, "roughtime_cert_info", "gauge", "Active certificate metadata, by scheme.")
	for _, scheme := range []string{schemeEd25519, schemeMLDSA44} {
		if state := certMetrics[scheme].state.Load(); state != nil {
			_, _ = fmt.Fprintf(w, "roughtime_cert_info{scheme=\"%s\",online_pubkey=\"%s\",root_pubkey=\"%s\"} 1\n", scheme, state.onlinePK, state.rootPK)
		}
	}
}

// writeRequestSamples writes each supported transport/scheme sample.
func writeRequestSamples(w io.Writer, name string, counters *requestCounters) {
	writeUint(w, name, `transport="udp",scheme="ed25519"`, counters.udpEd.Load())
	writeUint(w, name, `transport="tcp",scheme="ed25519"`, counters.tcpEd.Load())
	writeUint(w, name, `transport="tcp",scheme="mldsa44"`, counters.tcpPQ.Load())
}

// writePlainCounters writes server-wide unlabeled counters.
func writePlainCounters(w io.Writer) {
	// Each entry describes one unlabeled counter.
	for _, metric := range []struct {
		name, help string
		value      uint64
	}{
		{"roughtime_panics_total", "Goroutine panics recovered.", statsPanics.Load()},
		{"roughtime_udp_amp_suppressed_total", "UDP replies suppressed to prevent amplification.", statsAmpDropped.Load()},
		{"roughtime_tcp_accepted_total", "TCP connections accepted.", statsTCPAccepted.Load()},
		{"roughtime_tcp_rejected_total", "TCP connections rejected at the connection cap.", statsTCPRejected.Load()},
		{"roughtime_tcp_completed_total", "TCP request/reply round-trips completed.", statsTCPCompleted.Load()},
		{"roughtime_batches_total", "Signing batches completed.", statsBatches.Load()},
		{"roughtime_batched_reqs_total", "Requests included in completed signing batches.", statsBatchedReqs.Load()},
		{"roughtime_batch_errs_total", "Batches that could not produce replies.", statsBatchErrs.Load()},
		{"roughtime_udp_worker_exits_total", "UDP worker goroutines that exited unexpectedly.", statsWorkerExits.Load()},
	} {
		writeMeta(w, metric.name, "counter", metric.help)
		writeUint(w, metric.name, "", metric.value)
	}
}

// writeMeta writes Prometheus HELP and TYPE records.
func writeMeta(w io.Writer, name, kind, help string) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

// writeUint writes an unsigned metric sample.
func writeUint(w io.Writer, name, labels string, value uint64) {
	if labels == "" {
		_, _ = fmt.Fprintf(w, "%s %d\n", name, value)
		return
	}
	_, _ = fmt.Fprintf(w, "%s{%s} %d\n", name, labels, value)
}

// writeInt writes a labeled signed metric sample.
func writeInt(w io.Writer, name, labels string, value int64) {
	_, _ = fmt.Fprintf(w, "%s{%s} %d\n", name, labels, value)
}

// escapeLabel escapes a Prometheus label value.
func escapeLabel(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
}
