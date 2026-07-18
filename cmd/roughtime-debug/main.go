// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Command roughtime-debug probes a server's supported wire versions and prints
// a concise authenticated response summary. Draft 12 is probed in typed and
// untyped forms.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/internal/version"
	"github.com/tannerryan/roughtime/protocol"
)

var (
	// addr is the server endpoint flag.
	addr = flag.String("addr", "", "host:port of the Roughtime server")
	// pubkey is the server root-key flag.
	pubkey = flag.String("pubkey", "", "root public key (base64 or hex); 32 raw bytes selects Ed25519, 1312 raw bytes selects ML-DSA-44")
	// useTCP selects TCP transport.
	useTCP = flag.Bool("tcp", false, "use TCP transport; Google-Roughtime is UDP-only and ML-DSA-44 keys always use TCP")
	// timeout bounds each attempt.
	timeout = flag.Duration("timeout", 500*time.Millisecond, "timeout for each attempt (consider raising for ML-DSA-44 over TCP)")
	// retries caps attempts per version form.
	retries = flag.Int("retries", 3, "max attempts per version/form (>=1)")
	// forceVer selects one wire version.
	forceVer = flag.String("ver", "", "probe only this wire version, case-sensitive (e.g. draft-12, Google, ml-dsa-44); draft-12 falls back to the untyped form")
	// showVersion requests version output and exit.
	showVersion = flag.Bool("version", false, "print version and exit")
)

// probePlan identifies one concrete request form. Draft-12 has two forms under
// the same numeric wire version.
type probePlan struct {
	version  protocol.Version
	omitTYPE bool
	label    string
	short    string
}

// probeResult represents the outcome of a single per-form probe.
type probeResult struct {
	plan      probePlan
	transport string // "udp" or "tcp"
	midpoint  time.Time
	localNow  time.Time
	radius    time.Duration
	rtt       time.Duration
	request   []byte
	reply     []byte
	err       error
}

// main parses flags and runs the diagnostic client.
func main() {
	flag.Parse()
	if *showVersion {
		fmt.Printf("roughtime-debug %s (github.com/tannerryan/roughtime)\n\n%s\n", version.Full(), version.Copyright)
		return
	}
	if err := validateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, "debug:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "debug:", *addr+":", err)
		if errors.Is(ctx.Err(), context.Canceled) {
			os.Exit(130)
		}
		os.Exit(1)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		os.Exit(130)
	}
}

// validateFlags checks that required flags are set and within range.
func validateFlags() error {
	if *addr == "" || *pubkey == "" {
		return errors.New("usage: roughtime-debug -addr <host:port> -pubkey <base64-or-hex>")
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected positional args: %v", flag.Args())
	}
	if _, _, err := net.SplitHostPort(*addr); err != nil {
		return fmt.Errorf("invalid -addr %q: %w", roughtime.SanitizeForDisplay(*addr), err)
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout %s must be > 0", *timeout)
	}
	if *retries < 1 {
		return fmt.Errorf("-retries %d must be >= 1", *retries)
	}
	return nil
}

// defaultProbeVersions returns every implemented version compatible with sch.
func defaultProbeVersions(sch roughtime.Scheme) []protocol.Version {
	if sch == roughtime.SchemeMLDSA44 {
		return []protocol.Version{protocol.VersionMLDSA44}
	}
	versions := make([]protocol.Version, 0, len(protocol.Supported()))
	for _, candidate := range protocol.Supported() {
		if candidate != protocol.VersionMLDSA44 {
			versions = append(versions, candidate)
		}
	}
	return versions
}

// plansForVersion expands the shared draft-12 wire version into its typed and
// untyped request forms.
func plansForVersion(ver protocol.Version) []probePlan {
	if ver == protocol.VersionDraft12 {
		return []probePlan{
			{version: ver, label: "draft-ietf-ntp-roughtime-14+ (TYPE)", short: "draft-14+"},
			{version: ver, omitTYPE: true, label: "draft-ietf-ntp-roughtime-12/13 (no TYPE)", short: "draft-12/13"},
		}
	}
	return []probePlan{{version: ver, label: ver.String(), short: ver.ShortString()}}
}

// defaultProbePlans expands all scheme-compatible versions into concrete
// request forms.
func defaultProbePlans(sch roughtime.Scheme) []probePlan {
	var plans []probePlan
	for _, ver := range defaultProbeVersions(sch) {
		plans = append(plans, plansForVersion(ver)...)
	}
	return plans
}

// run executes the probe workflow against the configured server.
func run(ctx context.Context) error {
	rootPK, err := roughtime.DecodePublicKey(*pubkey)
	if err != nil {
		return fmt.Errorf("decoding public key: %w", err)
	}
	sch, err := roughtime.SchemeOfKey(rootPK)
	if err != nil {
		return err
	}
	plans := defaultProbePlans(sch)
	transport := "udp"
	if sch == roughtime.SchemeMLDSA44 || *useTCP {
		transport = "tcp"
	}
	if *forceVer != "" {
		ver, err := protocol.ParseShortVersion(*forceVer)
		if err != nil {
			return err
		}
		pqKey := sch == roughtime.SchemeMLDSA44
		pqVer := ver == protocol.VersionMLDSA44
		if pqKey != pqVer {
			return fmt.Errorf("-ver %s is incompatible with the supplied root key", roughtime.SanitizeForDisplay(*forceVer))
		}
		if ver == protocol.VersionGoogle && transport == "tcp" {
			return errors.New("-ver Google is incompatible with -tcp (Google-Roughtime is UDP-only)")
		}
		plans = plansForVersion(ver)
		var lastErr error
		for _, plan := range plans {
			result := probe(ctx, rootPK, plan, transport)
			fmt.Printf("=== Forced Version: %s ===\n", plan.label)
			if result.err != nil {
				fmt.Printf("Probe error: %s\n\n", result.err)
				lastErr = result.err
			}
			printDiagnostic(result)
			if result.err == nil {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return lastErr
	}

	fmt.Printf("=== Version Probe: %s (%s) ===\n", roughtime.SanitizeForDisplay(*addr), transport)
	fmt.Printf("Timeout per attempt: %s; attempts per form: %d\n", *timeout, *retries)
	var supported []probePlan
	var best *probeResult

	for _, plan := range plans {
		// Google-Roughtime is UDP-only, so a TCP probe would misreport it.
		if transport == "tcp" && plan.version == protocol.VersionGoogle {
			fmt.Printf("  %-48s %s\n", plan.label, "skipped (Google-Roughtime is UDP-only)")
			continue
		}
		result := probe(ctx, rootPK, plan, transport)
		status := "OK"
		if result.err != nil {
			status = result.err.Error()
		}
		fmt.Printf("  %-48s %s\n", plan.label, roughtime.SanitizeForDisplay(status))

		if result.err != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}
		supported = append(supported, plan)
		if best == nil {
			copyResult := result
			best = &copyResult
		}
	}

	fmt.Println()
	if len(supported) == 0 {
		return errors.New("no supported versions found")
	}

	shorts := make([]string, len(supported))
	for i, plan := range supported {
		shorts[i] = plan.short
	}
	fmt.Printf("Supported versions: %s\n", strings.Join(shorts, ", "))
	fmt.Printf("Negotiated:         %s\n\n", best.plan.label)
	printDiagnostic(*best)
	return nil
}

// probe sends a Roughtime request for a concrete version form, retrying on
// failure.
func probe(ctx context.Context, rootPK []byte, plan probePlan, transport string) probeResult {
	result := probeResult{plan: plan, transport: transport}
	versions := []protocol.Version{plan.version}

	var srv []byte
	if plan.version != protocol.VersionGoogle {
		srv = protocol.ComputeSRV(rootPK)
	}
	options := protocol.RequestOptions{
		OmitTYPE:         plan.omitTYPE,
		LegacyPacketSize: plan.version != protocol.VersionDraft12 || plan.omitTYPE,
	}
	nonce, request, err := protocol.CreateRequestWithOptions(versions, rand.Reader, srv, options)
	if err != nil {
		result.err = fmt.Errorf("request: %w", err)
		return result
	}
	result.request = request

	for attempt := range *retries {
		if err := ctx.Err(); err != nil {
			result.err = err
			return result
		}
		result.reply = nil
		result.rtt = 0
		result.localNow = time.Time{}
		result.midpoint = time.Time{}
		result.radius = 0
		reply, rtt, localNow, sendErr := sendProbe(ctx, request, *timeout, transport)
		if sendErr != nil {
			err = sendErr
		} else {
			result.reply = reply
			result.rtt = rtt
			result.localNow = localNow
			result.midpoint, result.radius, err = verifyProbeReply(plan, reply, rootPK, nonce, request)
			if err != nil {
				err = fmt.Errorf("verify: %w", err)
			}
		}
		if err == nil {
			result.err = nil
			return result
		}
		result.err = err
		if attempt == *retries-1 {
			return result
		}
	}
	return result
}

// verifyProbeReply authenticates a reply and requires its TYPE form to match
// the concrete draft-12 probe. The general protocol verifier remains
// compatibility-oriented, but discovery must not conflate drafts 12/13 with
// drafts 14+.
func verifyProbeReply(plan probePlan, reply, rootPK, nonce, request []byte) (midpoint time.Time, radius time.Duration, err error) {
	versions := []protocol.Version{plan.version}
	requireTYPE := plan.version == protocol.VersionDraft12 && !plan.omitTYPE
	midpoint, radius, err = protocol.VerifyReplyWithOptions(
		versions, reply, rootPK, nonce, request,
		protocol.VerifyOptions{RequireTYPE: requireTYPE},
	)
	if err != nil || plan.version != protocol.VersionDraft12 || !plan.omitTYPE {
		return midpoint, radius, err
	}

	tags, err := protocol.Decode(msgBody(reply))
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("decode verified response: %w", err)
	}
	if _, ok := tags[protocol.TagTYPE]; ok {
		return time.Time{}, 0, errors.New("draft-12/13 response unexpectedly carries TYPE")
	}
	return midpoint, radius, nil
}

// sendProbe performs one timeout-bounded round trip over the chosen transport.
func sendProbe(ctx context.Context, request []byte, deadline time.Duration, transport string) (reply []byte, rtt time.Duration, localNow time.Time, err error) {
	attemptCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	switch strings.ToLower(transport) {
	case "tcp":
		return protocol.RoundTripTCP(attemptCtx, *addr, request, deadline)
	case "udp":
		return protocol.RoundTripUDP(attemptCtx, *addr, request, deadline)
	default:
		return nil, 0, time.Time{}, fmt.Errorf("unsupported transport %q", transport)
	}
}

// isIETF reports whether pkt starts with the IETF "ROUGHTIM" framing magic.
func isIETF(pkt []byte) bool {
	return len(pkt) >= 8 && bytes.Equal(pkt[:8], []byte("ROUGHTIM"))
}

// msgBody strips the ROUGHTIM header if present and returns the message body.
func msgBody(pkt []byte) []byte {
	if !isIETF(pkt) {
		return pkt
	}
	bodyLen, err := protocol.ParsePacketHeader(pkt)
	if err != nil {
		return nil
	}
	if uint64(bodyLen) > uint64(len(pkt)-protocol.PacketHeaderSize) {
		return nil
	}
	return pkt[protocol.PacketHeaderSize : protocol.PacketHeaderSize+int(bodyLen)]
}

// decode parses Roughtime tag-value data and prints decode errors.
func decode(data []byte) map[uint32][]byte {
	tags, err := protocol.Decode(data)
	if err != nil {
		fmt.Printf("debug: decode: %s\n", roughtime.SanitizeForDisplay(err.Error()))
		return nil
	}
	return tags
}
