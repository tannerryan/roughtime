// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/tannerryan/roughtime"
)

// Table layout and display limits.
const (
	// minTableNameWidth is the minimum NAME column width.
	minTableNameWidth = 30
	// minTableAddressWidth is the minimum ADDRESS column width.
	minTableAddressWidth = 30
	// maxTableNameRunes caps displayed server names.
	maxTableNameRunes = 48
	// maxTableAddressRunes caps displayed endpoints.
	maxTableAddressRunes = 72
	// maxTableErrorRunes caps displayed errors.
	maxTableErrorRunes = 240
)

// responseInSync reports whether the local exchange interval and authenticated
// server window overlap. Both intervals are closed, so touching boundaries
// count as synchronized.
func responseInSync(r *roughtime.Response) bool {
	if r == nil || r.Radius < 0 || r.RTT < 0 {
		return false
	}
	localStart, localEnd := r.LocalNow.Add(-r.RTT), r.LocalNow
	serverStart := r.Midpoint.Add(-r.Radius)
	serverEnd := r.Midpoint.Add(r.Radius)
	return !localEnd.Before(serverStart) && !serverEnd.Before(localStart)
}

// printSingle prints one verified response.
func printSingle(r *roughtime.Response) {
	status := "out-of-sync"
	if responseInSync(r) {
		status = "in-sync"
	}
	if r.Server.Name != r.Address.Address {
		fmt.Printf("Server:    %s\n", display(r.Server.Name, maxTableNameRunes))
	}
	fmt.Printf("Address:    %s\n", display(r.Address.String(), maxTableAddressRunes))
	fmt.Printf("Version:    %s\n", r.Version)
	fmt.Printf("Midpoint:   %s\n", r.Midpoint.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Radius:     %s\n", r.Radius)
	fmt.Printf("Window:     [%s, %s]\n",
		r.Midpoint.Add(-r.Radius).UTC().Format(time.RFC3339Nano),
		r.Midpoint.Add(r.Radius).UTC().Format(time.RFC3339Nano))
	fmt.Printf("RTT:        %s\n", r.RTT.Round(time.Millisecond))
	fmt.Printf("Local:      %s\n", r.LocalNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Drift:      %s\n", r.Drift().Round(time.Millisecond))
	fmt.Printf("Status:     %s\n", status)
}

// printTable prints batch results, chain status, and drift statistics.
// expectedProbes is nonzero only for strict two-pass measurements.
func printTable(results []roughtime.Result, proof *roughtime.Proof, expectedProbes int) error {
	probeResults := len(results)
	probeSuccesses := 0
	for _, result := range results {
		if result.Err == nil && result.Response != nil {
			probeSuccesses++
		}
	}
	// Collapse repeated trust-root/endpoint entries without merging distinct
	// endpoints that share a root key.
	type rowKey struct {
		publicKey string
		address   string
	}
	rows := make([]roughtime.Result, 0, len(results))
	rowIndex := make(map[rowKey]int)
	for _, result := range results {
		if len(result.Server.PublicKey) == 0 {
			rows = append(rows, result)
			continue
		}
		key := rowKey{publicKey: string(result.Server.PublicKey), address: resultAddressKey(result)}
		if i, ok := rowIndex[key]; ok {
			if rows[i].Err != nil && result.Err == nil {
				rows[i] = result
			}
			continue
		}
		rowIndex[key] = len(rows)
		rows = append(rows, result)
	}
	results = rows

	nameW, addrW := minTableNameWidth, minTableAddressWidth
	for _, result := range results {
		nameW = max(nameW, utf8.RuneCountInString(display(result.Server.Name, maxTableNameRunes)))
		addrW = max(addrW, utf8.RuneCountInString(display(resultAddress(result), maxTableAddressRunes)))
	}
	rowFmt := fmt.Sprintf("%%-%ds  %%-%ds  %%-9s  %%-30s  %%-8s  %%-6s  %%-8s  %%s\n", nameW, addrW)
	fmt.Printf(rowFmt, "NAME", "ADDRESS", "VERSION", "MIDPOINT", "RADIUS", "RTT", "DRIFT", "STATUS")
	errFmt := fmt.Sprintf("%%-%ds  %%-%ds  error: %%s\n", nameW, addrW)

	successes := make([]roughtime.Result, 0, len(results))
	for _, result := range results {
		if result.Err != nil || result.Response == nil {
			message := "missing response"
			if result.Err != nil {
				message = result.Err.Error()
			}
			fmt.Printf(errFmt, display(result.Server.Name, maxTableNameRunes),
				display(resultAddress(result), maxTableAddressRunes), display(message, maxTableErrorRunes))
			continue
		}
		response := result.Response
		successes = append(successes, result)
		status := "out-of-sync"
		if responseInSync(response) {
			status = "in-sync"
		}
		fmt.Printf(rowFmt,
			display(response.Server.Name, maxTableNameRunes),
			display(response.Address.String(), maxTableAddressRunes),
			response.Version.ShortString(),
			response.Midpoint.UTC().Format(time.RFC3339Nano),
			"±"+response.Radius.String(),
			response.RTT.Round(time.Millisecond),
			response.Drift().Round(time.Millisecond),
			status)
	}

	if expectedProbes > 0 {
		fmt.Printf("\n%d/%d probes responded\n", probeSuccesses, expectedProbes)
	} else {
		fmt.Printf("\n%d/%d servers responded\n", len(successes), len(results))
	}
	if proof != nil {
		if err := printChainStatus(proof); err != nil {
			return err
		}
	}
	if expectedProbes > 0 {
		links := 0
		if proof != nil {
			links = proof.Len()
		}
		if probeResults != expectedProbes || probeSuccesses != expectedProbes || links != expectedProbes {
			fmt.Printf("Measurement:        FAILED: complete %d-probe chain required (%d replies, %d links)\n",
				expectedProbes, probeSuccesses, links)
			return fmt.Errorf("incomplete two-pass measurement: got %d/%d replies and %d/%d proof links",
				probeSuccesses, expectedProbes, links, expectedProbes)
		}
		fmt.Printf("Measurement:        complete (%d probes)\n", expectedProbes)
	}
	if len(successes) == 0 {
		return errors.New("no servers responded")
	}
	printConsensus(successes)
	return nil
}

// resultAddress returns the selected endpoint, or explicitly identifies a
// configured endpoint when no attempt succeeded.
func resultAddress(result roughtime.Result) string {
	if result.Address.Address != "" {
		return result.Address.String()
	}
	if len(result.Server.Addresses) > 0 {
		return "unknown (configured: " + result.Server.Addresses[0].String() + ")"
	}
	return "unknown (no configured endpoint)"
}

// resultAddressKey retains the historical coalescing key without presenting a
// configured endpoint as the endpoint associated with a failure.
func resultAddressKey(result roughtime.Result) string {
	if result.Address.Address != "" {
		return result.Address.String()
	}
	if len(result.Server.Addresses) > 0 {
		return result.Server.Addresses[0].String()
	}
	return ""
}

// display sanitizes and truncates untrusted terminal text.
func display(value string, limit int) string {
	value = roughtime.SanitizeForDisplay(value)
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	return string(runes[:limit-1]) + "…"
}

// printConsensus prints drift statistics for successful results.
func printConsensus(results []roughtime.Result) {
	c := roughtime.Consensus(results)
	if c.Samples == 0 {
		return
	}
	fmt.Printf("Consensus drift:    %s (median of %d endpoint samples, not agreement)\n", c.Median.Round(time.Millisecond), c.Samples)
	fmt.Printf("Corrected local:    %s (now + median drift)\n", time.Now().Add(c.Median).UTC().Format(time.RFC3339))
	fmt.Printf("Drift spread:       %s (min=%s, max=%s)\n",
		durationSpread(c.Min, c.Max).Round(time.Millisecond), c.Min.Round(time.Millisecond), c.Max.Round(time.Millisecond))
}

// durationSpread subtracts ordered durations with saturation on overflow.
func durationSpread(minimum, maximum time.Duration) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if maximum < minimum {
		return 0
	}
	if minimum < 0 && maximum > maxDuration+minimum {
		return maxDuration
	}
	return maximum - minimum
}

// printChainStatus verifies and prints the causal chain status.
func printChainStatus(proof *roughtime.Proof) error {
	if err := proof.Verify(); err != nil {
		fmt.Printf("Chain:              FAILED: %s\n", display(err.Error(), maxTableErrorRunes))
		return fmt.Errorf("chain verify: %w", err)
	}
	fmt.Printf("Chain:              ok (%d links verified)\n", proof.Len())
	return nil
}
