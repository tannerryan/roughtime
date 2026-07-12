// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/tannerryan/roughtime"
)

// printSingle prints a vertical summary of one verified server response with
// display strings sanitized.
func printSingle(r *roughtime.Response) {
	safeName := roughtime.SanitizeForDisplay(r.Server.Name)
	displayAddr := roughtime.SanitizeForDisplay(r.Address.String())
	windowStart := r.Midpoint.Add(-r.Radius).UTC().Format(time.RFC3339)
	windowEnd := r.Midpoint.Add(r.Radius).UTC().Format(time.RFC3339)
	status := "out-of-sync"
	if r.InSync() {
		status = "in-sync"
	}
	// in -addr mode Name duplicates Address, so skip the redundant line
	if r.Server.Name != r.Address.Address {
		fmt.Printf("Server:    %s\n", safeName)
	}
	fmt.Printf("Address:   %s\n", displayAddr)
	fmt.Printf("Version:   %s\n", r.Version)
	fmt.Printf("Midpoint:  %s\n", r.Midpoint.UTC().Format(time.RFC3339))
	fmt.Printf("Radius:    %s\n", r.Radius)
	fmt.Printf("Window:    [%s, %s]\n", windowStart, windowEnd)
	fmt.Printf("RTT:       %s\n", r.RTT.Round(time.Millisecond))
	fmt.Printf("Local:     %s\n", r.LocalNow.UTC().Format(time.RFC3339Nano))
	fmt.Printf("Drift:     %s\n", r.Drift().Round(time.Millisecond))
	fmt.Printf("Status:    %s\n", status)
}

// printTable prints the per-server table, drift consensus, and chain status
// with display strings sanitized.
func printTable(results []roughtime.Result, proof *roughtime.Proof, servers []roughtime.Server) error {
	nameW, addrW := 30, 30
	for _, s := range servers {
		nameW = max(nameW, len(s.Name))
	}
	for _, r := range results {
		// +6 accounts for the "tcp://" / "udp://" prefix from Address.String
		if r.Address.Address != "" {
			addrW = max(addrW, len(r.Address.Address)+6)
		} else if len(r.Server.Addresses) > 0 {
			addrW = max(addrW, len(r.Server.Addresses[0].Address)+6)
		}
	}
	rowFmt := fmt.Sprintf("%%-%ds  %%-%ds  %%-9s  %%-20s  %%-8s  %%-6s  %%-8s  %%s\n", nameW, addrW)
	fmt.Printf(rowFmt, "NAME", "ADDRESS", "VERSION", "MIDPOINT", "RADIUS", "RTT", "DRIFT", "STATUS")
	errFmt := fmt.Sprintf("%%-%ds  %%-%ds  error: %%s\n", nameW, addrW)

	// Dedupe rows on PublicKey plus resolved address, while distinct endpoints
	// sharing a root key stay separate.
	var rows []roughtime.Result
	type rowKey struct {
		publicKey string
		address   string
	}
	idxByKey := make(map[rowKey]int)
	for _, r := range results {
		if len(r.Server.PublicKey) == 0 {
			rows = append(rows, r)
			continue
		}
		key := rowKey{publicKey: string(r.Server.PublicKey), address: r.Address.String()}
		if i, ok := idxByKey[key]; ok {
			if rows[i].Err != nil && r.Err == nil {
				rows[i] = r
			}
			continue
		}
		idxByKey[key] = len(rows)
		rows = append(rows, r)
	}

	var deduped []roughtime.Result
	for _, r := range rows {
		if r.Err != nil {
			displayAddr := roughtime.SanitizeForDisplay(r.Address.String())
			if displayAddr == "://" && len(r.Server.Addresses) > 0 {
				displayAddr = roughtime.SanitizeForDisplay(r.Server.Addresses[0].String())
			}
			fmt.Printf(errFmt, roughtime.SanitizeForDisplay(r.Server.Name), displayAddr, roughtime.SanitizeForDisplay(r.Err.Error()))
			continue
		}
		resp := r.Response
		displayAddr := roughtime.SanitizeForDisplay(resp.Address.String())
		deduped = append(deduped, r)
		status := "out-of-sync"
		if resp.InSync() {
			status = "in-sync"
		}
		fmt.Printf(rowFmt,
			roughtime.SanitizeForDisplay(resp.Server.Name),
			displayAddr,
			resp.Version.ShortString(),
			resp.Midpoint.UTC().Format(time.RFC3339),
			"±"+resp.Radius.String(),
			resp.RTT.Round(time.Millisecond).String(),
			resp.Drift().Round(time.Millisecond).String(),
			status,
		)
	}
	fmt.Printf("\n%d/%d servers responded\n", len(deduped), len(servers))
	printConsensus(deduped)
	if proof != nil {
		if err := printChainStatus(proof); err != nil {
			return err
		}
	}
	if len(deduped) == 0 {
		return errors.New("no servers responded")
	}
	return nil
}

// printConsensus formats the [roughtime.Consensus] summary across results.
func printConsensus(results []roughtime.Result) {
	c := roughtime.Consensus(results)
	if c.Samples == 0 {
		return
	}
	corrected := time.Now().Add(c.Median).UTC().Format(time.RFC3339)
	fmt.Printf("Consensus drift:    %s (median of %d samples)\n",
		c.Median.Round(time.Millisecond), c.Samples)
	fmt.Printf("Corrected local:    %s (now + median drift)\n", corrected)
	fmt.Printf("Drift spread:       %s (min=%s, max=%s)\n",
		(c.Max - c.Min).Round(time.Millisecond),
		c.Min.Round(time.Millisecond),
		c.Max.Round(time.Millisecond),
	)
}

// printChainStatus prints the chain proof verification result and link count.
func printChainStatus(p *roughtime.Proof) error {
	if err := p.Verify(); err != nil {
		fmt.Printf("Chain:              FAILED: %s\n", roughtime.SanitizeForDisplay(err.Error()))
		return fmt.Errorf("chain verify: %w", err)
	}
	fmt.Printf("Chain:              ok (%d links verified)\n", p.Len())
	return nil
}
