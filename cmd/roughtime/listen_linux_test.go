// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build linux

package main

import (
	"net"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// TestHarvestRejectsMSGTRUNC covers kernel-reported truncation.
func TestHarvestRejectsMSGTRUNC(t *testing.T) {
	before := droppedFor(transportUDP, dropOversize)
	msgs := []ipv6.Message{{
		N:       maxPacketSize,
		Flags:   unix.MSG_TRUNC,
		Addr:    &net.UDPAddr{IP: net.IPv6loopback, Port: 2002},
		Buffers: [][]byte{make([]byte, maxPacketSize)},
	}}
	var batch []validatedRequest
	harvest(zap.NewNop(), msgs, nil, &batch)
	if len(batch) != 0 {
		t.Fatalf("harvest accepted %d truncated requests", len(batch))
	}
	if got := droppedFor(transportUDP, dropOversize) - before; got != 1 {
		t.Fatalf("oversize drops = %d, want 1", got)
	}
}

// TestHarvestRejectsReportedLengthBeyondBuffer covers oversized lengths.
func TestHarvestRejectsReportedLengthBeyondBuffer(t *testing.T) {
	before := droppedFor(transportUDP, dropOversize)
	msgs := []ipv6.Message{{
		N:       maxPacketSize + 1,
		Addr:    &net.UDPAddr{IP: net.IPv6loopback, Port: 2002},
		Buffers: [][]byte{make([]byte, maxPacketSize+1)},
	}}
	var batch []validatedRequest
	harvest(zap.NewNop(), msgs, nil, &batch)
	if len(batch) != 0 {
		t.Fatalf("harvest accepted %d oversize requests", len(batch))
	}
	if got := droppedFor(transportUDP, dropOversize) - before; got != 1 {
		t.Fatalf("oversize drops = %d, want 1", got)
	}
}
