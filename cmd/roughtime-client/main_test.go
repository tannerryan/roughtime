// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
	"golang.org/x/sys/unix"
)

// TestClientFlags covers the opt-in sizing flag and two-pass mode guards.
func TestClientFlags(t *testing.T) {
	origServers, origAddr, origPubkey := *serversFile, *addr, *pubkey
	origTwoPass, origChain, origStandard := *twoPass, *chainMode, *standardSize
	t.Cleanup(func() {
		*serversFile, *addr, *pubkey = origServers, origAddr, origPubkey
		*twoPass, *chainMode, *standardSize = origTwoPass, origChain, origStandard
	})

	*serversFile, *addr, *pubkey = "", "", ""
	*twoPass, *chainMode = true, true
	if err := validateFlags(); err == nil || !strings.Contains(err.Error(), "requires -servers") {
		t.Fatalf("validateFlags without ecosystem = %v", err)
	}
	*serversFile, *chainMode = "ecosystem.json", false
	if err := validateFlags(); err == nil || !strings.Contains(err.Error(), "requires -chain=true") {
		t.Fatalf("validateFlags without chain = %v", err)
	}

	*standardSize = true
	if c := newClient(); !c.StandardPacketSize {
		t.Fatal("newClient did not map -standard-size")
	}
	*standardSize = false
	if c := newClient(); c.StandardPacketSize {
		t.Fatal("newClient enabled -standard-size by default")
	}
}

// TestStrictEcosystemMinimum requires three witnesses for strict measurements.
func TestStrictEcosystemMinimum(t *testing.T) {
	origFile, origName := *serversFile, *nameFilter
	origFlex, origTwoPass := *flex, *twoPass
	t.Cleanup(func() {
		*serversFile, *nameFilter = origFile, origName
		*flex, *twoPass = origFlex, origTwoPass
	})
	data, err := roughtime.MarshalEcosystem([]roughtime.Server{{
		Name: "only", Version: "1", PublicKey: make([]byte, 32),
		Addresses: []roughtime.Address{{Transport: "udp", Address: "localhost:5319"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	*serversFile = t.TempDir() + "/servers.json"
	if err := os.WriteFile(*serversFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	*flex, *twoPass, *nameFilter = false, false, ""
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx); err == nil || !strings.Contains(err.Error(), "at least 3") {
		t.Fatalf("strict single-entry measurement: %v", err)
	}
	*nameFilter = "only"
	if err := run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("named single-server query: %v", err)
	}
	*flex, *nameFilter = true, ""
	if err := run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("flex single-server query: %v", err)
	}
}

// TestNormalizeServersBeforeSampling covers compatibility filtering and the
// primary endpoint order used by operator grouping.
func TestNormalizeServersBeforeSampling(t *testing.T) {
	key := make([]byte, 32)
	servers := []roughtime.Server{
		{
			Name:      "mixed",
			PublicKey: key,
			Addresses: []roughtime.Address{
				{Transport: "tcp", Address: "wrong.example:2003"},
				{Transport: "udp", Address: "preferred.test:2002"},
			},
		},
		{
			Name:      "too-old",
			Version:   "0",
			PublicKey: key,
			Addresses: []roughtime.Address{{Transport: "udp", Address: "old.example:2002"}},
		},
	}
	got := normalizeServers(servers)
	if len(got) != 1 {
		t.Fatalf("normalizeServers returned %d entries, want 1", len(got))
	}
	if got[0].Addresses[0].Address != "preferred.test:2002" {
		t.Fatalf("primary endpoint = %q", got[0].Addresses[0].Address)
	}
	if servers[0].Addresses[0].Address != "wrong.example:2003" {
		t.Fatal("normalization mutated source endpoints")
	}
}

// TestTwoPassServers covers same-order expansion, endpoint diversity, and the
// protocol chain-size guard without network traffic.
func TestTwoPassServers(t *testing.T) {
	servers := []roughtime.Server{
		{Name: "a", PublicKey: []byte{1}, Addresses: []roughtime.Address{{Transport: "udp", Address: "192.0.2.1:2002"}}},
		{Name: "b", PublicKey: []byte{2}, Addresses: []roughtime.Address{{Transport: "udp", Address: "192.0.2.2:2002"}}},
		{Name: "c", PublicKey: []byte{3}, Addresses: []roughtime.Address{{Transport: "udp", Address: "192.0.2.3:2002"}}},
	}
	got, err := twoPassServers(servers)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2*len(servers) {
		t.Fatalf("two-pass length = %d", len(got))
	}
	for i := range servers {
		if got[i].Name != servers[i].Name || got[i+len(servers)].Name != servers[i].Name {
			t.Fatalf("order at %d = %q/%q", i, got[i].Name, got[i+len(servers)].Name)
		}
	}
	if _, err := twoPassServers(servers[:2]); err == nil || !strings.Contains(err.Error(), "at least 3") {
		t.Fatalf("two endpoint groups error = %v", err)
	}
	aliases := append([]roughtime.Server(nil), servers...)
	aliases[1].PublicKey = aliases[0].PublicKey
	aliases[2].PublicKey = aliases[0].PublicKey
	if _, err := twoPassServers(aliases); err == nil || !strings.Contains(err.Error(), "distinct trust roots") {
		t.Fatalf("aliased trust roots error = %v", err)
	}

	over := make([]roughtime.Server, protocol.MaxChainLinks/2+1)
	for i := range over {
		over[i] = servers[i%len(servers)]
	}
	if _, err := twoPassServers(over); err == nil || !strings.Contains(err.Error(), "exceeding max") {
		t.Fatalf("oversize error = %v", err)
	}
}

// TestLoadServersFileRejectsFIFO ensures a local special file cannot block the
// client before signal-aware network work starts.
func TestLoadServersFileRejectsFIFO(t *testing.T) {
	path := t.TempDir() + "/servers.fifo"
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := loadServersFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("loadServersFile(FIFO) = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("loadServersFile blocked opening a FIFO")
	}
}

// TestTerminalErrorSanitizes checks terminal controls and the output size
// limit.
func TestTerminalErrorSanitizes(t *testing.T) {
	err := errors.New("bad \x1b[2J argument")
	got := terminalError(err)
	if strings.ContainsRune(got, '\x1b') || !strings.Contains(got, "argument") {
		t.Fatalf("terminalError = %q", got)
	}
	got = terminalError(errors.New(strings.Repeat("界", maxCLIErrorRunes+1)))
	if len([]rune(got)) != maxCLIErrorRunes {
		t.Fatalf("terminalError length = %d runes, want %d", len([]rune(got)), maxCLIErrorRunes)
	}
}

// TestLoadMixedEcosystemInStrictMode separates list syntax from wire support.
func TestLoadMixedEcosystemInStrictMode(t *testing.T) {
	origFile, origName := *serversFile, *nameFilter
	origFlex, origTCP, origAll := *flex, *useTCP, *all
	t.Cleanup(func() {
		*serversFile, *nameFilter = origFile, origName
		*flex, *useTCP, *all = origFlex, origTCP, origAll
	})
	*flex, *useTCP, *all = false, false, false
	data, err := json.Marshal(map[string]any{"servers": []map[string]any{
		{
			"name": "rfc", "version": "1", "publicKeyType": "ed25519",
			"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"addresses": []map[string]string{{"protocol": "udp", "address": "rfc.example:5319"}},
		},
		{
			"name": "pq", "version": "ml-dsa-44", "publicKeyType": "ml-dsa-44",
			"publicKey": base64.StdEncoding.EncodeToString(make([]byte, protocol.MLDSA44PublicKeySize)),
			"addresses": []map[string]string{{"protocol": "tcp", "address": "pq.example:5319"}},
		},
		{
			"name": "google", "version": "Google-Roughtime", "publicKeyType": "ed25519",
			"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"addresses": []map[string]string{{"protocol": "udp", "address": "google.example:2002"}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	*serversFile = t.TempDir() + "/servers.json"
	if err := os.WriteFile(*serversFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	*nameFilter = "rfc"
	servers, err := loadServers()
	if err != nil || len(servers) != 1 || servers[0].Version != "1" {
		t.Fatalf("named RFC query: %v, %v", servers, err)
	}
	if newClient().Mode != protocol.Strict {
		t.Fatal("mixed list enabled flex wire support")
	}
	*nameFilter = "pq"
	if _, err := loadServers(); err == nil || !strings.Contains(err.Error(), "requires flex mode") {
		t.Fatalf("named PQ query without -flex: %v", err)
	}
	*nameFilter, *all = "", true
	servers, err = loadServers()
	if err != nil || len(servers) != 1 || servers[0].Name != "rfc" {
		t.Fatalf("strict filtering: %v, %v", servers, err)
	}
	*flex = true
	servers, err = loadServers()
	if err != nil || len(servers) != 3 {
		t.Fatalf("flex filtering: %v, %v", servers, err)
	}
}
