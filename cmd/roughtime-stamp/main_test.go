// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
	"golang.org/x/sys/unix"
)

// TestPrintFailuresUsesStderr keeps failed witness diagnostics off stdout.
func TestPrintFailuresUsesStderr(t *testing.T) {
	dir := t.TempDir()
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	originalOut, originalErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	t.Cleanup(func() { os.Stdout, os.Stderr = originalOut, originalErr })
	printFailures([]roughtime.Result{
		{Server: roughtime.Server{Name: "healthy"}},
		{Server: roughtime.Server{Name: "offline\x1b"}, Err: errors.New("connection refused\x1b")},
	})
	out, err := os.ReadFile(stdout.Name())
	if err != nil || len(out) != 0 {
		t.Fatalf("stdout = %q, %v", out, err)
	}
	out, err = os.ReadFile(stderr.Name())
	if err != nil || !strings.Contains(string(out), "offline") ||
		!strings.Contains(string(out), "connection refused") ||
		strings.Contains(string(out), "healthy") || bytes.ContainsRune(out, '\x1b') {
		t.Fatalf("stderr = %q, %v", out, err)
	}
}

// TestStampFileInputs checks file-only input and cancellation before hashing.
func TestStampFileInputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "document")
	data := []byte("document contents")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{path, link} {
		digest, size, err := hashDocument(context.Background(), input)
		want := sha256.Sum256(data)
		if err != nil || size != int64(len(data)) || !bytes.Equal(digest, want[:]) {
			t.Fatalf("hashDocument(%s) = %x, %d, %v", input, digest, size, err)
		}
		got, err := readBoundedFile(input)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("readBoundedFile(%s) = %q, %v", input, got, err)
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{dir, fifo} {
		if _, _, err := hashDocument(context.Background(), input); err == nil {
			t.Fatalf("hashDocument accepted %s", input)
		}
		if _, err := readBoundedFile(input); err == nil {
			t.Fatalf("readBoundedFile accepted %s", input)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := hashDocument(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled hash = %v", err)
	}
	if err := os.Truncate(path, maxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(path); err == nil {
		t.Fatal("accepted oversized input")
	}
}

// TestWriteProofAtomic preserves old data on cancellation and replaces it on
// success.
func TestWriteProofAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeProofAtomic(ctx, path, []byte("new")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("old receipt = %q, %v", got, err)
	}
	if err := writeProofAtomic(context.Background(), path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("new receipt = %q, %v", got, err)
	}
	if err := writeProofAtomic(context.Background(), dir, []byte("bad")); err == nil {
		t.Fatal("replaced a directory")
	}
	patterns := []string{
		filepath.Join(dir, "*.tmp.*"),
		filepath.Join(filepath.Dir(dir), filepath.Base(dir)+".tmp.*"),
	}
	for _, pattern := range patterns {
		leftovers, err := filepath.Glob(pattern)
		if err != nil || len(leftovers) != 0 {
			t.Fatalf("temporary files for %q = %v, %v", pattern, leftovers, err)
		}
	}
}

// TestWriteMalfeasance keeps each evidence file separate from the receipt.
func TestWriteMalfeasance(t *testing.T) {
	dir := t.TempDir()
	receipt := filepath.Join(dir, "receipt")
	if err := os.WriteFile(receipt, []byte("valid receipt"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := ""
	for range 2 {
		path, err := writeMalfeasance(receipt, []byte("evidence"))
		if err != nil {
			t.Fatal(err)
		}
		if path == receipt || path == previous {
			t.Fatalf("evidence path reused: %s", path)
		}
		previous = path
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "evidence" {
			t.Fatalf("evidence = %q, %v", got, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("evidence permissions: %v, %v", info, err)
		}
	}
	got, err := os.ReadFile(receipt)
	if err != nil || string(got) != "valid receipt" {
		t.Fatalf("receipt changed: %q, %v", got, err)
	}
}

// TestFilterCompatibleNormalizes covers the scheme/version filter, preferred
// endpoint order used by operator sampling, and trust-root de-duplication.
func TestFilterCompatibleNormalizes(t *testing.T) {
	keyA := bytes.Repeat([]byte{1}, 32)
	keyB := bytes.Repeat([]byte{2}, 32)
	tests := []struct {
		name      string
		servers   []roughtime.Server
		want      int
		wantFirst string
		wantGroup string
	}{
		{
			name: "UDP preferred before TCP",
			servers: []roughtime.Server{{
				PublicKey: keyA,
				Addresses: []roughtime.Address{
					{Transport: "tcp", Address: "tcp.example:2003"},
					{Transport: "udp", Address: "preferred.test:2002"},
				},
			}},
			want:      1,
			wantFirst: "preferred.test:2002",
			wantGroup: "preferred.test",
		},
		{
			name: "old version dropped",
			servers: []roughtime.Server{{
				Version:   "1",
				PublicKey: keyA,
				Addresses: []roughtime.Address{{Transport: "udp", Address: "old.test:2002"}},
			}},
		},
		{
			name: "Google dropped",
			servers: []roughtime.Server{{
				Version:   roughtime.VersionLabelGoogle,
				PublicKey: keyA,
				Addresses: []roughtime.Address{{Transport: "udp", Address: "google.test:2002"}},
			}},
		},
		{
			name: "ML-DSA without TCP dropped",
			servers: []roughtime.Server{{
				PublicKey: bytes.Repeat([]byte{3}, protocol.MLDSA44PublicKeySize),
				Addresses: []roughtime.Address{{Transport: "udp", Address: "pq.test:2002"}},
			}},
		},
		{
			name: "same-group duplicate root kept once",
			servers: []roughtime.Server{
				{PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "192.0.2.1:2002"}}},
				{PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "192.0.2.1:2003"}}},
			},
			want:      1,
			wantFirst: "192.0.2.1:2002",
			wantGroup: "192.0.2.1",
		},
		{
			name: "cross-group root aliases dropped",
			servers: []roughtime.Server{
				{PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "first.test:2002"}}},
				{PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "second.test:2002"}}},
			},
		},
		{
			name: "cross-group Google alias drops root",
			servers: []roughtime.Server{
				{PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "first.test:2002"}}},
				{Version: roughtime.VersionLabelGoogle, PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "google.test:2002"}}},
			},
		},
		{
			name: "unusable root alias ignored",
			servers: []roughtime.Server{
				{PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "first.test:2002"}}},
				{Version: "1", PublicKey: keyB, Addresses: []roughtime.Address{{Transport: "udp", Address: "second.test:2002"}}},
			},
			want:      1,
			wantFirst: "first.test:2002",
			wantGroup: "first.test",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterCompatible(tc.servers)
			if len(got) != tc.want {
				t.Fatalf("filterCompatible returned %d entries, want %d", len(got), tc.want)
			}
			if tc.want == 0 {
				return
			}
			if got[0].Addresses[0].Address != tc.wantFirst {
				t.Fatalf("first endpoint = %q, want %q", got[0].Addresses[0].Address, tc.wantFirst)
			}
			if group := roughtime.OperatorKey(got[0]); group != tc.wantGroup {
				t.Fatalf("operator group = %q, want %q", group, tc.wantGroup)
			}
		})
	}
}

// TestFilterCompatibleMatchesProofClassification ensures creation only selects
// roots that verification can assign to endpoint-domain groups.
func TestFilterCompatibleMatchesProofClassification(t *testing.T) {
	keyA := bytes.Repeat([]byte{1}, 32)
	keyC := bytes.Repeat([]byte{2}, 32)
	keyD := bytes.Repeat([]byte{3}, 32)
	keyE := bytes.Repeat([]byte{4}, 32)
	server := func(key []byte, host string) roughtime.Server {
		return roughtime.Server{
			PublicKey: key,
			Addresses: []roughtime.Address{{Transport: "udp", Address: host + ":2002"}},
		}
	}
	servers := []roughtime.Server{
		server(keyA, "a.test"),
		{
			Version:   roughtime.VersionLabelGoogle,
			PublicKey: keyA,
			Addresses: []roughtime.Address{{Transport: "udp", Address: "b.test:2002"}},
		},
		server(keyC, "c.test"),
		server(keyD, "d.test"),
		server(keyE, "e.test"),
	}
	witnesses := filterCompatible(servers)
	if len(witnesses) != stampWitnesses {
		t.Fatalf("filterCompatible returned %d witnesses, want %d", len(witnesses), stampWitnesses)
	}
	links := make([]roughtime.ProofLink, 0, 2*len(witnesses))
	for range 2 {
		for _, witness := range witnesses {
			links = append(links, roughtime.ProofLink{PublicKey: witness.PublicKey})
		}
	}
	for name, trusted := range map[string][]roughtime.Server{
		"creation":     witnesses,
		"verification": servers,
	} {
		t.Run(name, func(t *testing.T) {
			profile := analyzeProof(links, trusted)
			if !profile.twoPass || profile.passSize != stampWitnesses || profile.groups != stampWitnesses {
				t.Fatalf("analyzeProof = %+v", profile)
			}
		})
	}
}

// TestAnalyzeProofNormalizedGroups covers same-order classification after
// endpoint normalization and conservative handling of root aliases.
func TestAnalyzeProofNormalizedGroups(t *testing.T) {
	keyA := bytes.Repeat([]byte{1}, 32)
	keyB := bytes.Repeat([]byte{2}, 32)
	keyC := bytes.Repeat([]byte{3}, 32)
	server := func(key []byte, addresses ...roughtime.Address) roughtime.Server {
		return roughtime.Server{PublicKey: key, Addresses: addresses}
	}
	link := func(key []byte) roughtime.ProofLink { return roughtime.ProofLink{PublicKey: key} }
	baseServers := []roughtime.Server{
		server(keyA,
			// The raw first endpoint shares keyB's group. Classification only
			// reaches three groups when NormalizeServer's UDP preference is
			// used.
			roughtime.Address{Transport: "tcp", Address: "192.0.2.2:2003"},
			roughtime.Address{Transport: "udp", Address: "192.0.2.1:2002"}),
		server(keyB, roughtime.Address{Transport: "udp", Address: "192.0.2.2:2002"}),
		server(keyC, roughtime.Address{Transport: "udp", Address: "192.0.2.3:2002"}),
	}
	validLinks := []roughtime.ProofLink{link(keyA), link(keyB), link(keyC), link(keyA), link(keyB), link(keyC)}
	tests := []struct {
		name     string
		links    []roughtime.ProofLink
		servers  []roughtime.Server
		twoPass  bool
		passSize int
		groups   int
	}{
		{"normalized same-order passes", validLinks, baseServers, true, 3, 3},
		{
			"unusable alias ignored",
			validLinks,
			append(append([]roughtime.Server(nil), baseServers...), roughtime.Server{
				Version:   "1",
				PublicKey: keyA,
				Addresses: []roughtime.Address{{Transport: "udp", Address: "198.51.100.1:2002"}},
			}),
			true, 3, 3,
		},
		{
			"usable alias is ambiguous",
			validLinks,
			append(append([]roughtime.Server(nil), baseServers...), server(keyA,
				roughtime.Address{Transport: "udp", Address: "198.51.100.1:2002"})),
			false, 0, 2,
		},
		{
			"different second-pass order",
			[]roughtime.ProofLink{link(keyA), link(keyB), link(keyC), link(keyA), link(keyC), link(keyB)},
			baseServers,
			false, 0, 3,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeProof(tc.links, tc.servers)
			if got.twoPass != tc.twoPass || got.passSize != tc.passSize || got.groups != tc.groups {
				t.Fatalf("analyzeProof = %+v, want twoPass=%v passSize=%d groups=%d",
					got, tc.twoPass, tc.passSize, tc.groups)
			}
		})
	}
}
