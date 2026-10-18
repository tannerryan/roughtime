// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// TestRFCClientAndProofModes checks RFC exchanges, proof trust, and mode
// boundaries.
func TestRFCClientAndProofModes(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	f.setVersions(1)
	server := f.server()
	server.Version = "01"
	data, err := roughtime.MarshalEcosystem([]roughtime.Server{server})
	if err != nil {
		t.Fatal(err)
	}
	// list decodes the emitted version as a JSON integer.
	var list struct {
		// Servers contains the serialized server entries.
		Servers []struct {
			Version uint32 // advertised wire version
		}
	}
	if err := json.Unmarshal(data, &list); err != nil || list.Servers[0].Version != 1 {
		t.Fatalf("version must be a JSON integer: %s, %v", data, err)
	}
	servers, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []protocol.Mode{protocol.Strict, protocol.Flex} {
		client := &roughtime.Client{Mode: mode, MaxAttempts: 1}
		cr, err := client.QueryChain(context.Background(), []roughtime.Server{servers[0], servers[0]})
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range cr.Results {
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			if version, ok := protocol.ExtractVersion(result.Response.Reply); !ok || version != 1 {
				t.Fatalf("negotiated version %v", version)
			}
		}
		proof, err := cr.Proof()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := proof.MarshalGzip()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := roughtime.ParseProof(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := parsed.Verify(); err != nil {
			t.Fatal(err)
		}
		if err := parsed.Trust(servers); err != nil {
			t.Fatal(err)
		}
	}
	legacyList := strings.Replace(string(data), `"version": 1`, `"version": "IETF"`, 1)
	if _, err := roughtime.ParseEcosystem([]byte(legacyList)); err == nil {
		t.Fatal("strict parser accepted textual version")
	}
	if _, err := roughtime.ParseEcosystemWithMode([]byte(legacyList), protocol.Flex); err != nil {
		t.Fatal(err)
	}
	f.setVersions(protocol.VersionDraft12)
	server.Version = "IETF"
	cr, err := (&roughtime.Client{Mode: protocol.Flex, MaxAttempts: 1}).QueryChain(context.Background(), []roughtime.Server{server})
	if err != nil || cr.Results[0].Err != nil {
		t.Fatalf("flex draft exchange: %v, %v", err, cr.Results[0].Err)
	}
	proof, _ := cr.Proof()
	encoded, err := proof.MarshalGzip()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roughtime.ParseProof(encoded); err == nil {
		t.Fatal("strict parser accepted draft proof")
	}
	parsed, err := roughtime.ParseProofWithMode(encoded, protocol.Flex)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatal(err)
	}
}

// TestRFCClientTCPFallback checks TCP fallback after UDP fails.
func TestRFCClientTCPFallback(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()
	server := f.server()
	server.Addresses = []roughtime.Address{{Transport: "udp", Address: f.tcpAddr}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := &roughtime.Client{Timeout: 100 * time.Millisecond}
	response, err := client.Query(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	if response.Address.Transport != "tcp" {
		t.Fatalf("transport %s", response.Address.Transport)
	}
}
