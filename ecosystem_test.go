// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tannerryan/roughtime"
)

// udpServer returns a minimal UDP test server.
func udpServer(name, addr string) roughtime.Server {
	return roughtime.Server{Name: name, Addresses: []roughtime.Address{{Transport: "udp", Address: addr}}}
}

// TestOperatorKey covers endpoint-domain grouping keys.
func TestOperatorKey(t *testing.T) {
	cases := map[string]string{
		"fr.ntp.inutile.pro:2002":       "inutile.pro",
		"sth1.roughtime.netnod.se:2002": "netnod.se",
		"127.0.0.1:2002":                "127.0.0.1",
		"[::1]:2002":                    "::1",
		"localhost:2002":                "localhost",
	}
	for addr, want := range cases {
		if got := roughtime.OperatorKey(udpServer("s", addr)); got != want {
			t.Errorf("OperatorKey(%q) = %q, want %q", addr, got, want)
		}
	}
	if got := roughtime.OperatorKey(roughtime.Server{Name: "fallback"}); got != "fallback" {
		t.Errorf("OperatorKey(no addresses) = %q, want %q", got, "fallback")
	}
}

// TestSampleByOperator covers endpoint-domain diversity sampling.
func TestSampleByOperator(t *testing.T) {
	servers := []roughtime.Server{
		udpServer("fr", "fr.ntp.inutile.pro:2002"),
		udpServer("es", "es.ntp.inutile.pro:2002"),
		udpServer("uk", "uk.ntp.inutile.pro:2002"),
		udpServer("us", "us.ntp.inutile.pro:2002"),
		udpServer("se", "roughtime.se:2002"),
	}
	got := roughtime.SampleByOperator(servers, 3)
	seen := map[string]bool{}
	for _, s := range got {
		k := roughtime.OperatorKey(s)
		if seen[k] {
			t.Fatalf("operator %q sampled twice: %v", k, got)
		}
		seen[k] = true
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 distinct operators", len(got))
	}
}

// TestParseEcosystemRoundTrip covers valid ecosystem decoding.
func TestParseEcosystemRoundTrip(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":          "example",
			"version":       "draft-ietf-ntp-roughtime-12",
			"publicKeyType": "ed25519",
			"publicKey":     base64.StdEncoding.EncodeToString(pk),
			"addresses":     []map[string]string{{"protocol": "udp", "address": "example.com:2002"}},
		}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	servers, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatalf("ParseEcosystem: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	got := servers[0]
	if got.Name != "example" {
		t.Fatalf("Name = %q", got.Name)
	}
	if len(got.PublicKey) != ed25519.PublicKeySize || !bytes.Equal(got.PublicKey, pk) {
		t.Fatalf("PublicKey mismatch")
	}
	if len(got.Addresses) != 1 || got.Addresses[0].Transport != "udp" {
		t.Fatalf("addresses = %+v", got.Addresses)
	}
}

// TestParseEcosystemValidatesPublicKeyType covers key-type mismatches.
func TestParseEcosystemValidatesPublicKeyType(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":          "mismatch",
			"publicKeyType": "ml-dsa-44",
			"publicKey":     base64.StdEncoding.EncodeToString(pk),
			"addresses":     []map[string]string{{"protocol": "udp", "address": "example.com:2002"}},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "publicKeyType") {
		t.Fatalf("ParseEcosystem: %v; want publicKeyType mismatch error", err)
	}
}

// TestParseEcosystemEnforcesMaxServers covers the server-count limit.
func TestParseEcosystemEnforcesMaxServers(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	entry := map[string]any{
		"name":      "x",
		"publicKey": base64.StdEncoding.EncodeToString(pk),
		"addresses": []map[string]string{{"protocol": "udp", "address": "x:1"}},
	}
	servers := make([]map[string]any, roughtime.MaxEcosystemServers+1)
	for i := range servers {
		servers[i] = entry
	}
	data, _ := json.Marshal(map[string]any{"servers": servers})
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("ParseEcosystem: %v; want max-entries error", err)
	}
}

// TestShippedEcosystemParses validates the bundled ecosystem file.
func TestShippedEcosystemParses(t *testing.T) {
	data, err := os.ReadFile("ecosystem.json")
	if err != nil {
		t.Fatalf("read ecosystem.json: %v", err)
	}
	servers, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatalf("ParseEcosystem: %v", err)
	}
	if len(servers) == 0 {
		t.Fatal("ecosystem.json has no servers")
	}
}

// TestParseEcosystemRejectsBadTransport covers unsupported transports.
func TestParseEcosystemRejectsBadTransport(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "x",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{{"protocol": "sctp", "address": "x:1"}},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "unsupported transport") {
		t.Fatalf("ParseEcosystem: %v; want unsupported-transport error", err)
	}
}

// TestParseEcosystemRejectsBadAddress covers malformed endpoints.
func TestParseEcosystemRejectsBadAddress(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "x",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{{"protocol": "udp", "address": "missing-port"}},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "bad address") {
		t.Fatalf("ParseEcosystem: %v; want bad-address error", err)
	}
}

// TestParseEcosystemRejectsIPv6Zone covers nonportable scoped addresses.
func TestParseEcosystemRejectsIPv6Zone(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "x",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{{"protocol": "udp", "address": "[fe80::1%en0]:2002"}},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "zone") {
		t.Fatalf("ParseEcosystem: %v; want IPv6-zone error", err)
	}
}

// TestParseEcosystemAcceptsIntVersion covers numeric ecosystem versions.
func TestParseEcosystemAcceptsIntVersion(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := []byte(`{"servers":[{"name":"x","version":12,"publicKey":"` +
		base64.StdEncoding.EncodeToString(pk) +
		`","addresses":[{"protocol":"udp","address":"x:1"}]}]}`)
	servers, err := roughtime.ParseEcosystem(doc)
	if err != nil {
		t.Fatalf("ParseEcosystem: %v", err)
	}
	if servers[0].Version != "12" {
		t.Fatalf("Version = %q, want %q", servers[0].Version, "12")
	}
}

// TestMarshalEcosystemRoundTrip covers ecosystem serialization.
func TestMarshalEcosystemRoundTrip(t *testing.T) {
	pk1, _, _ := ed25519.GenerateKey(rand.Reader)
	pq := bytes.Repeat([]byte{0x42}, 1312)
	in := []roughtime.Server{
		{
			Name:      "alpha",
			Version:   "draft-ietf-ntp-roughtime-12",
			PublicKey: pk1,
			Addresses: []roughtime.Address{{Transport: "udp", Address: "alpha.example:2002"}},
		},
		{
			Name:      "beta-pq",
			PublicKey: pq,
			Addresses: []roughtime.Address{{Transport: "tcp", Address: "beta.example:2003"}},
		},
	}
	data, err := roughtime.MarshalEcosystem(in)
	if err != nil {
		t.Fatalf("MarshalEcosystem: %v", err)
	}
	out, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatalf("ParseEcosystem (round-trip): %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round-trip length: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Name != in[i].Name {
			t.Errorf("server[%d] Name mismatch: %q vs %q", i, out[i].Name, in[i].Name)
		}
		if !bytes.Equal(out[i].PublicKey, in[i].PublicKey) {
			t.Errorf("server[%d] PublicKey mismatch", i)
		}
	}
}

// TestParseEcosystemRejectsOversizeInput covers the byte-size limit.
func TestParseEcosystemRejectsOversizeInput(t *testing.T) {
	data := bytes.Repeat([]byte{' '}, roughtime.MaxEcosystemBytes+1)
	if _, err := roughtime.ParseEcosystem(data); err == nil {
		t.Fatal("ParseEcosystem accepted oversize input")
	}
}

// FuzzParseEcosystem exercises the JSON trust boundary.
func FuzzParseEcosystem(f *testing.F) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	doc := map[string]any{"servers": []map[string]any{{
		"name":      "ex",
		"publicKey": base64.StdEncoding.EncodeToString(pk),
		"addresses": []map[string]string{{"protocol": "udp", "address": "x:1"}},
	}}}
	good, _ := json.Marshal(doc)
	f.Add(good)
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte(`{"servers":[]}`))
	f.Add([]byte(`{"servers":[{}]}`))

	f.Fuzz(func(t *testing.T, in []byte) {
		servers, err := roughtime.ParseEcosystem(in)
		if err != nil {
			return
		}
		if len(servers) == 0 {
			t.Fatal("ParseEcosystem returned empty list without error")
		}
		for _, s := range servers {
			if _, err := roughtime.SchemeOfKey(s.PublicKey); err != nil {
				t.Fatalf("ParseEcosystem returned server with invalid key length %d", len(s.PublicKey))
			}
		}
	})
}
