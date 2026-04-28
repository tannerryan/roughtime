// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tannerryan/roughtime"
)

// TestParseEcosystemRoundTrip verifies a minimal ecosystem document parses back
// to the original Server.
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

// TestParseEcosystemRejectsJunk verifies ParseEcosystem rejects empty,
// malformed, and key-less documents.
func TestParseEcosystemRejectsJunk(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("{"),
		[]byte(`{"servers":[]}`),
		[]byte(`{"servers":[{"publicKey":"not-base64-or-hex"}]}`),
	}
	for i, in := range cases {
		if _, err := roughtime.ParseEcosystem(in); err == nil {
			t.Fatalf("case %d: ParseEcosystem accepted junk", i)
		}
	}
}

// TestParseEcosystemValidatesPublicKeyType verifies a publicKeyType mismatching
// the decoded key length errors.
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

// TestParseEcosystemAllowsMissingPublicKeyType verifies ParseEcosystem accepts
// entries with no publicKeyType.
func TestParseEcosystemAllowsMissingPublicKeyType(t *testing.T) {
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "ok",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{{"protocol": "udp", "address": "example.com:2002"}},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err != nil {
		t.Fatalf("ParseEcosystem rejected entry without publicKeyType: %v", err)
	}
}

// TestParseEcosystemEnforcesMaxServers verifies ParseEcosystem rejects
// documents larger than MaxEcosystemServers.
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

// TestParseEcosystemSanitizesStrings verifies server names and address fields
// run through SanitizeForDisplay.
func TestParseEcosystemSanitizesStrings(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	const rlo = "\u202e"
	const lro = "\u202d"
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "evil" + rlo + ".com\x07",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{{"protocol": "udp", "address": "host" + lro + ":1"}},
		}},
	}
	data, _ := json.Marshal(doc)
	servers, err := roughtime.ParseEcosystem(data)
	if err != nil {
		t.Fatalf("ParseEcosystem: %v", err)
	}
	if strings.ContainsAny(servers[0].Name, lro+rlo+"\x07") {
		t.Fatalf("Name not sanitized: %q", servers[0].Name)
	}
	if strings.ContainsAny(servers[0].Addresses[0].Address, lro+rlo) {
		t.Fatalf("Address not sanitized: %q", servers[0].Addresses[0].Address)
	}
}

// TestParseEcosystemRejectsEmptyAddresses verifies ParseEcosystem rejects
// entries with no addresses.
func TestParseEcosystemRejectsEmptyAddresses(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := map[string]any{
		"servers": []map[string]any{{
			"name":      "noaddrs",
			"publicKey": base64.StdEncoding.EncodeToString(pk),
			"addresses": []map[string]string{},
		}},
	}
	data, _ := json.Marshal(doc)
	if _, err := roughtime.ParseEcosystem(data); err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("ParseEcosystem: %v; want no-addresses error", err)
	}
}

// TestParseEcosystemRejectsBadTransport verifies ParseEcosystem rejects
// unsupported transport labels.
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

// TestParseEcosystemAcceptsIntVersion verifies flexString.UnmarshalJSON
// stringifies an integer version.
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

// TestParseEcosystemRejectsBadVersionType verifies flexString.UnmarshalJSON
// rejects non-string non-int versions.
func TestParseEcosystemRejectsBadVersionType(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	doc := []byte(`{"servers":[{"name":"x","version":[1,2],"publicKey":"` +
		base64.StdEncoding.EncodeToString(pk) +
		`","addresses":[{"protocol":"udp","address":"x:1"}]}]}`)
	if _, err := roughtime.ParseEcosystem(doc); err == nil {
		t.Fatal("ParseEcosystem accepted array-typed version")
	}
}

// TestMarshalEcosystemRoundTrip verifies MarshalEcosystem output round-trips
// through ParseEcosystem.
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

// TestMarshalEcosystemEmptyRoundTrip verifies MarshalEcosystem accepts an empty
// list while ParseEcosystem rejects it.
func TestMarshalEcosystemEmptyRoundTrip(t *testing.T) {
	data, err := roughtime.MarshalEcosystem(nil)
	if err != nil {
		t.Fatalf("MarshalEcosystem(nil): %v", err)
	}
	_, err = roughtime.ParseEcosystem(data)
	if err == nil {
		t.Fatal("ParseEcosystem accepted empty server list")
	}
}

// TestMarshalEcosystemRejectsTooMany verifies MarshalEcosystem rejects more
// than MaxEcosystemServers entries.
func TestMarshalEcosystemRejectsTooMany(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(rand.Reader)
	servers := make([]roughtime.Server, roughtime.MaxEcosystemServers+1)
	for i := range servers {
		servers[i] = roughtime.Server{PublicKey: pk}
	}
	if _, err := roughtime.MarshalEcosystem(servers); err == nil {
		t.Fatal("expected too-many error")
	}
}

// TestMarshalEcosystemRejectsBadKey verifies MarshalEcosystem rejects servers
// with an invalid public key length.
func TestMarshalEcosystemRejectsBadKey(t *testing.T) {
	servers := []roughtime.Server{{
		Name:      "bogus",
		PublicKey: make([]byte, 7),
	}}
	if _, err := roughtime.MarshalEcosystem(servers); err == nil {
		t.Fatal("MarshalEcosystem accepted 7-byte public key")
	}
}

// TestSanitizeForDisplay verifies SanitizeForDisplay strips control, bidi, and
// zero-width runes.
func TestSanitizeForDisplay(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"line\nfeed", "linefeed"},
		{"car\rriage", "carriage"},
		{"null\x00byte", "nullbyte"},
		{"del\x7fbyte", "delbyte"},
		{"bell\x07byte", "bellbyte"},
		{"\u202eevil\u202c", "evil"}, // RLO + PDF
		{"\u2066iso\u2069", "iso"},   // LRI + PDI
		{"unicode é ñ 漢", "unicode é ñ 漢"},
	}
	for _, c := range cases {
		if got := roughtime.SanitizeForDisplay(c.in); got != c.want {
			t.Fatalf("SanitizeForDisplay(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// FuzzParseEcosystem fuzzes ParseEcosystem to ensure successful parses always
// yield valid keys.
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
