// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestMalfeasanceReportRoundTrip covers the modern report format.
func TestMalfeasanceReportRoundTrip(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseMalfeasanceReportWithMode(data, Flex)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(parsed.Links) != len(c.Links) {
		t.Fatalf("link count = %d, want %d", len(parsed.Links), len(c.Links))
	}
	for i := range c.Links {
		if !bytes.Equal(parsed.Links[i].Rand, c.Links[i].Rand) {
			t.Fatalf("link %d: rand mismatch", i)
		}
		if !bytes.Equal(parsed.Links[i].PublicKey, c.Links[i].PublicKey) {
			t.Fatalf("link %d: publicKey mismatch", i)
		}
		if !bytes.Equal(parsed.Links[i].Request, c.Links[i].Request) {
			t.Fatalf("link %d: request mismatch", i)
		}
		if !bytes.Equal(parsed.Links[i].Response, c.Links[i].Response) {
			t.Fatalf("link %d: response mismatch", i)
		}
	}

	if err := parsed.Verify(); err != nil {
		t.Fatalf("deserialized chain should verify: %v", err)
	}
}

// TestParseMalfeasanceReportRejectsMalformed covers invalid reports.
func TestParseMalfeasanceReportRejectsMalformed(t *testing.T) {
	if _, err := ParseMalfeasanceReportWithMode([]byte(`not json`), Flex); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// TestMalfeasanceReportRoundTripDraft10 covers the legacy report format.
func TestMalfeasanceReportRoundTripDraft10(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// probe contains the legacy arrays checked by this test.
	var probe struct {
		Nonces    []string `json:"nonces"`
		Responses []string `json:"responses"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("legacy format unmarshal: %v", err)
	}
	if len(probe.Nonces) != len(c.Links)-1 || len(probe.Responses) != len(c.Links) {
		t.Fatalf("legacy arrays length mismatch: nonces=%d want=%d responses=%d want=%d",
			len(probe.Nonces), len(c.Links)-1, len(probe.Responses), len(c.Links))
	}
	parsed, err := ParseMalfeasanceReportWithMode(data, Flex)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Links) != len(c.Links) {
		t.Fatalf("link count = %d, want %d", len(parsed.Links), len(c.Links))
	}
	for i, link := range parsed.Links {
		if !bytes.Equal(link.Rand, c.Links[i].Rand) {
			t.Fatalf("link %d: rand mismatch", i)
		}
		if !bytes.Equal(link.Response, c.Links[i].Response) {
			t.Fatalf("link %d: response mismatch", i)
		}
		if link.Request != nil || link.PublicKey != nil {
			t.Fatalf("link %d: legacy format should drop Request/PublicKey", i)
		}
	}

	// Accept the compatible equal-length shape.
	probe.Nonces = append([]string{""}, probe.Nonces...)
	oldData, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMalfeasanceReportWithMode(oldData, Flex); err != nil {
		t.Fatalf("parse compatible legacy shape: %v", err)
	}
}

// TestMalfeasanceReportRoundTripDraft01 covers the early report format.
func TestMalfeasanceReportRoundTripDraft01(t *testing.T) {
	c, _ := buildChain(t, VersionDraft01, 2)
	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}
	var report []malfeasanceLinkEarly
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report) != 2 || report[0].Blind == "" {
		t.Fatal("invalid early report shape")
	}
	parsed, err := ParseMalfeasanceReportWithMode(data, Flex)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Links) != len(c.Links) || !bytes.Equal(parsed.Links[1].Rand, c.Links[1].Rand) {
		t.Fatal("early report did not round-trip")
	}
}

// FuzzParseMalfeasanceReport exercises historical report parsing.
func FuzzParseMalfeasanceReport(f *testing.F) {
	rfc, err := os.ReadFile("testdata/rfc10049-appendix-b.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(rfc)
	// seedResponse is one response in the valid fuzzer seed.
	type seedResponse struct {
		Rand      string `json:"rand,omitempty"`
		PublicKey string `json:"publicKey"`
		Request   string `json:"request"`
		Response  string `json:"response"`
	}
	// seedReport is the valid fuzzer seed's top-level shape.
	type seedReport struct {
		Responses []seedResponse `json:"responses"`
	}
	validReport, _ := json.Marshal(seedReport{
		Responses: []seedResponse{
			{
				PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				Request:   base64.StdEncoding.EncodeToString(make([]byte, 64)),
				Response:  base64.StdEncoding.EncodeToString(make([]byte, 128)),
			},
			{
				Rand:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
				PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				Request:   base64.StdEncoding.EncodeToString(make([]byte, 64)),
				Response:  base64.StdEncoding.EncodeToString(make([]byte, 128)),
			},
		},
	})
	f.Add(validReport)
	response := base64.StdEncoding.EncodeToString(make([]byte, 128))
	transition := base64.StdEncoding.EncodeToString(make([]byte, 32))
	blind := base64.StdEncoding.EncodeToString(make([]byte, 64))
	f.Add([]byte(`{"nonces":["` + transition + `"],"responses":["` + response + `","` + response + `"]}`))
	f.Add([]byte(`{"nonces":["","` + transition + `"],"responses":["` + response + `","` + response + `"]}`))
	f.Add([]byte(`[{"blind":"` + blind + `","response_packet":"` + response + `"},{"response_packet":"` + response + `"}]`))

	f.Add([]byte("{}"))
	f.Add([]byte(`{"responses":[]}`))
	f.Add([]byte(`{"responses":[{}]}`))
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte(`{"responses":[{"publicKey":"!!!","request":"!!!","response":"!!!"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if strict, err := ParseMalfeasanceReport(data); err == nil {
			out, err := strict.MalfeasanceReport()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseMalfeasanceReport(out); err != nil {
				t.Fatal(err)
			}
			_ = strict.Verify()
		}
		chain, err := ParseMalfeasanceReportWithMode(data, Flex)
		if err != nil {
			return
		}
		out, err := chain.MalfeasanceReport()
		if err != nil {
			return
		}
		chain2, err := ParseMalfeasanceReportWithMode(out, Flex)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if len(chain2.Links) != len(chain.Links) {
			t.Fatalf("link count mismatch: %d vs %d", len(chain2.Links), len(chain.Links))
		}
		// Historical formats omit request/key metadata and the first link's
		// unused blind.
		preservesMetadata := chain.inferMalfeasanceFormat() == malfeasanceFormatModern
		for i := range chain.Links {
			if (preservesMetadata || i > 0) && !bytes.Equal(chain.Links[i].Rand, chain2.Links[i].Rand) {
				t.Fatalf("link %d rand mismatch", i)
			}
			if preservesMetadata && !bytes.Equal(chain.Links[i].PublicKey, chain2.Links[i].PublicKey) {
				t.Fatalf("link %d publicKey mismatch", i)
			}
			if preservesMetadata && !bytes.Equal(chain.Links[i].Request, chain2.Links[i].Request) {
				t.Fatalf("link %d request mismatch", i)
			}
			if !bytes.Equal(chain.Links[i].Response, chain2.Links[i].Response) {
				t.Fatalf("link %d response mismatch", i)
			}
		}
	})
}

// TestParseMalfeasanceReportRejectsTooManyLinks covers the link-count limit.
func TestParseMalfeasanceReportRejectsTooManyLinks(t *testing.T) {
	const n = 1025
	entries := make([]string, n)
	for i := range entries {
		entries[i] = `""`
	}
	data := []byte(`{"nonces":[` + strings.Join(entries, ",") + `],"responses":[` + strings.Join(entries, ",") + `]}`)
	if _, err := ParseMalfeasanceReportWithMode(data, Flex); err == nil {
		t.Fatal("expected error for too many links")
	}
}

// TestReportArrayLimitBeforeDecode rejects excess entries before decoding their
// fields.
func TestReportArrayLimitBeforeDecode(t *testing.T) {
	for _, data := range []string{
		`[` + strings.Repeat(`{},`, MaxChainLinks) + `false]`,
		`{"nonces":[` + strings.Repeat(`"",`, MaxChainLinks) + `false],"responses":["AA=="]}`,
	} {
		if _, err := ParseMalfeasanceReportWithMode([]byte(data), Flex); err == nil || !strings.Contains(err.Error(), "max") {
			t.Fatalf("expected entry-limit error before decoding excess value, got %v", err)
		}
	}
}

// TestReportArrayJSONCompatibility preserves null and duplicate-key behavior.
func TestReportArrayJSONCompatibility(t *testing.T) {
	var report malfeasanceReportLegacy
	if err := json.Unmarshal([]byte(`{"responses":["old"],"responses":["new"],"nonces":null}`), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Responses) != 1 || report.Responses[0] != "new" || report.Nonces != nil {
		t.Fatalf("unexpected replacement: %+v", report)
	}
	if err := json.Unmarshal([]byte(`{"responses":null}`), &report); err != nil || report.Responses != nil {
		t.Fatalf("null did not clear array: %+v, %v", report, err)
	}
	for _, value := range []string{`{}`, `false`, `1`, `"value"`} {
		if err := json.Unmarshal([]byte(`{"responses":`+value+`}`), &report); err == nil {
			t.Fatalf("accepted non-array %s", value)
		}
	}
}
