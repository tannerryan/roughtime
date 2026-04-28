// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestMalfeasanceReportRoundTrip verifies a chain round-trips through
// MalfeasanceReport and ParseMalfeasanceReport.
func TestMalfeasanceReportRoundTrip(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseMalfeasanceReport(data)
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

// TestMalfeasanceReportFirstLinkNoRand verifies the first link omits "rand" in
// JSON output.
func TestMalfeasanceReportFirstLinkNoRand(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}

	var raw struct {
		Responses []map[string]any `json:"responses"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	if _, ok := raw.Responses[0]["rand"]; ok {
		t.Fatal("first link should not have rand in JSON")
	}
	if _, ok := raw.Responses[1]["rand"]; !ok {
		t.Fatal("second link should have rand in JSON")
	}
}

// TestMalfeasanceReportFields verifies report links include valid base64
// publicKey, request, and response.
func TestMalfeasanceReportFields(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 2)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}

	var report struct {
		Responses []struct {
			Rand      string `json:"rand"`
			PublicKey string `json:"publicKey"`
			Request   string `json:"request"`
			Response  string `json:"response"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}

	for i, r := range report.Responses {
		if r.PublicKey == "" {
			t.Fatalf("link %d: missing publicKey", i)
		}
		if r.Request == "" {
			t.Fatalf("link %d: missing request", i)
		}
		if r.Response == "" {
			t.Fatalf("link %d: missing response", i)
		}
		for _, field := range []string{r.PublicKey, r.Request, r.Response} {
			if _, err := base64.StdEncoding.DecodeString(field); err != nil {
				t.Fatalf("link %d: invalid base64: %v", i, err)
			}
		}
	}
}

// TestParseMalfeasanceReportRejectsEmpty verifies ParseMalfeasanceReport
// rejects an empty responses array.
func TestParseMalfeasanceReportRejectsEmpty(t *testing.T) {
	if _, err := ParseMalfeasanceReport([]byte(`{"responses":[]}`)); err == nil {
		t.Fatal("expected error for empty responses")
	}
}

// TestParseMalfeasanceReportRejectsMalformed verifies ParseMalfeasanceReport
// rejects non-JSON input.
func TestParseMalfeasanceReportRejectsMalformed(t *testing.T) {
	if _, err := ParseMalfeasanceReport([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// TestParseMalfeasanceReportRejectsBadBase64 verifies ParseMalfeasanceReport
// rejects invalid base64 in fields.
func TestParseMalfeasanceReportRejectsBadBase64(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("test"))
	for _, field := range []string{"publicKey", "request", "response"} {
		t.Run(field, func(t *testing.T) {
			entry := map[string]string{
				"publicKey": valid,
				"request":   valid,
				"response":  valid,
			}
			entry[field] = "!!!not-base64!!!"
			data, _ := json.Marshal(map[string]any{"responses": []any{entry}})
			if _, err := ParseMalfeasanceReport(data); err == nil {
				t.Fatalf("expected error for bad %s", field)
			}
		})
	}
}

// TestParseMalfeasanceReportRejectsLegacyLengthMismatch verifies legacy reports
// with mismatched array lengths are rejected.
func TestParseMalfeasanceReportRejectsLegacyLengthMismatch(t *testing.T) {
	data := []byte(`{"nonces":["YQ==","Yg=="],"responses":["YQ=="]}`)
	if _, err := ParseMalfeasanceReport(data); err == nil ||
		!strings.Contains(err.Error(), "length mismatch") {
		t.Fatalf("ParseMalfeasanceReport: %v; want length-mismatch error", err)
	}
}

// TestIsLegacyChainEmpty verifies isLegacyChain returns false for an empty
// chain.
func TestIsLegacyChainEmpty(t *testing.T) {
	var c Chain
	if c.isLegacyChain() {
		t.Fatal("isLegacyChain returned true for empty chain")
	}
}

// TestMalfeasanceReportEmpty verifies MalfeasanceReport rejects an empty chain.
func TestMalfeasanceReportEmpty(t *testing.T) {
	var c Chain
	if _, err := c.MalfeasanceReport(); err == nil {
		t.Fatal("expected error for empty chain")
	}
}

// TestMalfeasanceReportRoundTripDraft10 verifies draft-10 chains emit and
// round-trip the legacy format.
func TestMalfeasanceReportRoundTripDraft10(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe struct {
		Nonces    []string `json:"nonces"`
		Responses []string `json:"responses"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("legacy format unmarshal: %v", err)
	}
	if len(probe.Nonces) != len(c.Links) || len(probe.Responses) != len(c.Links) {
		t.Fatalf("legacy arrays length mismatch: nonces=%d responses=%d want=%d",
			len(probe.Nonces), len(probe.Responses), len(c.Links))
	}
	parsed, err := ParseMalfeasanceReport(data)
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
}

// TestMalfeasanceReportLegacyVerifyFails pins that drafts 10-11 chains cannot
// re-verify after round-trip; the legacy format drops per-link request bytes.
func TestMalfeasanceReportLegacyVerifyFails(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)
	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(); err == nil {
		t.Fatal("expected legacy round-trip Verify to fail")
	}
}

// TestMalfeasanceReportRoundTripDraft12 verifies draft-12 chains round-trip and
// re-verify.
func TestMalfeasanceReportRoundTripDraft12(t *testing.T) {
	c, _ := buildChain(t, VersionDraft12, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatalf("deserialized draft-12 chain should verify: %v", err)
	}
}

// TestParseMalfeasanceReportLegacyFromChain verifies parsing a hand-built
// legacy report produced from a chain.
func TestParseMalfeasanceReportLegacyFromChain(t *testing.T) {
	c, _ := buildChain(t, VersionDraft10, 3)

	nonces := make([]string, len(c.Links))
	responses := make([]string, len(c.Links))
	for i, link := range c.Links {
		if link.Rand != nil {
			nonces[i] = base64.StdEncoding.EncodeToString(link.Rand)
		}
		responses[i] = base64.StdEncoding.EncodeToString(link.Response)
	}
	data, err := json.Marshal(struct {
		Nonces    []string `json:"nonces"`
		Responses []string `json:"responses"`
	}{Nonces: nonces, Responses: responses})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatalf("parse legacy report: %v", err)
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
	}
}

// TestMalfeasanceReportRoundTripDraft14 verifies draft-14 chains round-trip and
// re-verify.
func TestMalfeasanceReportRoundTripDraft14(t *testing.T) {
	c, servers := buildChain(t, VersionDraft12, 3)

	data, err := c.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseMalfeasanceReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Links) != len(c.Links) {
		t.Fatalf("link count = %d, want %d", len(parsed.Links), len(c.Links))
	}
	for i, link := range parsed.Links {
		if !bytes.Equal(link.PublicKey, c.Links[i].PublicKey) {
			t.Fatalf("link %d: public key mismatch", i)
		}
		if !bytes.Equal(link.Request, c.Links[i].Request) {
			t.Fatalf("link %d: request mismatch", i)
		}
		if !bytes.Equal(link.Response, c.Links[i].Response) {
			t.Fatalf("link %d: response mismatch", i)
		}
	}
	_ = servers
	if err := parsed.Verify(); err != nil {
		t.Fatalf("round-tripped draft-14 chain should verify: %v", err)
	}
}

// FuzzParseMalfeasanceReport fuzzes ParseMalfeasanceReport for round-trip
// stability and panic-safety.
func FuzzParseMalfeasanceReport(f *testing.F) {
	validReport, _ := json.Marshal(struct {
		Responses []struct {
			Rand      string `json:"rand,omitempty"`
			PublicKey string `json:"publicKey"`
			Request   string `json:"request"`
			Response  string `json:"response"`
		} `json:"responses"`
	}{
		Responses: []struct {
			Rand      string `json:"rand,omitempty"`
			PublicKey string `json:"publicKey"`
			Request   string `json:"request"`
			Response  string `json:"response"`
		}{
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

	f.Add([]byte("{}"))
	f.Add([]byte(`{"responses":[]}`))
	f.Add([]byte(`{"responses":[{}]}`))
	f.Add([]byte(""))
	f.Add([]byte("null"))
	f.Add([]byte(`{"responses":[{"publicKey":"!!!","request":"!!!","response":"!!!"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		chain, err := ParseMalfeasanceReport(data)
		if err != nil {
			return
		}
		out, err := chain.MalfeasanceReport()
		if err != nil {
			return
		}
		chain2, err := ParseMalfeasanceReport(out)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if len(chain2.Links) != len(chain.Links) {
			t.Fatalf("link count mismatch: %d vs %d", len(chain2.Links), len(chain.Links))
		}
		for i := range chain.Links {
			if !bytes.Equal(chain.Links[i].Rand, chain2.Links[i].Rand) {
				t.Fatalf("link %d rand mismatch", i)
			}
			if !bytes.Equal(chain.Links[i].PublicKey, chain2.Links[i].PublicKey) {
				t.Fatalf("link %d publicKey mismatch", i)
			}
			if !bytes.Equal(chain.Links[i].Request, chain2.Links[i].Request) {
				t.Fatalf("link %d request mismatch", i)
			}
			if !bytes.Equal(chain.Links[i].Response, chain2.Links[i].Response) {
				t.Fatalf("link %d response mismatch", i)
			}
		}
	})
}

// TestParseMalfeasanceReportLegacy verifies ParseMalfeasanceReport decodes a
// legacy report.
func TestParseMalfeasanceReportLegacy(t *testing.T) {
	legacy := []byte(`{"nonces":["","` +
		base64.StdEncoding.EncodeToString(make([]byte, 32)) +
		`"],"responses":["` +
		base64.StdEncoding.EncodeToString([]byte("resp1")) +
		`","` +
		base64.StdEncoding.EncodeToString([]byte("resp2")) +
		`"]}`)
	chain, err := ParseMalfeasanceReport(legacy)
	if err != nil {
		t.Fatalf("parse legacy report: %v", err)
	}
	if len(chain.Links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(chain.Links))
	}
	if chain.Links[0].Rand != nil {
		t.Error("first link rand should be nil")
	}
	if len(chain.Links[1].Rand) != 32 {
		t.Errorf("second link rand length = %d, want 32", len(chain.Links[1].Rand))
	}
	if !bytes.Equal(chain.Links[0].Response, []byte("resp1")) {
		t.Error("first response mismatch")
	}
	if !bytes.Equal(chain.Links[1].Response, []byte("resp2")) {
		t.Error("second response mismatch")
	}
	if chain.Links[0].Request != nil || chain.Links[0].PublicKey != nil {
		t.Error("legacy link should have nil Request and PublicKey")
	}
}

// TestParseMalfeasanceReportLegacyLengthMismatch verifies legacy reports with
// mismatched array lengths are rejected.
func TestParseMalfeasanceReportLegacyLengthMismatch(t *testing.T) {
	legacy := []byte(`{"nonces":["",""],"responses":["` +
		base64.StdEncoding.EncodeToString([]byte("x")) + `"]}`)
	if _, err := ParseMalfeasanceReport(legacy); err == nil {
		t.Fatal("expected length mismatch error")
	}
}

// TestParseMalfeasanceReportRejectsTooManyLinks verifies ParseMalfeasanceReport
// rejects more than maxChainLinks entries.
func TestParseMalfeasanceReportRejectsTooManyLinks(t *testing.T) {
	const n = 1025
	entries := make([]string, n)
	for i := range entries {
		entries[i] = `""`
	}
	data := []byte(`{"nonces":[` + joinStrings(entries) + `],"responses":[` + joinStrings(entries) + `]}`)
	if _, err := ParseMalfeasanceReport(data); err == nil {
		t.Fatal("expected error for too many links")
	}
}

// joinStrings joins parts with commas without importing strings.
func joinStrings(parts []string) string {
	var b []byte
	for i, p := range parts {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, p...)
	}
	return string(b)
}

// TestParseMalfeasanceReportLegacyBadBase64 verifies legacy reports with bad
// base64 nonces or responses are rejected.
func TestParseMalfeasanceReportLegacyBadBase64(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("ok"))
	t.Run("nonce", func(t *testing.T) {
		data := []byte(`{"nonces":["!!!"],"responses":["` + good + `"]}`)
		if _, err := ParseMalfeasanceReport(data); err == nil {
			t.Fatal("expected error for bad legacy nonce")
		}
	})
	t.Run("response", func(t *testing.T) {
		data := []byte(`{"nonces":["` + good + `"],"responses":["!!!"]}`)
		if _, err := ParseMalfeasanceReport(data); err == nil {
			t.Fatal("expected error for bad legacy response")
		}
	})
}

// TestParseMalfeasanceReportRejectsBadRand verifies ParseMalfeasanceReport
// rejects bad base64 in the rand field.
func TestParseMalfeasanceReportRejectsBadRand(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("ok"))
	entry := map[string]string{
		"rand":      "!!!not-base64!!!",
		"publicKey": good,
		"request":   good,
		"response":  good,
	}
	data, _ := json.Marshal(map[string]any{"responses": []any{entry}})
	if _, err := ParseMalfeasanceReport(data); err == nil {
		t.Fatal("expected error for bad rand")
	}
}
