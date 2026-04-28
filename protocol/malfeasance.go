// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// maxMalfeasanceReportBytes caps the in-memory report size at 4 MiB.
const maxMalfeasanceReportBytes = 4 * 1024 * 1024

// malfeasanceReport is the drafts-12+ JSON report shape.
type malfeasanceReport struct {
	Responses []malfeasanceLink `json:"responses"`
}

// malfeasanceLink is one chain entry in a drafts-12+ report.
type malfeasanceLink struct {
	Rand      string `json:"rand,omitempty"`
	PublicKey string `json:"publicKey"`
	Request   string `json:"request"`
	Response  string `json:"response"`
}

// malfeasanceReportLegacy is the drafts 10-11 parallel-array format.
type malfeasanceReportLegacy struct {
	Nonces    []string `json:"nonces"`
	Responses []string `json:"responses"`
}

// MalfeasanceReport serializes the chain as JSON, picking legacy or drafts-12+
// format by version.
func (c *Chain) MalfeasanceReport() ([]byte, error) {
	if len(c.Links) == 0 {
		return nil, errors.New("protocol: empty chain")
	}
	if c.isLegacyChain() {
		return c.marshalLegacyReport()
	}
	report := malfeasanceReport{
		Responses: make([]malfeasanceLink, len(c.Links)),
	}
	for i, link := range c.Links {
		ml := malfeasanceLink{
			PublicKey: base64.StdEncoding.EncodeToString(link.PublicKey),
			Request:   base64.StdEncoding.EncodeToString(link.Request),
			Response:  base64.StdEncoding.EncodeToString(link.Response),
		}
		if link.Rand != nil {
			ml.Rand = base64.StdEncoding.EncodeToString(link.Rand)
		}
		report.Responses[i] = ml
	}
	return json.Marshal(report)
}

// isLegacyChain reports whether every link is groupD10, requiring the legacy
// report format.
func (c *Chain) isLegacyChain() bool {
	if len(c.Links) == 0 {
		return false
	}
	for _, link := range c.Links {
		ver, ok := ExtractVersion(link.Response)
		if !ok {
			return false
		}
		if wireGroupOf(ver, false) != groupD10 {
			return false
		}
	}
	return true
}

// marshalLegacyReport serializes the chain in the drafts 10-11 format.
func (c *Chain) marshalLegacyReport() ([]byte, error) {
	report := malfeasanceReportLegacy{
		Nonces:    make([]string, len(c.Links)),
		Responses: make([]string, len(c.Links)),
	}
	for i, link := range c.Links {
		if link.Rand != nil {
			report.Nonces[i] = base64.StdEncoding.EncodeToString(link.Rand)
		}
		report.Responses[i] = base64.StdEncoding.EncodeToString(link.Response)
	}
	return json.Marshal(report)
}

// ParseMalfeasanceReport deserializes a JSON malfeasance report into a Chain.
func ParseMalfeasanceReport(data []byte) (*Chain, error) {
	if len(data) > maxMalfeasanceReportBytes {
		return nil, fmt.Errorf("protocol: malfeasance report is %d bytes (max %d)", len(data), maxMalfeasanceReportBytes)
	}
	// legacy: top-level "nonces" with string entries; drafts-12+: object
	// entries
	var probe struct {
		Nonces    json.RawMessage   `json:"nonces"`
		Responses []json.RawMessage `json:"responses"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("protocol: parse malfeasance report: %w", err)
	}
	if len(probe.Responses) == 0 {
		return nil, errors.New("protocol: malfeasance report has no responses")
	}
	if len(probe.Responses) > maxChainLinks {
		return nil, fmt.Errorf("protocol: malfeasance report has %d links (max %d)", len(probe.Responses), maxChainLinks)
	}
	legacy := len(probe.Nonces) > 0 && len(probe.Responses[0]) > 0 && probe.Responses[0][0] == '"'

	if legacy {
		var report malfeasanceReportLegacy
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("protocol: parse legacy malfeasance report: %w", err)
		}
		if len(report.Nonces) != len(report.Responses) {
			return nil, fmt.Errorf("protocol: legacy report nonces/responses length mismatch (%d vs %d)", len(report.Nonces), len(report.Responses))
		}
		c := &Chain{Links: make([]ChainLink, len(report.Responses))}
		for i := range report.Responses {
			var err error
			if report.Nonces[i] != "" {
				if c.Links[i].Rand, err = base64.StdEncoding.DecodeString(report.Nonces[i]); err != nil {
					return nil, fmt.Errorf("protocol: legacy report link %d: decode nonce: %w", i, err)
				}
			}
			if c.Links[i].Response, err = base64.StdEncoding.DecodeString(report.Responses[i]); err != nil {
				return nil, fmt.Errorf("protocol: legacy report link %d: decode response: %w", i, err)
			}
		}
		return c, nil
	}

	var report malfeasanceReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("protocol: parse malfeasance report: %w", err)
	}

	c := &Chain{Links: make([]ChainLink, len(report.Responses))}
	for i, ml := range report.Responses {
		var err error

		if ml.Rand != "" {
			if c.Links[i].Rand, err = base64.StdEncoding.DecodeString(ml.Rand); err != nil {
				return nil, fmt.Errorf("protocol: report link %d: decode rand: %w", i, err)
			}
		}
		if c.Links[i].PublicKey, err = base64.StdEncoding.DecodeString(ml.PublicKey); err != nil {
			return nil, fmt.Errorf("protocol: report link %d: decode publicKey: %w", i, err)
		}
		if c.Links[i].Request, err = base64.StdEncoding.DecodeString(ml.Request); err != nil {
			return nil, fmt.Errorf("protocol: report link %d: decode request: %w", i, err)
		}
		if c.Links[i].Response, err = base64.StdEncoding.DecodeString(ml.Response); err != nil {
			return nil, fmt.Errorf("protocol: report link %d: decode response: %w", i, err)
		}
	}

	return c, nil
}
