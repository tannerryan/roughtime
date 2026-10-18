// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// maxMalfeasanceReportBytes caps accepted and emitted JSON at 4 MiB.
const maxMalfeasanceReportBytes = 4 * 1024 * 1024

// boundedReportArray caps each report array before decoding too many entries.
type boundedReportArray[T any] []T

// UnmarshalJSON preserves array decoding while enforcing MaxChainLinks early.
func (entries *boundedReportArray[T]) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		*entries = nil
		return nil
	}
	if token != json.Delim('[') {
		return errors.New("protocol: report field must be an array")
	}
	*entries = (*entries)[:0]
	for decoder.More() {
		if len(*entries) == MaxChainLinks {
			return fmt.Errorf("protocol: malfeasance report has more than %d links (max %d)", MaxChainLinks, MaxChainLinks)
		}
		var entry T
		if err := decoder.Decode(&entry); err != nil {
			return err
		}
		*entries = append(*entries, entry)
	}
	_, err = decoder.Token()
	return err
}

// malfeasanceReport is the modern JSON report shape.
type malfeasanceReport struct {
	Responses boundedReportArray[malfeasanceLink] `json:"responses"`
}

// malfeasanceLink is one modern report entry.
type malfeasanceLink struct {
	Rand      string `json:"rand,omitempty"`
	PublicKey string `json:"publicKey"`
	Request   string `json:"request"`
	Response  string `json:"response"`
}

// malfeasanceReportLegacy is the drafts 08-11 parallel-array format.
type malfeasanceReportLegacy struct {
	Nonces    boundedReportArray[string] `json:"nonces"`
	Responses boundedReportArray[string] `json:"responses"`
}

// malfeasanceLinkEarly is the drafts 01-03 array-entry format. Blind belongs to
// the response that precedes the request derived from it.
type malfeasanceLinkEarly struct {
	Blind          string `json:"blind,omitempty"`
	ResponsePacket string `json:"response_packet"`
}

// malfeasanceFormat identifies a historical report encoding.
type malfeasanceFormat uint8

const (
	// malfeasanceFormatEarly is the drafts 01-03 array form.
	malfeasanceFormatEarly malfeasanceFormat = iota
	// malfeasanceFormatLegacy is the drafts 08-11 parallel-array form.
	malfeasanceFormatLegacy
	// malfeasanceFormatModern is the self-contained object form.
	malfeasanceFormatModern
)

// MalfeasanceReport serializes an RFC report in strict mode. Flex mode selects
// the draft-01/03 array or draft-08/11 parallel arrays when applicable. Other
// chains use self-contained response objects.
func (c *Chain) MalfeasanceReport() ([]byte, error) {
	if c.Mode != Strict && c.Mode != Flex {
		return nil, errors.New("protocol: invalid mode")
	}
	if len(c.Links) == 0 {
		return nil, errors.New("protocol: empty chain")
	}
	if len(c.Links) > MaxChainLinks {
		return nil, fmt.Errorf("protocol: chain has %d links (max %d)", len(c.Links), MaxChainLinks)
	}
	format := malfeasanceFormatModern
	if c.Mode == Flex {
		format = c.inferMalfeasanceFormat()
	} else if err := validateRFCReportLinks(c.Links); err != nil {
		return nil, err
	}
	if err := validateMalfeasanceLinks(c.Links, format); err != nil {
		return nil, err
	}
	switch format {
	case malfeasanceFormatEarly:
		return c.marshalEarlyReport()
	case malfeasanceFormatLegacy:
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
	return marshalMalfeasanceJSON(report)
}

// validateMalfeasanceLinks prevents emitting a report that this package's
// parser would immediately reject.
func validateMalfeasanceLinks(links []ChainLink, format malfeasanceFormat) error {
	for i, link := range links {
		if len(link.Response) == 0 {
			return fmt.Errorf("protocol: malfeasance link %d: missing response", i)
		}
		switch format {
		case malfeasanceFormatModern:
			if len(link.PublicKey) == 0 || len(link.Request) == 0 {
				return fmt.Errorf("protocol: malfeasance link %d: missing public key or request", i)
			}
			if i > 0 && len(link.Rand) == 0 {
				return fmt.Errorf("protocol: malfeasance link %d: missing rand", i)
			}
			if len(link.Rand) != 0 && len(link.Rand) != 32 && len(link.Rand) != 64 {
				return fmt.Errorf("protocol: malfeasance link %d: rand is %d bytes, want 32 or 64", i, len(link.Rand))
			}
		case malfeasanceFormatLegacy:
			if i > 0 && len(link.Rand) != 32 {
				return fmt.Errorf("protocol: malfeasance link %d: nonce is %d bytes, want 32", i, len(link.Rand))
			}
		case malfeasanceFormatEarly:
			if i > 0 && len(link.Rand) != 64 {
				return fmt.Errorf("protocol: malfeasance link %d: blind is %d bytes, want 64", i, len(link.Rand))
			}
		}
	}
	return nil
}

// inferMalfeasanceFormat selects a draft format for homogeneous chains. Mixed
// chains and drafts 04-07 use self-contained response objects.
func (c *Chain) inferMalfeasanceFormat() malfeasanceFormat {
	early, legacy := len(c.Links) > 0, len(c.Links) > 0
	for _, link := range c.Links {
		ver, ok := ExtractVersion(link.Response)
		if !ok {
			return malfeasanceFormatModern
		}
		early = early && ver >= VersionDraft01 && ver <= VersionDraft03
		legacy = legacy && ver >= VersionDraft08 && ver <= VersionDraft11
	}
	if early {
		return malfeasanceFormatEarly
	}
	if legacy {
		return malfeasanceFormatLegacy
	}
	return malfeasanceFormatModern
}

// marshalEarlyReport serializes the drafts 01-03 array format. ChainLink.Rand
// belongs to the current request, while the historical "blind" field belongs to
// the preceding response, hence the one-position shift.
func (c *Chain) marshalEarlyReport() ([]byte, error) {
	report := make([]malfeasanceLinkEarly, len(c.Links))
	for i, link := range c.Links {
		report[i].ResponsePacket = base64.StdEncoding.EncodeToString(link.Response)
		if i+1 < len(c.Links) && c.Links[i+1].Rand != nil {
			report[i].Blind = base64.StdEncoding.EncodeToString(c.Links[i+1].Rand)
		}
	}
	return marshalMalfeasanceJSON(report)
}

// marshalLegacyReport serializes the chain in the drafts 08-11 format.
func (c *Chain) marshalLegacyReport() ([]byte, error) {
	report := malfeasanceReportLegacy{
		Nonces:    make([]string, len(c.Links)-1),
		Responses: make([]string, len(c.Links)),
	}
	for i, link := range c.Links {
		if i > 0 {
			report.Nonces[i-1] = base64.StdEncoding.EncodeToString(link.Rand)
		}
		report.Responses[i] = base64.StdEncoding.EncodeToString(link.Response)
	}
	return marshalMalfeasanceJSON(report)
}

// marshalMalfeasanceJSON encodes a size-bounded report.
func marshalMalfeasanceJSON(report any) ([]byte, error) {
	data, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	if len(data) > maxMalfeasanceReportBytes {
		return nil, fmt.Errorf("protocol: malfeasance report is %d bytes (max %d)", len(data), maxMalfeasanceReportBytes)
	}
	return data, nil
}

// ParseMalfeasanceReport parses RFC report structure into a strict Chain. Call
// [Chain.Verify] to authenticate the evidence.
func ParseMalfeasanceReport(data []byte) (*Chain, error) {
	return ParseMalfeasanceReportWithMode(data, Strict)
}

// ParseMalfeasanceReportWithMode parses a report without authenticating its
// evidence.
func ParseMalfeasanceReportWithMode(data []byte, mode Mode) (*Chain, error) {
	if mode != Strict && mode != Flex {
		return nil, errors.New("protocol: invalid mode")
	}
	chain, err := parseMalfeasanceReport(data, mode)
	if err != nil {
		return nil, err
	}
	chain.Mode = mode
	if mode == Strict {
		if err := validateRFCReportLinks(chain.Links); err != nil {
			return nil, err
		}
	}
	return chain, nil
}

// validateRFCReportLinks checks RFC key sizes, blinding values, and packet
// forms.
func validateRFCReportLinks(links []ChainLink) error {
	for i, link := range links {
		if len(link.PublicKey) != 32 || (len(link.Rand) != 32 && (i > 0 || len(link.Rand) != 0)) {
			return fmt.Errorf("protocol: report link %d has invalid key or rand", i)
		}
		if _, err := ParseRequest(link.Request); err != nil {
			return fmt.Errorf("protocol: report link %d: %w", i, err)
		}
		if _, err := unwrapPacket(link.Response); err != nil {
			return fmt.Errorf("protocol: report link %d: %w", i, err)
		}
		if version, ok := ExtractVersion(link.Response); !ok || version != Version1 {
			return fmt.Errorf("protocol: report link %d does not contain an RFC response", i)
		}
	}
	return nil
}

// parseMalfeasanceReport decodes RFC reports and flex legacy formats.
func parseMalfeasanceReport(data []byte, mode Mode) (*Chain, error) {
	if len(data) > maxMalfeasanceReportBytes {
		return nil, fmt.Errorf("protocol: malfeasance report is %d bytes (max %d)", len(data), maxMalfeasanceReportBytes)
	}
	if mode == Strict && !utf8.Valid(data) {
		return nil, errors.New("protocol: malfeasance report is not valid UTF-8")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("protocol: empty malfeasance report")
	}
	if trimmed[0] == '[' {
		if mode != Flex {
			return nil, errors.New("protocol: array reports require flex mode")
		}
		return parseEarlyMalfeasanceReport(trimmed)
	}
	// probe distinguishes legacy string arrays from modern object entries.
	var probe struct {
		Nonces    json.RawMessage                     `json:"nonces"`
		Responses boundedReportArray[json.RawMessage] `json:"responses"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("protocol: parse malfeasance report: %w", err)
	}
	if len(probe.Responses) == 0 {
		return nil, errors.New("protocol: malfeasance report has no responses")
	}
	if len(probe.Responses) > MaxChainLinks {
		return nil, fmt.Errorf("protocol: malfeasance report has %d links (max %d)", len(probe.Responses), MaxChainLinks)
	}
	legacy := len(probe.Nonces) > 0 && len(probe.Responses[0]) > 0 && probe.Responses[0][0] == '"'

	if legacy {
		if mode != Flex {
			return nil, errors.New("protocol: parallel-array reports require flex mode")
		}
		var report malfeasanceReportLegacy
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("protocol: parse legacy malfeasance report: %w", err)
		}
		canonical := len(report.Nonces) == len(report.Responses)-1
		compatible := len(report.Nonces) == len(report.Responses) && report.Nonces[0] == ""
		if !canonical && !compatible {
			return nil, fmt.Errorf("protocol: legacy report has %d nonces for %d responses", len(report.Nonces), len(report.Responses))
		}
		c := &Chain{Links: make([]ChainLink, len(report.Responses))}
		for i := range report.Responses {
			var err error
			if c.Links[i].Response, err = base64.StdEncoding.DecodeString(report.Responses[i]); err != nil {
				return nil, fmt.Errorf("protocol: legacy report link %d: decode response: %w", i, err)
			}
		}
		start := 0
		if compatible {
			start = 1
		}
		for i := start; i < len(report.Nonces); i++ {
			link := i + 1 - start
			if report.Nonces[i] == "" {
				return nil, fmt.Errorf("protocol: legacy report link %d: missing nonce", link)
			}
			var err error
			c.Links[link].Rand, err = base64.StdEncoding.DecodeString(report.Nonces[i])
			if err != nil {
				return nil, fmt.Errorf("protocol: legacy report link %d: decode nonce: %w", link, err)
			}
			if len(c.Links[link].Rand) != 32 {
				return nil, fmt.Errorf("protocol: legacy report link %d: nonce is %d bytes, want 32", link, len(c.Links[link].Rand))
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

		if i > 0 && ml.Rand == "" {
			return nil, fmt.Errorf("protocol: report link %d: missing rand", i)
		}
		if ml.PublicKey == "" {
			return nil, fmt.Errorf("protocol: report link %d: missing publicKey", i)
		}
		if ml.Request == "" {
			return nil, fmt.Errorf("protocol: report link %d: missing request", i)
		}
		if ml.Response == "" {
			return nil, fmt.Errorf("protocol: report link %d: missing response", i)
		}
		if ml.Rand != "" {
			if c.Links[i].Rand, err = base64.StdEncoding.DecodeString(ml.Rand); err != nil {
				return nil, fmt.Errorf("protocol: report link %d: decode rand: %w", i, err)
			}
			if len(c.Links[i].Rand) != 32 && len(c.Links[i].Rand) != 64 {
				return nil, fmt.Errorf("protocol: report link %d: rand is %d bytes, want 32 or 64", i, len(c.Links[i].Rand))
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

// parseEarlyMalfeasanceReport parses the drafts 01-03 array format and shifts
// each blind onto the following ChainLink.Rand field.
func parseEarlyMalfeasanceReport(data []byte) (*Chain, error) {
	var report boundedReportArray[malfeasanceLinkEarly]
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("protocol: parse early malfeasance report: %w", err)
	}
	if len(report) == 0 {
		return nil, errors.New("protocol: malfeasance report has no responses")
	}
	if len(report) > MaxChainLinks {
		return nil, fmt.Errorf("protocol: malfeasance report has %d links (max %d)", len(report), MaxChainLinks)
	}
	c := &Chain{Links: make([]ChainLink, len(report))}
	for i, entry := range report {
		if entry.ResponsePacket == "" {
			return nil, fmt.Errorf("protocol: early report link %d: missing response_packet", i)
		}
		response, err := base64.StdEncoding.DecodeString(entry.ResponsePacket)
		if err != nil {
			return nil, fmt.Errorf("protocol: early report link %d: decode response_packet: %w", i, err)
		}
		c.Links[i].Response = response
		if i+1 == len(report) {
			if entry.Blind == "" {
				continue
			}
			return nil, errors.New("protocol: last early report link must not contain blind")
		}
		if entry.Blind == "" {
			return nil, fmt.Errorf("protocol: early report link %d: missing blind", i)
		}
		blind, err := base64.StdEncoding.DecodeString(entry.Blind)
		if err != nil {
			return nil, fmt.Errorf("protocol: early report link %d: decode blind: %w", i, err)
		}
		if len(blind) != 64 {
			return nil, fmt.Errorf("protocol: early report link %d: blind is %d bytes, want 64", i, len(blind))
		}
		c.Links[i+1].Rand = blind
	}
	return c, nil
}
