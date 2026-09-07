// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

// MaxEcosystemServers caps the size of a parsed ecosystem file.
const MaxEcosystemServers = 1024

// MaxEcosystemBytes caps ecosystem JSON accepted by ParseEcosystem.
const MaxEcosystemBytes = 4 * 1024 * 1024

// ecosystemFile is the top-level JSON shape of a Roughtime ecosystem document.
type ecosystemFile struct {
	Servers []ecosystemServer `json:"servers"`
}

// ecosystemServer is one entry in an ecosystem document.
type ecosystemServer struct {
	Name          string             `json:"name"`
	Version       flexString         `json:"version"`
	PublicKeyType string             `json:"publicKeyType"`
	PublicKey     string             `json:"publicKey"`
	Addresses     []ecosystemAddress `json:"addresses"`
}

// ecosystemAddress is one transport-tagged address from an ecosystem entry.
type ecosystemAddress struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

// flexString decodes a JSON field that may be either a string or an integer.
type flexString string

// googleEcosystemVersion is the numeric Google-Roughtime label.
const googleEcosystemVersion = "3000600613"

// UnmarshalJSON accepts a JSON string or non-negative integer (uint32 range)
// and stringifies integers.
func (v *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = flexString(s)
		return nil
	}
	var n uint32
	if err := json.Unmarshal(b, &n); err == nil {
		*v = flexString(fmt.Sprintf("%d", n))
		return nil
	}
	return fmt.Errorf("version must be a string or integer, got %s", SanitizeForDisplay(truncateForErr(string(b))))
}

// MarshalJSON preserves numeric server-list versions as JSON integers while
// retaining legacy textual labels used by existing ecosystem files.
func (v flexString) MarshalJSON() ([]byte, error) {
	s := string(v)
	if n, err := strconv.ParseUint(s, 10, 32); err == nil && strconv.FormatUint(n, 10) == s {
		return []byte(s), nil
	}
	return json.Marshal(s)
}

// ParseEcosystem decodes and structurally validates a JSON server list. Use
// [NormalizeServer] to check client compatibility and order endpoints. Semantic
// fields containing characters removed by [SanitizeForDisplay] are rejected
// rather than rewritten.
func ParseEcosystem(data []byte) ([]Server, error) {
	if len(data) > MaxEcosystemBytes {
		return nil, fmt.Errorf("roughtime: ecosystem is %d bytes (max %d)", len(data), MaxEcosystemBytes)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("roughtime: ecosystem is not valid UTF-8")
	}
	var f ecosystemFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("roughtime: parsing ecosystem: %w", err)
	}
	if len(f.Servers) == 0 {
		return nil, errors.New("roughtime: ecosystem has no servers")
	}
	if len(f.Servers) > MaxEcosystemServers {
		return nil, fmt.Errorf("roughtime: ecosystem has %d entries (max %d)", len(f.Servers), MaxEcosystemServers)
	}
	out := make([]Server, 0, len(f.Servers))
	for i, es := range f.Servers {
		if err := validateSemanticField("name", es.Name); err != nil {
			return nil, fmt.Errorf("roughtime: server %d: %w", i, err)
		}
		if err := validateSemanticField("version", string(es.Version)); err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(es.Name), err)
		}
		if err := validateSemanticField("publicKeyType", es.PublicKeyType); err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(es.Name), err)
		}
		pk, err := DecodePublicKey(es.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(es.Name), err)
		}
		if es.PublicKeyType != "" {
			sch, _ := SchemeOfKey(pk) // length already validated by DecodePublicKey
			want := publicKeyTypeFor(sch)
			if !strings.EqualFold(es.PublicKeyType, want) {
				return nil, fmt.Errorf("roughtime: server %d (%s): publicKeyType %q does not match decoded key (expected %q)",
					i, SanitizeForDisplay(es.Name), SanitizeForDisplay(es.PublicKeyType), want)
			}
		}
		if len(es.Addresses) == 0 {
			return nil, fmt.Errorf("roughtime: server %d (%s): no addresses", i, SanitizeForDisplay(es.Name))
		}
		addrs := make([]Address, 0, len(es.Addresses))
		for _, a := range es.Addresses {
			if err := validateSemanticField("transport", a.Protocol); err != nil {
				return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(es.Name), err)
			}
			t := strings.ToLower(a.Protocol)
			if t != "udp" && t != "tcp" {
				return nil, fmt.Errorf("roughtime: server %d (%s): unsupported transport %q", i, SanitizeForDisplay(es.Name), SanitizeForDisplay(a.Protocol))
			}
			if err := validateEndpoint(a.Address); err != nil {
				return nil, fmt.Errorf("roughtime: server %d (%s): bad address %q: %w", i, SanitizeForDisplay(es.Name), SanitizeForDisplay(a.Address), err)
			}
			addrs = append(addrs, Address{Transport: t, Address: a.Address})
		}
		s := Server{
			Name:      es.Name,
			Version:   string(es.Version),
			PublicKey: pk,
			Addresses: addrs,
		}
		out = append(out, s)
	}
	return out, nil
}

// SampleByOperator returns up to n servers, at most one per [OperatorKey].
// OperatorKey is an endpoint-domain heuristic, not an authenticated ownership
// identity, so callers must not treat this function alone as Sybil resistance.
// Fewer than n are returned when endpoint-domain groups are scarce.
func SampleByOperator(servers []Server, n int) []Server {
	if n <= 0 {
		return nil
	}
	groups := map[string][]Server{}
	order := make([]string, 0, len(servers))
	for _, s := range servers {
		k := OperatorKey(s)
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], s)
	}
	mrand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	out := make([]Server, 0, min(n, len(order)))
	for _, k := range order {
		if len(out) == n {
			break
		}
		g := groups[k]
		out = append(out, g[mrand.IntN(len(g))])
	}
	return out
}

// OperatorKey returns an endpoint-domain grouping key for s. It uses the
// primary address's registered domain (eTLD+1), or its bare host for an IP
// literal or single-label name. With no address it uses Name. The result is not
// authenticated operator identity.
func OperatorKey(s Server) string {
	if len(s.Addresses) == 0 {
		return strings.ToLower(strings.TrimSuffix(s.Name, "."))
	}
	host, _, err := net.SplitHostPort(s.Addresses[0].Address)
	if err != nil {
		host = s.Addresses[0].Address
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	if reg, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return reg
	}
	return host
}

// MarshalEcosystem serializes servers as ecosystem JSON.
func MarshalEcosystem(servers []Server) ([]byte, error) {
	if len(servers) == 0 {
		return nil, errors.New("roughtime: ecosystem has no servers")
	}
	if len(servers) > MaxEcosystemServers {
		return nil, fmt.Errorf("roughtime: %d servers exceeds max %d", len(servers), MaxEcosystemServers)
	}
	out := ecosystemFile{Servers: make([]ecosystemServer, 0, len(servers))}
	for i, s := range servers {
		if err := validateSemanticField("name", s.Name); err != nil {
			return nil, fmt.Errorf("roughtime: server %d: %w", i, err)
		}
		if err := validateSemanticField("version", s.Version); err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(s.Name), err)
		}
		sch, err := SchemeOfKey(s.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(s.Name), err)
		}
		if len(s.Addresses) == 0 {
			return nil, fmt.Errorf("roughtime: server %d (%s): no addresses", i, SanitizeForDisplay(s.Name))
		}
		addrs := make([]ecosystemAddress, 0, len(s.Addresses))
		for _, a := range s.Addresses {
			if err := validateSemanticField("transport", a.Transport); err != nil {
				return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(s.Name), err)
			}
			t := strings.ToLower(a.Transport)
			if t != "udp" && t != "tcp" {
				return nil, fmt.Errorf("roughtime: server %d (%s): unsupported transport %q", i, SanitizeForDisplay(s.Name), SanitizeForDisplay(a.Transport))
			}
			if err := validateEndpoint(a.Address); err != nil {
				return nil, fmt.Errorf("roughtime: server %d (%s): bad address %q: %w", i, SanitizeForDisplay(s.Name), SanitizeForDisplay(a.Address), err)
			}
			addrs = append(addrs, ecosystemAddress{Protocol: t, Address: a.Address})
		}
		out.Servers = append(out.Servers, ecosystemServer{
			Name:          s.Name,
			Version:       flexString(s.Version),
			PublicKeyType: publicKeyTypeFor(sch),
			PublicKey:     base64.StdEncoding.EncodeToString(s.PublicKey),
			Addresses:     addrs,
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(data) > MaxEcosystemBytes {
		return nil, fmt.Errorf("roughtime: encoded ecosystem is %d bytes (max %d)", len(data), MaxEcosystemBytes)
	}
	return data, nil
}

// validateSemanticField rejects semantic strings that would change when made
// safe for terminal display.
func validateSemanticField(name, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if SanitizeForDisplay(value) != value {
		return fmt.Errorf("%s contains control, line/paragraph separator, or disallowed format characters", name)
	}
	return nil
}

// validateEndpoint accepts a host and numeric TCP/UDP port.
func validateEndpoint(endpoint string) error {
	if err := validateSemanticField("address", endpoint); err != nil {
		return err
	}
	if strings.TrimSpace(endpoint) != endpoint {
		return errors.New("leading or trailing whitespace")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	if host == "" {
		return errors.New("empty host")
	}
	if strings.Contains(host, "%") {
		return errors.New("IPv6 zone identifiers are not allowed")
	}
	if port == "" {
		return errors.New("empty port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return fmt.Errorf("invalid numeric port %q", port)
	}
	return nil
}

// isGoogleEcosystemVersion recognizes both the legacy label and the numeric
// pre-IETF version assigned by the server-list specification.
func isGoogleEcosystemVersion(version string) bool {
	return strings.EqualFold(version, VersionLabelGoogle) || version == googleEcosystemVersion
}

// publicKeyTypeFor returns the ecosystem-file label for sch.
func publicKeyTypeFor(sch Scheme) string {
	switch sch {
	case SchemeMLDSA44:
		return "ml-dsa-44"
	default:
		return "ed25519"
	}
}

// SanitizeForDisplay strips ASCII and C1 controls, Unicode line and paragraph
// separators, and selected bidi or zero-width format characters from untrusted
// display strings. It preserves ordinary Unicode spaces, including nonbreaking
// spaces.
func SanitizeForDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
			return -1
		case r >= 0x80 && r <= 0x9f:
			return -1
		case r == 0x061C:
			return -1
		case r >= 0x200B && r <= 0x200F:
			return -1
		case r == 0x2028 || r == 0x2029:
			return -1
		case r >= 0x202A && r <= 0x202E:
			return -1
		case r >= 0x2066 && r <= 0x2069:
			return -1
		}
		return r
	}, s)
}
