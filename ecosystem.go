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
	"strings"

	"golang.org/x/net/publicsuffix"
)

// MaxEcosystemServers caps the size of a parsed ecosystem file.
const MaxEcosystemServers = 1024

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
	return fmt.Errorf("version must be a string or integer, got %s", string(b))
}

// ParseEcosystem decodes a JSON server list into [Server] values with decoded
// keys and sanitized strings.
func ParseEcosystem(data []byte) ([]Server, error) {
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
			t := strings.ToLower(a.Protocol)
			if t != "udp" && t != "tcp" {
				return nil, fmt.Errorf("roughtime: server %d (%s): unsupported transport %q", i, SanitizeForDisplay(es.Name), SanitizeForDisplay(a.Protocol))
			}
			addrs = append(addrs, Address{Transport: t, Address: SanitizeForDisplay(a.Address)})
		}
		out = append(out, Server{
			Name:      SanitizeForDisplay(es.Name),
			Version:   string(es.Version),
			PublicKey: pk,
			Addresses: addrs,
		})
	}
	return out, nil
}

// SampleByOperator returns up to n servers, at most one per operator (grouped
// by [OperatorKey]), so no operator can dominate the consensus median however
// many entries it registers. Operators, and the server within each, are chosen
// at random. Fewer than n are returned when operators are scarce.
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
	out := make([]Server, 0, n)
	for _, k := range order {
		if len(out) == n {
			break
		}
		g := groups[k]
		out = append(out, g[mrand.IntN(len(g))])
	}
	return out
}

// OperatorKey identifies a server's operator by the registered domain (eTLD+1)
// of its primary address, falling back to the bare host for IP literals and
// single-label names.
func OperatorKey(s Server) string {
	if len(s.Addresses) == 0 {
		return s.Name
	}
	host, _, err := net.SplitHostPort(s.Addresses[0].Address)
	if err != nil {
		host = s.Addresses[0].Address
	}
	host = strings.ToLower(host)
	if reg, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return reg
	}
	return host
}

// MarshalEcosystem serializes servers as ecosystem JSON. Empty input produces a
// doc [ParseEcosystem] rejects.
func MarshalEcosystem(servers []Server) ([]byte, error) {
	if len(servers) > MaxEcosystemServers {
		return nil, fmt.Errorf("roughtime: %d servers exceeds max %d", len(servers), MaxEcosystemServers)
	}
	out := ecosystemFile{Servers: make([]ecosystemServer, 0, len(servers))}
	for i, s := range servers {
		sch, err := SchemeOfKey(s.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("roughtime: server %d (%s): %w", i, SanitizeForDisplay(s.Name), err)
		}
		addrs := make([]ecosystemAddress, 0, len(s.Addresses))
		for _, a := range s.Addresses {
			addrs = append(addrs, ecosystemAddress{Protocol: a.Transport, Address: SanitizeForDisplay(a.Address)})
		}
		out.Servers = append(out.Servers, ecosystemServer{
			Name:          SanitizeForDisplay(s.Name),
			Version:       flexString(s.Version),
			PublicKeyType: publicKeyTypeFor(sch),
			PublicKey:     base64.StdEncoding.EncodeToString(s.PublicKey),
			Addresses:     addrs,
		})
	}
	return json.MarshalIndent(out, "", "  ")
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

// SanitizeForDisplay strips control characters and bidi format codes from
// untrusted display strings.
func SanitizeForDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20 || r == 0x7f:
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
