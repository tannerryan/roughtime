// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"unicode/utf8"

	"github.com/tannerryan/roughtime/protocol"
)

// Scheme identifies the signature suite of a server's root key.
type Scheme int

const (
	// SchemeEd25519 is the classical signature suite used by the Google and
	// IETF wire versions.
	SchemeEd25519 Scheme = iota
	// SchemeMLDSA44 is the experimental ML-DSA-44 post-quantum signature suite
	// (TCP only).
	SchemeMLDSA44
)

// SchemeOfKey returns the scheme implied by pk's length (32 = Ed25519, 1312 =
// ML-DSA-44).
func SchemeOfKey(pk []byte) (Scheme, error) {
	switch len(pk) {
	case ed25519.PublicKeySize:
		return SchemeEd25519, nil
	case protocol.MLDSA44PublicKeySize:
		return SchemeMLDSA44, nil
	default:
		return 0, fmt.Errorf("roughtime: unexpected public key length %d", len(pk))
	}
}

// VersionsForScheme returns the wire-version preference list to advertise for a
// server in the given scheme.
func VersionsForScheme(sch Scheme) []protocol.Version {
	if sch == SchemeMLDSA44 {
		return []protocol.Version{protocol.VersionMLDSA44}
	}
	out := make([]protocol.Version, 0)
	for _, v := range protocol.Supported() {
		if v == protocol.VersionGoogle || v == protocol.VersionMLDSA44 {
			continue
		}
		out = append(out, v)
	}
	return out
}

// DecodePublicKey decodes a 32-byte Ed25519 or 1312-byte ML-DSA-44 root public
// key from base64 or hex.
func DecodePublicKey(s string) ([]byte, error) {
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && (len(b) == ed25519.PublicKeySize || len(b) == protocol.MLDSA44PublicKeySize) {
			return b, nil
		}
	}
	return nil, fmt.Errorf("roughtime: public key %q is not a 32-byte Ed25519 or 1312-byte ML-DSA-44 key in base64 or hex", truncateForErr(s))
}

// truncateForErr bounds an attacker-controlled string at a rune boundary before
// embedding it in an error.
func truncateForErr(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	end := limit
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "..."
}
