// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"filippo.io/mldsa"
)

// MLDSA44PublicKeySize is the on-wire public-key length of the experimental
// ML-DSA-44 (FIPS 204) wire variant.
const MLDSA44PublicKeySize = mldsa.MLDSA44PublicKeySize

// sigScheme identifies the signature algorithm: Ed25519 for standard versions,
// ML-DSA-44 for the experimental post-quantum version.
type sigScheme int

const (
	schemeEd25519 sigScheme = iota
	schemeMLDSA44
)

// String returns a short human-readable name for s.
func (s sigScheme) String() string {
	switch s {
	case schemeEd25519:
		return "Ed25519"
	case schemeMLDSA44:
		return "ML-DSA-44"
	default:
		return fmt.Sprintf("sigScheme(%d)", int(s))
	}
}

// schemeOfGroup returns the signature scheme used by a wire group.
func schemeOfGroup(g wireGroup) sigScheme {
	if g == groupPQ {
		return schemeMLDSA44
	}
	return schemeEd25519
}

// schemeOf returns the signature scheme used by a Roughtime protocol version.
func schemeOf(v Version) sigScheme {
	return schemeOfGroup(wireGroupOf(v, false))
}

// publicKeySize returns the on-wire public key length for a scheme.
func publicKeySize(s sigScheme) int {
	switch s {
	case schemeMLDSA44:
		return mldsa.MLDSA44PublicKeySize
	default:
		return ed25519.PublicKeySize
	}
}

// signatureSize returns the on-wire signature length for a scheme.
func signatureSize(s sigScheme) int {
	switch s {
	case schemeMLDSA44:
		return mldsa.MLDSA44SignatureSize
	default:
		return ed25519.SignatureSize
	}
}

// SchemePublicKeySize returns the on-wire public key length for the scheme
// associated with v.
func SchemePublicKeySize(v Version) int { return publicKeySize(schemeOf(v)) }

// SchemeSignatureSize returns the on-wire signature length for the scheme
// associated with v.
func SchemeSignatureSize(v Version) int { return signatureSize(schemeOf(v)) }

// signEd25519 signs ctx || msg with sk.
func signEd25519(sk ed25519.PrivateKey, msg, ctx []byte) []byte {
	toSign := make([]byte, len(ctx)+len(msg))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], msg)
	return ed25519.Sign(sk, toSign)
}

// verifyEd25519 verifies sig over ctx || msg against pk.
func verifyEd25519(pk ed25519.PublicKey, msg, ctx, sig []byte) bool {
	if len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	toVerify := make([]byte, len(ctx)+len(msg))
	copy(toVerify, ctx)
	copy(toVerify[len(ctx):], msg)
	return ed25519.Verify(pk, toVerify, sig)
}

// signMLDSA44 signs msg with sk under the given FIPS 204 context.
func signMLDSA44(sk *mldsa.PrivateKey, msg, ctx []byte) ([]byte, error) {
	return sk.Sign(nil, msg, &mldsa.Options{Context: string(ctx)})
}

// verifyMLDSA44 verifies sig over msg under the given context.
func verifyMLDSA44(pk *mldsa.PublicKey, msg, ctx, sig []byte) bool {
	if pk == nil || len(sig) != mldsa.MLDSA44SignatureSize {
		return false
	}
	return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: string(ctx)}) == nil
}

// suiteSupportedVersionsBytes returns the pre-encoded VERS bytes for scheme s,
// scoped per scheme so downgrade protection binds to the scheme used.
func suiteSupportedVersionsBytes(s sigScheme) []byte {
	if s == schemeMLDSA44 {
		return supportedVersionsMLDSA44Bytes
	}
	return supportedVersionsEd25519Bytes
}

// errSchemeNotSupported is returned for an unimplemented scheme.
var errSchemeNotSupported = errors.New("protocol: signature scheme not supported")
