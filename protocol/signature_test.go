// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"filippo.io/mldsa"
)

// TestSigSchemeStringUnknown verifies sigScheme.String formats unknown schemes.
func TestSigSchemeStringUnknown(t *testing.T) {
	got := sigScheme(99).String()
	if got != "sigScheme(99)" {
		t.Fatalf("unknown sigScheme.String() = %q, want %q", got, "sigScheme(99)")
	}
}

// TestSchemeOfGroupSweep verifies schemeOfGroup distinguishes Ed25519 and
// ML-DSA-44 wire groups.
func TestSchemeOfGroupSweep(t *testing.T) {
	classic := []wireGroup{
		groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07,
		groupD08, groupD10, groupD12, groupD14,
	}
	for _, g := range classic {
		if got := schemeOfGroup(g); got != schemeEd25519 {
			t.Fatalf("schemeOfGroup(%d) = %v, want Ed25519", g, got)
		}
	}
	if got := schemeOfGroup(groupPQ); got != schemeMLDSA44 {
		t.Fatalf("schemeOfGroup(groupPQ) = %v, want ML-DSA-44", got)
	}
}

// TestSuiteSupportedVersionsBytes verifies per-scheme VERS lists contain only
// versions of that scheme.
func TestSuiteSupportedVersionsBytes(t *testing.T) {
	parse := func(b []byte) []Version {
		out := make([]Version, 0, len(b)/4)
		for i := 0; i+4 <= len(b); i += 4 {
			out = append(out, Version(binary.LittleEndian.Uint32(b[i:])))
		}
		return out
	}
	for _, v := range parse(suiteSupportedVersionsBytes(schemeEd25519)) {
		if v == VersionMLDSA44 {
			t.Fatalf("Ed25519 VERS list leaked PQ version 0x%08x", uint32(v))
		}
	}
	for _, v := range parse(suiteSupportedVersionsBytes(schemeMLDSA44)) {
		if v != VersionMLDSA44 {
			t.Fatalf("PQ VERS list leaked non-PQ version 0x%08x", uint32(v))
		}
	}
}

// TestPQSchemeOf verifies schemeOf maps versions to the correct scheme.
func TestPQSchemeOf(t *testing.T) {
	if s := schemeOf(VersionGoogle); s != schemeEd25519 {
		t.Fatalf("schemeOf(Google) = %v, want Ed25519", s)
	}
	if s := schemeOf(VersionDraft12); s != schemeEd25519 {
		t.Fatalf("schemeOf(Draft12) = %v, want Ed25519", s)
	}
	if s := schemeOf(VersionMLDSA44); s != schemeMLDSA44 {
		t.Fatalf("schemeOf(MLDSA44) = %v, want ML-DSA-44", s)
	}
}

// TestVerifyEd25519RejectsBadSizes verifies verifyEd25519 short-circuits on
// wrong-length pk or sig.
func TestVerifyEd25519RejectsBadSizes(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(sk, []byte("hello"))
	if verifyEd25519(make([]byte, 16), []byte("hello"), nil, sig) {
		t.Fatal("accepted wrong-length public key")
	}
	if verifyEd25519(pk, []byte("hello"), nil, make([]byte, 12)) {
		t.Fatal("accepted wrong-length signature")
	}
}

// TestVerifyMLDSA44RejectsBadInputs verifies verifyMLDSA44 short-circuits on
// nil pk or wrong-length sig.
func TestVerifyMLDSA44RejectsBadInputs(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	if verifyMLDSA44(nil, []byte("msg"), nil, make([]byte, mldsa.MLDSA44SignatureSize)) {
		t.Fatal("accepted nil public key")
	}
	if verifyMLDSA44(sk.PublicKey(), []byte("msg"), nil, make([]byte, 12)) {
		t.Fatal("accepted wrong-length signature")
	}
}

// TestPQSizes verifies SchemePublicKeySize and SchemeSignatureSize for Ed25519
// and ML-DSA-44.
func TestPQSizes(t *testing.T) {
	if SchemePublicKeySize(VersionMLDSA44) != mldsa.MLDSA44PublicKeySize {
		t.Fatal("PQ public key size mismatch")
	}
	if SchemeSignatureSize(VersionMLDSA44) != mldsa.MLDSA44SignatureSize {
		t.Fatal("PQ signature size mismatch")
	}
	if SchemePublicKeySize(VersionDraft12) != ed25519.PublicKeySize {
		t.Fatal("Ed25519 public key size mismatch")
	}
	if SchemeSignatureSize(VersionDraft12) != ed25519.SignatureSize {
		t.Fatal("Ed25519 signature size mismatch")
	}
}
