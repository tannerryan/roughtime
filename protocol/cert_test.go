// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"filippo.io/mldsa"
)

// TestNewCertificate verifies NewCertificate builds non-empty CERT bytes for
// every Ed25519 wire group.
func TestNewCertificate(t *testing.T) {
	cert, _ := testCert(t)
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12} {
		if len(cert.certBytes(g)) == 0 {
			t.Fatalf("empty CERT for group %d", g)
		}
	}
}

// TestNewCertificateRejectsInvalidKeySize verifies NewCertificate rejects keys
// with the wrong size.
func TestNewCertificateRejectsInvalidKeySize(t *testing.T) {
	if _, err := NewCertificate(time.Now(), time.Now(), make([]byte, 10), make([]byte, 10)); err == nil {
		t.Fatal("expected error")
	}
}

// TestNewCertificateRejectsInvalidWindow verifies NewCertificate rejects MINT
// >= MAXT.
func TestNewCertificateRejectsInvalidWindow(t *testing.T) {
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	_, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()

	if _, err := NewCertificate(now, now, onlineSK, rootSK); err == nil {
		t.Fatal("expected error for MINT == MAXT")
	}
	if _, err := NewCertificate(now.Add(time.Hour), now, onlineSK, rootSK); err == nil {
		t.Fatal("expected error for MINT > MAXT")
	}
	if _, err := NewCertificate(now, now.Add(time.Hour), onlineSK, rootSK); err != nil {
		t.Fatalf("unexpected error for valid window: %v", err)
	}
}

// TestCacheKeyForDistinctGroups verifies cacheKeyFor distinguishes wire groups
// with different encoding or context.
func TestCacheKeyForDistinctGroups(t *testing.T) {
	cert, _ := testCert(t)
	groups := []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12}
	seen := make(map[certCacheKey]wireGroup)
	for _, g := range groups {
		k := cert.cacheKeyFor(g)
		if prev, ok := seen[k]; ok {
			if !bytes.Equal(delegationContext(g), delegationContext(prev)) ||
				usesMJDMicroseconds(g) != usesMJDMicroseconds(prev) {
				t.Fatalf("groups %d and %d have same cache key but different behavior", prev, g)
			}
		}
		seen[k] = g
	}
	if cert.cacheKeyFor(groupGoogle) == cert.cacheKeyFor(groupD01) ||
		cert.cacheKeyFor(groupD01) == cert.cacheKeyFor(groupD08) ||
		cert.cacheKeyFor(groupD08) == cert.cacheKeyFor(groupD12) {
		t.Fatal("cache keys should be distinct across encoding/context changes")
	}
}

// TestNewCertificateGroupD14 verifies NewCertificate produces a verifiable CERT
// for groupD14.
func TestNewCertificateGroupD14(t *testing.T) {
	rootSK, onlineSK := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)
	now := time.Now()
	cert, err := NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = verifyCert(cert.certBytes(groupD14), rootPK, groupD14)
	if err != nil {
		t.Fatalf("verifyCert with groupD14 failed: %v", err)
	}
}

// TestCertificateWipe verifies Wipe zeros the Ed25519 online key and tolerates
// a nil receiver.
func TestCertificateWipe(t *testing.T) {
	cert, _ := testCert(t)
	if allZero(cert.edOnlineSK) {
		t.Fatal("precondition: onlineSK should not already be zero")
	}
	cert.Wipe()
	if !allZero(cert.edOnlineSK) {
		t.Fatal("onlineSK not zeroed after Wipe")
	}
	var nilCert *Certificate
	nilCert.Wipe()
}

// TestCertBytesPanicsOnCacheMiss verifies certBytes panics when the cache lacks
// the requested wire group.
func TestCertBytesPanicsOnCacheMiss(t *testing.T) {
	c := &Certificate{cache: map[certCacheKey][]byte{}}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on cache miss")
		}
		msg, ok := r.(string)
		if !ok || !bytes.Contains([]byte(msg), []byte("cache miss")) {
			t.Fatalf("unexpected panic value: %v", r)
		}
	}()
	_ = c.certBytes(groupD12)
}

// TestVerifyCertRejectsCorruptCERT verifies verifyCert rejects unparseable CERT
// bytes.
func TestVerifyCertRejectsCorruptCERT(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	if _, _, _, err := verifyCert([]byte{0xff, 0xff, 0xff, 0xff}, pk, groupGoogle); err == nil {
		t.Fatal("expected error for corrupt CERT")
	}
}

// TestVerifyCertRejectsMissingDELE verifies verifyCert rejects a CERT lacking
// DELE.
func TestVerifyCertRejectsMissingDELE(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	certBytes, _ := encode(map[uint32][]byte{
		TagSIG: make([]byte, ed25519.SignatureSize),
	})
	if _, _, _, err := verifyCert(certBytes, pk, groupGoogle); err == nil {
		t.Fatal("expected error for missing DELE")
	}
}

// TestVerifyCertRejectsBadSIGSize verifies verifyCert rejects a SIG of wrong
// length.
func TestVerifyCertRejectsBadSIGSize(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	certBytes, _ := encode(map[uint32][]byte{
		TagSIG:  make([]byte, 32), // wrong size
		TagDELE: make([]byte, 4),
	})
	if _, _, _, err := verifyCert(certBytes, pk, groupGoogle); err == nil {
		t.Fatal("expected error for bad SIG size in CERT")
	}
}

// TestVerifyCertRejectsSignatureFailure verifies verifyCert rejects a CERT with
// invalid signature.
func TestVerifyCertRejectsSignatureFailure(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, ed25519.PublicKeySize),
		TagMINT: make([]byte, 8),
		TagMAXT: make([]byte, 8),
	})
	certBytes, _ := encode(map[uint32][]byte{
		TagSIG:  make([]byte, ed25519.SignatureSize),
		TagDELE: dele,
	})
	if _, _, _, err := verifyCert(certBytes, pk, groupGoogle); err == nil {
		t.Fatal("expected error for signature failure")
	}
}

// TestVerifyCertRejectsBadPUBK verifies verifyCert rejects a DELE with
// wrong-size PUBK.
func TestVerifyCertRejectsBadPUBK(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, 16), // wrong size
		TagMINT: make([]byte, 8),
		TagMAXT: make([]byte, 8),
	})
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for bad PUBK size")
	}
}

// TestVerifyCertRejectsBadMINTSize verifies verifyCert rejects a DELE with
// wrong-size MINT.
func TestVerifyCertRejectsBadMINTSize(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, ed25519.PublicKeySize),
		TagMINT: make([]byte, 4), // wrong size
		TagMAXT: make([]byte, 8),
	})
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for bad MINT size")
	}
}

// TestVerifyCertRejectsBadMAXTSize verifies verifyCert rejects a DELE with
// wrong-size MAXT.
func TestVerifyCertRejectsBadMAXTSize(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	dele, _ := encode(map[uint32][]byte{
		TagPUBK: make([]byte, ed25519.PublicKeySize),
		TagMINT: make([]byte, 8),
		TagMAXT: make([]byte, 4), // wrong size
	})
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for bad MAXT size")
	}
}

// TestVerifyCertRejectsCorruptDELE verifies verifyCert rejects an unparseable
// DELE even with a valid signature.
func TestVerifyCertRejectsCorruptDELE(t *testing.T) {
	rootSK, _ := testKeys(t)
	rootPK := rootSK.Public().(ed25519.PublicKey)

	// raw bytes that are not a valid Roughtime message (zero tag count)
	dele := []byte{0x00, 0x00, 0x00, 0x00}
	ctx := delegationContext(groupGoogle)
	toSign := make([]byte, len(ctx)+len(dele))
	copy(toSign, ctx)
	copy(toSign[len(ctx):], dele)
	sig := ed25519.Sign(rootSK, toSign)

	certBytes, _ := encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
	if _, _, _, err := verifyCert(certBytes, rootPK, groupGoogle); err == nil {
		t.Fatal("expected error for corrupt DELE after valid signature")
	}
}

// TestValidateDelegationWindowRejectsBadMINT verifies validateDelegationWindow
// rejects MINT of wrong length.
func TestValidateDelegationWindowRejectsBadMINT(t *testing.T) {
	if _, _, err := validateDelegationWindow(time.Now(), time.Second, make([]byte, 4), make([]byte, 8), groupGoogle); err == nil {
		t.Fatal("expected error for bad MINT")
	}
}

// TestValidateDelegationWindowRejectsBadMAXT verifies validateDelegationWindow
// rejects MAXT of wrong length.
func TestValidateDelegationWindowRejectsBadMAXT(t *testing.T) {
	if _, _, err := validateDelegationWindow(time.Now(), time.Second, make([]byte, 8), make([]byte, 4), groupGoogle); err == nil {
		t.Fatal("expected error for bad MAXT")
	}
}

// TestPQNewCertificateRejectsNilKey verifies NewCertificateMLDSA44 rejects nil
// keys.
func TestPQNewCertificateRejectsNilKey(t *testing.T) {
	now := time.Now()
	if _, err := NewCertificateMLDSA44(now, now.Add(time.Hour), nil, nil); err == nil {
		t.Fatal("expected error on nil keys")
	}
}

// TestPQNewCertificateRejectsBadWindow verifies NewCertificateMLDSA44 rejects
// MINT >= MAXT.
func TestPQNewCertificateRejectsBadWindow(t *testing.T) {
	rootSK, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	onlineSK, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	now := time.Now()
	if _, err := NewCertificateMLDSA44(now.Add(time.Hour), now, onlineSK, rootSK); err == nil {
		t.Fatal("expected error when MINT >= MAXT")
	}
}

// TestPQWipeDropsReference verifies Wipe releases the PQ online key.
func TestPQWipeDropsReference(t *testing.T) {
	cert, _ := testPQCert(t)
	if cert.pqOnlineSK == nil {
		t.Fatal("PQ cert missing online key before Wipe")
	}
	cert.Wipe()
	if cert.pqOnlineSK != nil {
		t.Fatal("Wipe did not release the PQ online signing key")
	}
}

// TestBuildCERTRejectsUnknownScheme verifies buildCERT returns
// errSchemeNotSupported for an unknown scheme.
func TestBuildCERTRejectsUnknownScheme(t *testing.T) {
	c := &Certificate{scheme: 99, mint: time.Now().Add(-time.Hour), maxt: time.Now().Add(time.Hour)}
	if _, err := c.buildCERT(groupGoogle, nil, nil); !errors.Is(err, errSchemeNotSupported) {
		t.Fatalf("buildCERT: %v; want errSchemeNotSupported", err)
	}
}

// TestValidateDelegationWindowReturnsErrDelegationWindow verifies a midpoint
// outside MINT..MAXT wraps ErrDelegationWindow.
func TestValidateDelegationWindowReturnsErrDelegationWindow(t *testing.T) {
	g := groupD14
	mint := time.Now().Add(time.Hour)
	maxt := time.Now().Add(2 * time.Hour)
	mintBuf := encodeTimestamp(mint, g)
	maxtBuf := encodeTimestamp(maxt, g)
	midpoint := time.Now().Add(-time.Hour)
	_, _, err := validateDelegationWindow(midpoint, time.Second, mintBuf[:], maxtBuf[:], g)
	if err == nil {
		t.Fatal("expected delegation-window error")
	}
	if !errors.Is(err, ErrDelegationWindow) {
		t.Fatalf("expected ErrDelegationWindow, got %v", err)
	}
}
