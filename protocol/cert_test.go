// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// TestNewCertificate covers Ed25519 certificate construction.
func TestNewCertificate(t *testing.T) {
	cert, _ := testCert(t)
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12} {
		if len(cert.certBytes(g)) == 0 {
			t.Fatalf("empty CERT for group %d", g)
		}
	}
}

// TestNewCertificateGroupD14 covers the typed shared-version certificate.
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

// TestCertificateWipe covers online-key disposal.
func TestCertificateWipe(t *testing.T) {
	cert, _ := testCert(t)
	if allZero(cert.edOnlineSK) {
		t.Fatal("precondition: onlineSK should not already be zero")
	}
	onlineSK := cert.edOnlineSK
	cert.Wipe()
	if !allZero(onlineSK) {
		t.Fatal("onlineSK not zeroed after Wipe")
	}
	if cert.edOnlineSK != nil {
		t.Fatal("onlineSK reference retained after Wipe")
	}
	var nilCert *Certificate
	nilCert.Wipe()
}

// TestVerifyCertRejectsCorruptCERT covers malformed certificate rejection.
func TestVerifyCertRejectsCorruptCERT(t *testing.T) {
	pk := make([]byte, ed25519.PublicKeySize)
	if _, _, _, err := verifyCert([]byte{0xff, 0xff, 0xff, 0xff}, pk, groupGoogle); err == nil {
		t.Fatal("expected error for corrupt CERT")
	}
}

// TestPQNewCertificateRejectsNilKey covers absent ML-DSA-44 keys.
func TestPQNewCertificateRejectsNilKey(t *testing.T) {
	now := time.Now()
	if _, err := NewCertificateMLDSA44(now, now.Add(time.Hour), nil, nil); err == nil {
		t.Fatal("expected error on nil keys")
	}
}

// TestPQWipeDropsReference covers ML-DSA-44 key release.
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
