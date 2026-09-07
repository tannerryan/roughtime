// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// TestVersionsForScheme covers scheme-specific preference lists.
func TestVersionsForScheme(t *testing.T) {
	ed := roughtime.VersionsForScheme(roughtime.SchemeEd25519)
	if len(ed) == 0 {
		t.Fatal("Ed25519 list empty")
	}
	for _, v := range ed {
		if v == protocol.VersionGoogle || v == protocol.VersionMLDSA44 {
			t.Fatalf("Ed25519 list contains %v, should exclude Google and PQ", v)
		}
	}

	pq := roughtime.VersionsForScheme(roughtime.SchemeMLDSA44)
	if len(pq) != 1 || pq[0] != protocol.VersionMLDSA44 {
		t.Fatalf("MLDSA44 list = %v, want [VersionMLDSA44]", pq)
	}
}

// TestSchemeOfKey covers key-length scheme selection.
func TestSchemeOfKey(t *testing.T) {
	if sch, err := roughtime.SchemeOfKey(make([]byte, 32)); err != nil || sch != roughtime.SchemeEd25519 {
		t.Fatalf("32-byte: sch=%v err=%v", sch, err)
	}
	if sch, err := roughtime.SchemeOfKey(make([]byte, 1312)); err != nil || sch != roughtime.SchemeMLDSA44 {
		t.Fatalf("1312-byte: sch=%v err=%v", sch, err)
	}
	if _, err := roughtime.SchemeOfKey(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
}

// TestDecodePublicKey covers Ed25519 text encodings.
func TestDecodePublicKey(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	inputs := []string{
		base64.StdEncoding.EncodeToString(want),
		base64.RawStdEncoding.EncodeToString(want),
		base64.URLEncoding.EncodeToString(want),
		fmt.Sprintf("%x", want),
	}
	for _, in := range inputs {
		got, err := roughtime.DecodePublicKey(in)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("DecodePublicKey(%q): got=%x err=%v", in, got, err)
		}
	}
	if _, err := roughtime.DecodePublicKey("definitely not a key"); err == nil {
		t.Fatal("accepted garbage")
	}
}

// TestDecodePublicKeyMLDSA44 covers ML-DSA-44 text encodings.
func TestDecodePublicKeyMLDSA44(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 1312)
	for _, in := range []string{
		base64.StdEncoding.EncodeToString(want),
		fmt.Sprintf("%x", want),
		fmt.Sprintf("%x\n", want),
	} {
		got, err := roughtime.DecodePublicKey(in)
		if err != nil {
			t.Fatalf("DecodePublicKey: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("ML-DSA-44 key round-trip mismatch")
		}
	}
}

// TestDecodePublicKeyRejectsWrongLength covers invalid key sizes.
func TestDecodePublicKeyRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 33, 64, 1311, 1313, 2048} {
		raw := bytes.Repeat([]byte{0x99}, n)
		if _, err := roughtime.DecodePublicKey(base64.StdEncoding.EncodeToString(raw)); err == nil {
			t.Fatalf("DecodePublicKey accepted %d-byte key", n)
		}
	}
}
