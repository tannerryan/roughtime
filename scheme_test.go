// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// TestVersionsForScheme verifies the Ed25519 list excludes Google and ML-DSA-44
// and the MLDSA44 list contains only VersionMLDSA44.
func TestVersionsForScheme(t *testing.T) {
	ed := roughtime.VersionsForScheme(roughtime.SchemeEd25519)
	if len(ed) == 0 {
		t.Fatal("Ed25519 list empty")
	}
	for _, v := range ed {
		if v == protocol.VersionGoogle || v == protocol.VersionMLDSA44 {
			t.Fatalf("Ed25519 list contains %v; should exclude Google and PQ", v)
		}
	}

	pq := roughtime.VersionsForScheme(roughtime.SchemeMLDSA44)
	if len(pq) != 1 || pq[0] != protocol.VersionMLDSA44 {
		t.Fatalf("MLDSA44 list = %v; want [VersionMLDSA44]", pq)
	}
}

// TestVersionsForSchemeUnknown verifies an unknown scheme falls through to the
// Ed25519 list.
func TestVersionsForSchemeUnknown(t *testing.T) {
	got := roughtime.VersionsForScheme(roughtime.Scheme(99))
	want := roughtime.VersionsForScheme(roughtime.SchemeEd25519)
	if len(got) != len(want) {
		t.Fatalf("unknown scheme: got %d versions, want %d (Ed25519 list length)", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("unknown scheme[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestSchemeOfKey verifies SchemeOfKey maps 32-byte keys to Ed25519, 1312-byte
// to ML-DSA-44, and rejects others.
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

// TestDecodePublicKey verifies DecodePublicKey accepts std/raw/url base64 and
// hex encodings of a 32-byte key.
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

// TestDecodePublicKeyMLDSA44 verifies DecodePublicKey accepts a 1312-byte
// ML-DSA-44 key.
func TestDecodePublicKeyMLDSA44(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 1312)
	got, err := roughtime.DecodePublicKey(base64.StdEncoding.EncodeToString(want))
	if err != nil {
		t.Fatalf("DecodePublicKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("ML-DSA-44 key round-trip mismatch")
	}
}

// TestDecodePublicKeyRejectsWrongLength verifies DecodePublicKey rejects keys
// that are not 32 or 1312 bytes.
func TestDecodePublicKeyRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 33, 64, 1311, 1313, 2048} {
		raw := bytes.Repeat([]byte{0x99}, n)
		if _, err := roughtime.DecodePublicKey(base64.StdEncoding.EncodeToString(raw)); err == nil {
			t.Fatalf("DecodePublicKey accepted %d-byte key", n)
		}
	}
}

// TestDecodePublicKeyTruncatesError verifies DecodePublicKey error messages are
// bounded in length.
func TestDecodePublicKeyTruncatesError(t *testing.T) {
	huge := strings.Repeat("X", 100_000)
	_, err := roughtime.DecodePublicKey(huge)
	if err == nil {
		t.Fatal("DecodePublicKey accepted 100k-byte garbage")
	}
	if len(err.Error()) > 200 {
		t.Fatalf("error message length %d exceeds bound; should truncate", len(err.Error()))
	}
}

// FuzzDecodePublicKey fuzzes DecodePublicKey to ensure successful decodes
// always pass SchemeOfKey.
func FuzzDecodePublicKey(f *testing.F) {
	pk := make([]byte, 32)
	f.Add(base64.StdEncoding.EncodeToString(pk))
	f.Add(fmt.Sprintf("%x", pk))
	f.Add("")
	f.Add("not a key")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := roughtime.DecodePublicKey(s)
		if err != nil {
			return
		}
		if _, err := roughtime.SchemeOfKey(b); err != nil {
			t.Fatalf("DecodePublicKey returned length %d; SchemeOfKey rejects it", len(b))
		}
	})
}

// FuzzVersionsForScheme fuzzes VersionsForScheme to ensure non-PQ schemes never
// include VersionMLDSA44.
func FuzzVersionsForScheme(f *testing.F) {
	f.Add(int(roughtime.SchemeEd25519))
	f.Add(int(roughtime.SchemeMLDSA44))
	f.Add(99)
	f.Add(-1)
	f.Fuzz(func(t *testing.T, n int) {
		vs := roughtime.VersionsForScheme(roughtime.Scheme(n))
		seenPQ := false
		for _, v := range vs {
			if v == protocol.VersionMLDSA44 {
				seenPQ = true
			}
		}
		if roughtime.Scheme(n) != roughtime.SchemeMLDSA44 && seenPQ {
			t.Fatalf("non-PQ scheme %d returned VersionMLDSA44", n)
		}
	})
}
