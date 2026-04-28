// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	"testing"
)

// TestVersionString verifies Version.String for known versions and unknown
// values.
func TestVersionString(t *testing.T) {
	tests := []struct {
		ver  Version
		want string
	}{
		{VersionGoogle, "Google-Roughtime"},
		{VersionDraft01, "draft-ietf-ntp-roughtime-01"},
		{VersionDraft02, "draft-ietf-ntp-roughtime-02"},
		{VersionDraft03, "draft-ietf-ntp-roughtime-03"},
		{VersionDraft04, "draft-ietf-ntp-roughtime-04"},
		{VersionDraft05, "draft-ietf-ntp-roughtime-05"},
		{VersionDraft06, "draft-ietf-ntp-roughtime-06"},
		{VersionDraft07, "draft-ietf-ntp-roughtime-07"},
		{VersionDraft08, "draft-ietf-ntp-roughtime-08"},
		{VersionDraft09, "draft-ietf-ntp-roughtime-09"},
		{VersionDraft10, "draft-ietf-ntp-roughtime-10"},
		{VersionDraft11, "draft-ietf-ntp-roughtime-11"},
		{VersionDraft12, "draft-ietf-ntp-roughtime-12"},
		{Version(0xdeadbeef), "Version(0xdeadbeef)"},
	}
	for _, tt := range tests {
		if got := tt.ver.String(); got != tt.want {
			t.Errorf("Version(%#x).String() = %q, want %q", uint32(tt.ver), got, tt.want)
		}
	}
}

// TestShortString verifies Version.ShortString for known versions and unknown
// values.
func TestShortString(t *testing.T) {
	tests := []struct {
		ver  Version
		want string
	}{
		{VersionGoogle, "Google"},
		{VersionDraft08, "draft-08"},
		{VersionDraft12, "draft-12"},
		{Version(0xdeadbeef), "0xdeadbeef"},
	}
	for _, tt := range tests {
		if got := tt.ver.ShortString(); got != tt.want {
			t.Errorf("Version(%#x).ShortString() = %q, want %q", uint32(tt.ver), got, tt.want)
		}
	}
}

// FuzzParseShortVersion fuzzes ParseShortVersion for round-trip stability with
// ShortString.
func FuzzParseShortVersion(f *testing.F) {
	for _, v := range Supported() {
		f.Add(v.ShortString())
	}
	f.Add("draft-99")
	f.Add("")
	f.Add("ROUGHTIM")
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseShortVersion(s)
		if err == nil && v.ShortString() != s {
			t.Fatalf("round-trip: %q → %v → %q", s, v, v.ShortString())
		}
	})
}

// TestParseShortVersion verifies ParseShortVersion round-trips every supported
// version and rejects unknown labels.
func TestParseShortVersion(t *testing.T) {
	for _, v := range Supported() {
		got, err := ParseShortVersion(v.ShortString())
		if err != nil {
			t.Fatalf("ParseShortVersion(%q): %v", v.ShortString(), err)
		}
		if got != v {
			t.Fatalf("ParseShortVersion(%q) = %v, want %v", v.ShortString(), got, v)
		}
	}
	if _, err := ParseShortVersion("draft-999"); err == nil {
		t.Fatal("accepted unknown label")
	}
	if _, err := ParseShortVersion(""); err == nil {
		t.Fatal("accepted empty label")
	}
}

// TestSelectVersionGoogle verifies SelectVersion picks Google when client is
// empty and nonce is 64 bytes.
func TestSelectVersionGoogle(t *testing.T) {
	ver, err := SelectVersion(nil, 64, ServerPreferenceEd25519)
	if err != nil || ver != VersionGoogle {
		t.Fatal("expected VersionGoogle")
	}
}

// TestSelectVersionRejectsNoVERShortNonce verifies SelectVersion rejects empty
// client versions with non-Google nonce sizes.
func TestSelectVersionRejectsNoVERShortNonce(t *testing.T) {
	if _, err := SelectVersion(nil, 32, ServerPreferenceEd25519); err == nil {
		t.Fatal("expected error")
	}
}

// TestSelectVersionPreference verifies SelectVersion picks the highest
// mutually-supported version.
func TestSelectVersionPreference(t *testing.T) {
	ver, err := SelectVersion([]Version{VersionDraft01, VersionDraft12}, 32, ServerPreferenceEd25519)
	if err != nil || ver != VersionDraft12 {
		t.Fatal("expected VersionDraft12")
	}
}

// TestSelectVersionRejectsNoMutual verifies SelectVersion errors when no mutual
// version exists.
func TestSelectVersionRejectsNoMutual(t *testing.T) {
	if _, err := SelectVersion([]Version{0x99999999}, 32, ServerPreferenceEd25519); err == nil {
		t.Fatal("expected error")
	}
}

// TestSupportedAscending verifies supportedVersionsEd25519 is in ascending
// order.
func TestSupportedAscending(t *testing.T) {
	vs := supportedVersionsEd25519
	for i := 1; i < len(vs); i++ {
		if vs[i] <= vs[i-1] {
			t.Fatalf("not ascending at index %d", i)
		}
	}
}

// TestSupportedBytesLength verifies supportedVersionsEd25519Bytes has 4 bytes
// per version.
func TestSupportedBytesLength(t *testing.T) {
	if len(supportedVersionsEd25519Bytes) != 4*len(supportedVersionsEd25519) {
		t.Fatal("length mismatch")
	}
}

// TestClientVersionPreference verifies clientVersionPreference maps draft-12 to
// groupD14.
func TestClientVersionPreference(t *testing.T) {
	ver, g, err := clientVersionPreference([]Version{VersionDraft08, VersionDraft12})
	if err != nil || ver != VersionDraft12 || g != groupD14 {
		t.Fatal("expected Draft12/groupD14")
	}
}

// TestClientVersionPreferenceRejectsEmpty verifies clientVersionPreference
// errors on an empty list.
func TestClientVersionPreferenceRejectsEmpty(t *testing.T) {
	if _, _, err := clientVersionPreference(nil); err == nil {
		t.Fatal("expected error")
	}
}

// TestSupportedExported verifies Supported returns IETF descending, then
// Google, then PQ.
func TestSupportedExported(t *testing.T) {
	got := Supported()
	wantLen := len(supportedVersionsEd25519) + 1 + len(supportedVersionsMLDSA44)
	if len(got) != wantLen {
		t.Fatalf("len(Supported()) = %d, want %d", len(got), wantLen)
	}
	googleIdx := len(supportedVersionsEd25519)
	if got[googleIdx] != VersionGoogle {
		t.Fatalf("index %d = %s, want VersionGoogle", googleIdx, got[googleIdx])
	}
	for i := 1; i < googleIdx; i++ {
		if got[i] >= got[i-1] {
			t.Fatalf("IETF entries not descending at index %d: %s >= %s", i, got[i], got[i-1])
		}
	}
	// mutating the returned slice must not affect future calls
	got[0] = VersionGoogle
	if Supported()[0] == VersionGoogle {
		t.Fatal("Supported() must return a defensive copy")
	}
}

// TestSelectVersionRejectsNonceSizeMismatch verifies SelectVersion only returns
// versions whose nonce size matches.
func TestSelectVersionRejectsNonceSizeMismatch(t *testing.T) {
	if _, err := SelectVersion([]Version{VersionDraft12}, 64, ServerPreferenceEd25519); err == nil {
		t.Fatal("expected error: Draft12 with 64-byte nonce")
	}
	if _, err := SelectVersion([]Version{VersionDraft04}, 32, ServerPreferenceEd25519); err == nil {
		t.Fatal("expected error: Draft04 with 32-byte nonce")
	}
	// 64-byte nonce forces Draft04 despite Draft12 having higher preference
	v, err := SelectVersion([]Version{VersionDraft04, VersionDraft12}, 64, ServerPreferenceEd25519)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != VersionDraft04 {
		t.Fatalf("got %v, want VersionDraft04", v)
	}
	v, err = SelectVersion([]Version{VersionDraft04, VersionDraft12}, 32, ServerPreferenceEd25519)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != VersionDraft12 {
		t.Fatalf("got %v, want VersionDraft12", v)
	}
}

// TestPQSelectVersion verifies SelectVersion across PQ-only and dual-suite
// preferences.
func TestPQSelectVersion(t *testing.T) {
	v, err := SelectVersion([]Version{VersionMLDSA44}, 32, ServerPreferenceMLDSA44)
	if err != nil || v != VersionMLDSA44 {
		t.Fatalf("SelectVersion PQ: v=%v err=%v", v, err)
	}
	if _, err := SelectVersion([]Version{VersionDraft12}, 32, ServerPreferenceMLDSA44); err == nil {
		t.Fatal("expected error: Draft12 not in PQ preference")
	}
	dual := append([]Version{}, ServerPreferenceMLDSA44...)
	dual = append(dual, ServerPreferenceEd25519...)
	v, err = SelectVersion([]Version{VersionMLDSA44, VersionDraft12}, 32, dual)
	if err != nil || v != VersionMLDSA44 {
		t.Fatalf("dual server preferring PQ: v=%v err=%v", v, err)
	}
	v, err = SelectVersion([]Version{VersionDraft12}, 32, dual)
	if err != nil || v != VersionDraft12 {
		t.Fatalf("dual server falling back to Draft12: v=%v err=%v", v, err)
	}
}

// FuzzSelectVersion fuzzes SelectVersion for panic-safety on arbitrary version
// lists.
func FuzzSelectVersion(f *testing.F) {
	f.Add([]byte{}, 32)
	f.Add([]byte{}, 64)
	f.Add([]byte{0x0c, 0x00, 0x00, 0x80}, 32)
	f.Add([]byte{0x08, 0x00, 0x00, 0x80, 0x0c, 0x00, 0x00, 0x80}, 32)

	f.Fuzz(func(t *testing.T, verBytes []byte, nonceLen int) {
		if len(verBytes)%4 != 0 || len(verBytes) > 4*maxVersionList {
			return
		}
		vers := make([]Version, 0, len(verBytes)/4)
		for i := 0; i < len(verBytes); i += 4 {
			vers = append(vers, Version(binary.LittleEndian.Uint32(verBytes[i:i+4])))
		}
		if nonceLen < 0 || nonceLen > 1024 {
			return
		}
		_, _ = SelectVersion(vers, nonceLen, ServerPreferenceEd25519)
	})
}
