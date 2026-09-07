// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"testing"
)

// TestVersionString covers full version labels.
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
		{VersionMLDSA44, "roughtime-ml-dsa-44"},
		{Version(0xdeadbeef), "Version(0xdeadbeef)"},
	}
	for _, tt := range tests {
		if got := tt.ver.String(); got != tt.want {
			t.Errorf("Version(%#x).String() = %q, want %q", uint32(tt.ver), got, tt.want)
		}
	}
}

// TestParseShortVersion covers compact version parsing.
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

// TestSelectVersionGoogle covers implicit Google negotiation.
func TestSelectVersionGoogle(t *testing.T) {
	ver, err := SelectVersion(nil, 64, ServerPreferenceEd25519)
	if err != nil || ver != VersionGoogle {
		t.Fatal("expected VersionGoogle")
	}
}

// TestSelectVersionPreference covers server-order negotiation.
func TestSelectVersionPreference(t *testing.T) {
	ver, err := SelectVersion([]Version{VersionDraft01, VersionDraft12}, 32, ServerPreferenceEd25519)
	if err != nil || ver != VersionDraft12 {
		t.Fatal("expected VersionDraft12")
	}
}

// TestSelectVersionRejectsNoMutual covers an empty version intersection.
func TestSelectVersionRejectsNoMutual(t *testing.T) {
	if _, err := SelectVersion([]Version{0x99999999}, 32, ServerPreferenceEd25519); err == nil {
		t.Fatal("expected error")
	}
}

// TestSupportedAscending covers Ed25519 version ordering and uniqueness.
func TestSupportedAscending(t *testing.T) {
	vs := supportedVersionsEd25519
	for i := 1; i < len(vs); i++ {
		if vs[i] <= vs[i-1] {
			t.Fatalf("not ascending at index %d", i)
		}
	}
}

// TestPQSelectVersion covers ML-DSA-44 negotiation.
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
