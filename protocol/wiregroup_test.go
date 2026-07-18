// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"testing"
)

// TestWireGroupOf covers version-to-wire-group mapping.
func TestWireGroupOf(t *testing.T) {
	// Cases map each version family to its wire group.
	tests := []struct {
		ver     Version
		hasType bool
		want    wireGroup
	}{
		{VersionGoogle, false, groupGoogle},
		{VersionDraft01, false, groupD01},
		{VersionDraft02, false, groupD02},
		{VersionDraft03, false, groupD03},
		{VersionDraft04, false, groupD03},
		{VersionDraft05, false, groupD05},
		{VersionDraft06, false, groupD05},
		{VersionDraft07, false, groupD07},
		{VersionDraft08, false, groupD08},
		{VersionDraft09, false, groupD08},
		{VersionDraft10, false, groupD10},
		{VersionDraft11, false, groupD10},
		{VersionDraft12, false, groupD12},
		{VersionDraft12, true, groupD14},
	}
	for _, tt := range tests {
		if got := wireGroupOf(tt.ver, tt.hasType); got != tt.want {
			t.Errorf("wireGroupOf(%#x, %v) = %d, want %d", tt.ver, tt.hasType, got, tt.want)
		}
	}
}

// TestNoncInSREP covers nonce placement by wire group.
func TestNoncInSREP(t *testing.T) {
	for _, g := range []wireGroup{groupD01, groupD02} {
		if !noncInSREP(g) {
			t.Fatalf("group %d should have NONC in SREP", g)
		}
	}
	for _, g := range []wireGroup{groupGoogle, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if noncInSREP(g) {
			t.Fatalf("group %d should not have NONC in SREP", g)
		}
	}
}

// TestNonceSize covers nonce length by wire group.
func TestNonceSize(t *testing.T) {
	// Cases cover each nonce-size transition.
	tests := []struct {
		ver  Version
		want int
	}{
		{VersionGoogle, 64},
		{VersionDraft01, 64},
		{VersionDraft04, 64},
		{VersionDraft05, 32},
		{VersionDraft06, 32},
		{VersionDraft08, 32},
		{VersionDraft10, 32},
		{VersionDraft12, 32},
	}
	for _, tt := range tests {
		if got := nonceSize(wireGroupOf(tt.ver, false)); got != tt.want {
			t.Errorf("nonceSize(%#x) = %d, want %d", tt.ver, got, tt.want)
		}
	}
}

// TestSigningContextsMatchSpec covers signature context strings.
func TestSigningContextsMatchSpec(t *testing.T) {
	// Cases cover every signing context.
	tests := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"delegation old (Google, drafts 01-06/08-11)", delegationCtxOld, []byte("RoughTime v1 delegation signature--\x00")},
		{"delegation new (draft 07, drafts 12+)", delegationCtxNew, []byte("RoughTime v1 delegation signature\x00")},
		{"response (all versions)", responseCtx, []byte("RoughTime v1 response signature\x00")},
	}
	for _, tt := range tests {
		if !bytes.Equal(tt.got, tt.want) {
			t.Errorf("%s context = %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}
