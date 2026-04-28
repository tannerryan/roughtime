// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"testing"
)

// TestWireGroupOf verifies wireGroupOf maps each version to the expected wire
// group.
func TestWireGroupOf(t *testing.T) {
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

// TestHashSize verifies hashSize returns 64 for Google and 32 for IETF wire
// groups.
func TestHashSize(t *testing.T) {
	if hashSize(groupGoogle) != 64 {
		t.Fatal("Google hash size should be 64")
	}
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if hashSize(g) != 32 {
			t.Fatalf("IETF hash size for group %d should be 32", g)
		}
	}
}

// TestUsesRoughtimHeader verifies usesRoughtimHeader is false for Google and
// true for IETF wire groups.
func TestUsesRoughtimHeader(t *testing.T) {
	if usesRoughtimHeader(groupGoogle) {
		t.Fatal("Google should not use ROUGHTIM header")
	}
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if !usesRoughtimHeader(g) {
			t.Fatalf("group %d should use ROUGHTIM header", g)
		}
	}
}

// TestUsesMJDMicroseconds verifies usesMJDMicroseconds is true only for drafts
// 01-07.
func TestUsesMJDMicroseconds(t *testing.T) {
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07} {
		if !usesMJDMicroseconds(g) {
			t.Fatalf("group %d should use MJD", g)
		}
	}
	for _, g := range []wireGroup{groupGoogle, groupD08, groupD10, groupD12, groupD14} {
		if usesMJDMicroseconds(g) {
			t.Fatalf("group %d should not use MJD", g)
		}
	}
}

// TestUsesFullPacketLeaf verifies usesFullPacketLeaf is true only for drafts
// 12+.
func TestUsesFullPacketLeaf(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10} {
		if usesFullPacketLeaf(g) {
			t.Fatalf("group %d should not use full-packet leaf", g)
		}
	}
	for _, g := range []wireGroup{groupD12, groupD14} {
		if !usesFullPacketLeaf(g) {
			t.Fatalf("group %d should use full-packet leaf", g)
		}
	}
}

// TestNoncInSREP verifies noncInSREP is true only for drafts 01-02.
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

// TestHasResponseVER verifies hasResponseVER is true only for drafts 01-11.
func TestHasResponseVER(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD12, groupD14} {
		if hasResponseVER(g) {
			t.Fatalf("group %d should not have top-level VER", g)
		}
	}
	for _, g := range []wireGroup{groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10} {
		if !hasResponseVER(g) {
			t.Fatalf("group %d should have top-level VER", g)
		}
	}
}

// TestHasResponseNONC verifies hasResponseNONC is true only for drafts 03+.
func TestHasResponseNONC(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02} {
		if hasResponseNONC(g) {
			t.Fatalf("group %d should not have top-level NONC", g)
		}
	}
	for _, g := range []wireGroup{groupD03, groupD05, groupD07, groupD08, groupD10, groupD12, groupD14} {
		if !hasResponseNONC(g) {
			t.Fatalf("group %d should have top-level NONC", g)
		}
	}
}

// TestHasSREPVERS verifies hasSREPVERS is true only for drafts 12+.
func TestHasSREPVERS(t *testing.T) {
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD07, groupD08, groupD10} {
		if hasSREPVERS(g) {
			t.Fatalf("group %d should not have SREP VERS", g)
		}
	}
	for _, g := range []wireGroup{groupD12, groupD14} {
		if !hasSREPVERS(g) {
			t.Fatalf("group %d should have SREP VERS", g)
		}
	}
}

// TestUsesSHA512_256 verifies usesSHA512_256 is true only for drafts 02 and 07.
func TestUsesSHA512_256(t *testing.T) {
	for _, g := range []wireGroup{groupD02, groupD07} {
		if !usesSHA512_256(g) {
			t.Fatalf("group %d should use SHA-512/256", g)
		}
	}
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD03, groupD05, groupD08, groupD10, groupD12, groupD14} {
		if usesSHA512_256(g) {
			t.Fatalf("group %d should not use SHA-512/256", g)
		}
	}
}

// TestNonceSize verifies nonceSize is 64 for Google and drafts 01-04, 32 for
// drafts 05+.
func TestNonceSize(t *testing.T) {
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

// TestDelegationContext verifies delegationContext distinguishes old (with
// hyphens) and new contexts.
func TestDelegationContext(t *testing.T) {
	old := delegationContext(groupGoogle)
	if !bytes.Contains(old, []byte("--")) || old[len(old)-1] != 0 {
		t.Fatal("old context should contain -- and be null-terminated")
	}
	neu := delegationContext(groupD12)
	if bytes.Contains(neu, []byte("--")) || neu[len(neu)-1] != 0 {
		t.Fatal("new context should not contain -- and be null-terminated")
	}
	for _, g := range []wireGroup{groupGoogle, groupD01, groupD02, groupD03, groupD05, groupD08, groupD10} {
		if !bytes.Equal(delegationContext(g), old) {
			t.Fatalf("group %d should use old context", g)
		}
	}
	for _, g := range []wireGroup{groupD07, groupD12, groupD14} {
		if !bytes.Equal(delegationContext(g), neu) {
			t.Fatalf("group %d should use new context", g)
		}
	}
}

// TestNoncInSREPExported verifies the exported NoncInSREP matches the internal
// noncInSREP across versions.
func TestNoncInSREPExported(t *testing.T) {
	versions := []Version{
		VersionGoogle, VersionDraft01, VersionDraft02, VersionDraft03,
		VersionDraft04, VersionDraft05, VersionDraft07, VersionDraft08,
		VersionDraft10, VersionDraft12,
	}
	for _, v := range versions {
		for _, hasType := range []bool{false, true} {
			want := noncInSREP(wireGroupOf(v, hasType))
			if got := NoncInSREP(v, hasType); got != want {
				t.Errorf("NoncInSREP(%s, %v) = %v, want %v", v, hasType, got, want)
			}
		}
	}
	if !NoncInSREP(VersionDraft01, false) || !NoncInSREP(VersionDraft02, false) {
		t.Fatal("drafts 01 and 02 must report NONC-in-SREP")
	}
	if NoncInSREP(VersionDraft12, true) {
		t.Fatal("draft 12 must not report NONC-in-SREP")
	}
}
