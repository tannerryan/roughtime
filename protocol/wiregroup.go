// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

// wireGroup identifies a set of drafts that share on-wire behaviour.
type wireGroup int

const (
	// groupGoogle is Google-Roughtime (no header, no VER).
	groupGoogle wireGroup = iota
	// groupD01 is draft 01.
	groupD01
	// groupD02 is draft 02.
	groupD02
	// groupD03 is drafts 03-04.
	groupD03
	// groupD05 is drafts 05-06.
	groupD05
	// groupD07 is draft 07.
	groupD07
	// groupD08 is drafts 08-09.
	groupD08
	// groupD10 is drafts 10-11.
	groupD10
	// groupD12 is drafts 12-13 and the fallback for 14-19 without TYPE.
	groupD12
	// groupD14 is drafts 14-19 with TYPE.
	groupD14
	// groupPQ is the experimental ML-DSA-44 PQ wire group.
	groupPQ
)

// wireGroupOf returns the wire group for a version and TYPE presence.
func wireGroupOf(v Version, hasType bool) wireGroup {
	switch {
	case v == VersionGoogle:
		return groupGoogle
	case v == VersionMLDSA44:
		return groupPQ
	case v == VersionDraft01:
		return groupD01
	case v == VersionDraft02:
		return groupD02
	case v <= VersionDraft04:
		return groupD03
	case v <= VersionDraft06:
		return groupD05
	case v == VersionDraft07:
		return groupD07
	case v <= VersionDraft09:
		return groupD08
	case v <= VersionDraft11:
		return groupD10
	default:
		if hasType {
			return groupD14
		}
		return groupD12
	}
}

// hashSize returns the Merkle hash output length: 64 for Google, 32 for IETF.
func hashSize(g wireGroup) int {
	if g == groupGoogle {
		return 64
	}
	return 32
}

// nonceSize returns the nonce length: 64 for Google and drafts 01-04, 32 for
// drafts 05+.
func nonceSize(g wireGroup) int {
	if g <= groupD03 {
		return 64
	}
	return 32
}

// usesRoughtimHeader reports whether packets use the 12-byte ROUGHTIM header.
func usesRoughtimHeader(g wireGroup) bool { return g >= groupD01 }

// usesMJDMicroseconds reports whether timestamps use MJD-µs encoding (drafts
// 01-07).
func usesMJDMicroseconds(g wireGroup) bool { return g >= groupD01 && g <= groupD07 }

// usesFullPacketLeaf reports whether the Merkle leaf is the full request packet
// (drafts 12+).
func usesFullPacketLeaf(g wireGroup) bool { return g >= groupD12 }

// noncInSREP reports whether NONC sits inside SREP (drafts 01-02).
func noncInSREP(g wireGroup) bool { return g == groupD01 || g == groupD02 }

// NoncInSREP reports whether ver+hasType places NONC inside SREP.
func NoncInSREP(ver Version, hasType bool) bool { return noncInSREP(wireGroupOf(ver, hasType)) }

// hasResponseVER reports whether the response carries a top-level VER tag
// (drafts 01-11).
func hasResponseVER(g wireGroup) bool { return g >= groupD01 && g < groupD12 }

// hasResponseNONC reports whether the response echoes NONC at top level (drafts
// 03+).
func hasResponseNONC(g wireGroup) bool { return g >= groupD03 }

// hasSREPVERS reports whether SREP carries VER and VERS (drafts 12+).
func hasSREPVERS(g wireGroup) bool { return g >= groupD12 }

// usesSHA512_256 reports whether the hash is SHA-512/256 (drafts 02 and 07).
func usesSHA512_256(g wireGroup) bool { return g == groupD02 || g == groupD07 }

var (
	// delegationCtxOld is the delegation context for Google and drafts 01-06,
	// 08-11.
	delegationCtxOld = []byte("RoughTime v1 delegation signature--\x00")
	// delegationCtxNew is the delegation context for draft 07 and drafts 12+.
	delegationCtxNew = []byte("RoughTime v1 delegation signature\x00")
)

// delegationContext returns the delegation signature context for g.
func delegationContext(g wireGroup) []byte {
	if g == groupD07 || g >= groupD12 {
		return delegationCtxNew
	}
	return delegationCtxOld
}
