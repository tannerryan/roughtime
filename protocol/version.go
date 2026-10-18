// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"errors"
	"fmt"
	"slices"
)

// Version identifies a Roughtime protocol version on the wire.
type Version uint32

// Mode controls protocol compatibility. Its zero value accepts RFC 10049 only.
type Mode uint8

const (
	// Strict accepts RFC 10049 version 1.
	Strict Mode = iota
	// Flex also accepts the implemented drafts and experimental formats.
	Flex
)

// allows reports whether the mode accepts v.
func (m Mode) allows(v Version) bool {
	return v == Version1 || m == Flex && isRecognizedVersion(v)
}

// checkVersions rejects invalid modes and versions unavailable in that mode.
func checkVersions(mode Mode, versions []Version) error {
	if mode != Strict && mode != Flex {
		return errors.New("protocol: invalid mode")
	}
	for _, v := range versions {
		if !mode.allows(v) {
			return fmt.Errorf("protocol: version %s requires flex mode", v)
		}
	}
	return nil
}

// Roughtime protocol versions.
const (
	// Version1 is RFC 10049.
	Version1 Version = 1
	// VersionGoogle is Google-Roughtime (no VER tag).
	VersionGoogle Version = 0
	// VersionDraft01 is draft-ietf-ntp-roughtime-01.
	VersionDraft01 Version = 0x80000001
	// VersionDraft02 is draft-ietf-ntp-roughtime-02.
	VersionDraft02 Version = 0x80000002
	// VersionDraft03 is draft-ietf-ntp-roughtime-03.
	VersionDraft03 Version = 0x80000003
	// VersionDraft04 is draft-ietf-ntp-roughtime-04.
	VersionDraft04 Version = 0x80000004
	// VersionDraft05 is draft-ietf-ntp-roughtime-05.
	VersionDraft05 Version = 0x80000005
	// VersionDraft06 is draft-ietf-ntp-roughtime-06.
	VersionDraft06 Version = 0x80000006
	// VersionDraft07 is draft-ietf-ntp-roughtime-07.
	VersionDraft07 Version = 0x80000007
	// VersionDraft08 is draft-ietf-ntp-roughtime-08.
	VersionDraft08 Version = 0x80000008
	// VersionDraft09 is draft-ietf-ntp-roughtime-09.
	VersionDraft09 Version = 0x80000009
	// VersionDraft10 is draft-ietf-ntp-roughtime-10.
	VersionDraft10 Version = 0x8000000a
	// VersionDraft11 is draft-ietf-ntp-roughtime-11.
	VersionDraft11 Version = 0x8000000b
	// VersionDraft12 is drafts 12-19 (shared wire version).
	VersionDraft12 Version = 0x8000000c

	// VersionMLDSA44 is the experimental RFC version 1 extension using
	// ML-DSA-44.
	VersionMLDSA44 Version = 0x90000001
)

// String returns a recognized version name or a hexadecimal unknown value.
func (v Version) String() string {
	switch v {
	case Version1:
		return "RFC 10049 v1"
	case VersionGoogle:
		return "Google-Roughtime"
	case VersionDraft01:
		return "draft-ietf-ntp-roughtime-01"
	case VersionDraft02:
		return "draft-ietf-ntp-roughtime-02"
	case VersionDraft03:
		return "draft-ietf-ntp-roughtime-03"
	case VersionDraft04:
		return "draft-ietf-ntp-roughtime-04"
	case VersionDraft05:
		return "draft-ietf-ntp-roughtime-05"
	case VersionDraft06:
		return "draft-ietf-ntp-roughtime-06"
	case VersionDraft07:
		return "draft-ietf-ntp-roughtime-07"
	case VersionDraft08:
		return "draft-ietf-ntp-roughtime-08"
	case VersionDraft09:
		return "draft-ietf-ntp-roughtime-09"
	case VersionDraft10:
		return "draft-ietf-ntp-roughtime-10"
	case VersionDraft11:
		return "draft-ietf-ntp-roughtime-11"
	case VersionDraft12:
		return "draft-ietf-ntp-roughtime-12"
	case VersionMLDSA44:
		return "roughtime-ml-dsa-44"
	default:
		return fmt.Sprintf("Version(0x%08x)", uint32(v))
	}
}

// ShortString returns a display label, abbreviating draft and extension names.
func (v Version) ShortString() string {
	switch v {
	case Version1:
		return v.String()
	case VersionGoogle:
		return "Google"
	case VersionDraft12:
		return "draft-12"
	case VersionMLDSA44:
		return "ml-dsa-44"
	default:
		if v >= VersionDraft01 && v <= VersionDraft12 {
			return fmt.Sprintf("draft-%02d", uint32(v)-0x80000000)
		}
		return fmt.Sprintf("0x%08x", uint32(v))
	}
}

// ParseShortVersion parses a display label, also accepting v1 for RFC version
// 1.
func ParseShortVersion(s string) (Version, error) {
	if s == "v1" {
		return Version1, nil
	}
	for _, v := range SupportedWithMode(Flex) {
		if v.ShortString() == s {
			return v, nil
		}
	}
	return 0, fmt.Errorf("protocol: unknown version %q", s)
}

// ServerPreferenceEd25519 lists flex Ed25519 negotiation preferences, starting
// with RFC version 1. Strict servers use only [Version1].
var ServerPreferenceEd25519 = []Version{
	Version1,
	VersionDraft12,
	VersionDraft11, VersionDraft10,
	VersionDraft09, VersionDraft08,
	VersionDraft07, VersionDraft06,
	VersionDraft05, VersionDraft04, VersionDraft03, VersionDraft02, VersionDraft01,
	VersionGoogle,
}

// ServerPreferenceMLDSA44 is the negotiation preference list for ML-DSA-44.
var ServerPreferenceMLDSA44 = []Version{VersionMLDSA44}

// supportedVersionsEd25519 lists Ed25519 IETF versions in ascending order for
// SREP VERS.
var supportedVersionsEd25519 = []Version{
	Version1,
	VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04,
	VersionDraft05, VersionDraft06, VersionDraft07,
	VersionDraft08, VersionDraft09,
	VersionDraft10, VersionDraft11,
	VersionDraft12,
}

// supportedVersionsMLDSA44 is the scheme-scoped VERS list for ML-DSA-44.
var supportedVersionsMLDSA44 = []Version{VersionMLDSA44}

// Supported returns the versions accepted in strict mode.
func Supported() []Version {
	return SupportedWithMode(Strict)
}

// SupportedWithMode returns versions in negotiation preference order.
func SupportedWithMode(mode Mode) []Version {
	if mode != Flex {
		return []Version{Version1}
	}
	out := slices.Clone(supportedVersionsEd25519)
	slices.Reverse(out)
	out = slices.DeleteFunc(out, func(v Version) bool { return v == Version1 })
	out = append([]Version{Version1}, out...)
	out = append(out, VersionGoogle)
	out = append(out, supportedVersionsMLDSA44...)
	return out
}

// SelectVersion returns the first server-preferred version offered by the
// client whose nonce size matches nonceLen.
func SelectVersion(clientVersions []Version, nonceLen int, serverVersions []Version) (Version, error) {
	if len(clientVersions) == 0 {
		if nonceLen == nonceSize(groupGoogle) && slices.Contains(serverVersions, VersionGoogle) {
			return VersionGoogle, nil
		}
		return 0, errors.New("protocol: no supported version")
	}
	for _, sv := range serverVersions {
		if !isRecognizedVersion(sv) {
			continue
		}
		if nonceSize(wireGroupOf(sv, false)) != nonceLen {
			continue
		}
		if slices.Contains(clientVersions, sv) {
			return sv, nil
		}
	}
	return 0, errors.New("protocol: no mutually supported version")
}

// clientVersionPreference prefers RFC version 1, then the highest draft
// version.
func clientVersionPreference(versions []Version) (Version, wireGroup, error) {
	if len(versions) == 0 {
		return 0, 0, errors.New("protocol: empty version list")
	}
	for _, v := range versions {
		if !isRecognizedVersion(v) {
			return 0, 0, fmt.Errorf("protocol: unsupported version %s", v)
		}
	}
	best := slices.Max(versions)
	if slices.Contains(versions, Version1) {
		best = Version1
	}
	return best, wireGroupOf(best, true), nil
}

// isRecognizedVersion reports whether v has wire semantics implemented by this
// package. Unknown versions can still be parsed from peer offers, but builders
// and verifiers must not guess their wire format.
func isRecognizedVersion(v Version) bool {
	return v == Version1 || v == VersionGoogle ||
		(v >= VersionDraft01 && v <= VersionDraft12) ||
		v == VersionMLDSA44
}

// versionOffered reports whether ver appears in the client's version list.
func versionOffered(ver Version, versions []Version) bool {
	return slices.Contains(versions, ver)
}

// filterKnownVersions copies the versions accepted by mode.
func filterKnownVersions(versions []Version, mode Mode) []Version {
	return slices.DeleteFunc(slices.Clone(versions), func(v Version) bool { return !mode.allows(v) })
}
