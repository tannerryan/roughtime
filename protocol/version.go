// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Version identifies a Roughtime protocol version on the wire.
type Version uint32

// Roughtime protocol versions.
const (
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

	// VersionMLDSA44 is the experimental ML-DSA-44 post-quantum wire variant.
	VersionMLDSA44 Version = 0x90000001
)

// String returns the IETF draft name or a hex representation for unknown
// values.
func (v Version) String() string {
	switch v {
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

// ShortString returns a compact version label.
func (v Version) ShortString() string {
	switch v {
	case VersionGoogle:
		return "Google"
	case VersionDraft12:
		return "draft-12"
	case VersionMLDSA44:
		return "ml-dsa-44"
	default:
		if v > VersionGoogle && v <= VersionDraft12 {
			return fmt.Sprintf("draft-%02d", uint32(v)-0x80000000)
		}
		return fmt.Sprintf("0x%08x", uint32(v))
	}
}

// ParseShortVersion is the inverse of [Version.ShortString] over [Supported].
func ParseShortVersion(s string) (Version, error) {
	for _, v := range Supported() {
		if v.ShortString() == s {
			return v, nil
		}
	}
	return 0, fmt.Errorf("protocol: unknown version %q", s)
}

// ServerPreferenceEd25519 lists Ed25519 versions in descending negotiation
// preference.
var ServerPreferenceEd25519 = []Version{
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
	VersionDraft01, VersionDraft02, VersionDraft03, VersionDraft04,
	VersionDraft05, VersionDraft06, VersionDraft07,
	VersionDraft08, VersionDraft09,
	VersionDraft10, VersionDraft11,
	VersionDraft12,
}

// supportedVersionsMLDSA44 is the scheme-scoped VERS list for ML-DSA-44.
var supportedVersionsMLDSA44 = []Version{VersionMLDSA44}

var (
	// supportedVersionsEd25519Bytes is the pre-encoded VERS bytes for Ed25519.
	supportedVersionsEd25519Bytes []byte
	// supportedVersionsMLDSA44Bytes is the pre-encoded VERS bytes for
	// ML-DSA-44.
	supportedVersionsMLDSA44Bytes []byte
)

// init populates the pre-encoded VERS byte slices.
func init() {
	encVers := func(vs []Version) []byte {
		out := make([]byte, 4*len(vs))
		for i, v := range vs {
			binary.LittleEndian.PutUint32(out[4*i:4*i+4], uint32(v))
		}
		return out
	}
	supportedVersionsEd25519Bytes = encVers(supportedVersionsEd25519)
	supportedVersionsMLDSA44Bytes = encVers(supportedVersionsMLDSA44)
}

// Supported returns all recognized protocol versions: newest IETF first,
// Google, then post-quantum.
func Supported() []Version {
	out := slices.Clone(supportedVersionsEd25519)
	slices.Reverse(out)
	out = append(out, VersionGoogle)
	out = append(out, supportedVersionsMLDSA44...)
	return out
}

// SelectVersion picks the best mutually supported version whose nonce size
// matches nonceLen.
func SelectVersion(clientVersions []Version, nonceLen int, serverVersions []Version) (Version, error) {
	if len(clientVersions) == 0 {
		if nonceLen == nonceSize(groupGoogle) && slices.Contains(serverVersions, VersionGoogle) {
			return VersionGoogle, nil
		}
		return 0, errors.New("protocol: no supported version")
	}
	for _, sv := range serverVersions {
		if nonceSize(wireGroupOf(sv, false)) != nonceLen {
			continue
		}
		if slices.Contains(clientVersions, sv) {
			return sv, nil
		}
	}
	return 0, errors.New("protocol: no mutually supported version")
}

// clientVersionPreference returns the highest version and its wire group.
func clientVersionPreference(versions []Version) (Version, wireGroup, error) {
	if len(versions) == 0 {
		return 0, 0, errors.New("protocol: empty version list")
	}
	best := slices.Max(versions)
	return best, wireGroupOf(best, true), nil
}

// versionOffered reports whether ver appears in the client's version list.
func versionOffered(ver Version, versions []Version) bool {
	return slices.Contains(versions, ver)
}
