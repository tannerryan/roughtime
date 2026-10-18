// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrDelegationWindow is returned by [VerifyReply] when the midpoint falls
// outside MINT..MAXT.
var ErrDelegationWindow = errors.New("protocol: midpoint outside delegation window")

var (
	// minPlausibleMidpoint rejects a misdecoded wire epoch.
	minPlausibleMidpoint = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	// maxPlausibleMidpoint rejects a misdecoded wire epoch.
	maxPlausibleMidpoint = time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
)

// VerifyReply authenticates a server response using the contract documented by
// [VerifyReplyWithOptions].
func VerifyReply(versions []Version, reply, rootPK, nonce, requestBytes []byte) (midpoint time.Time, radius time.Duration, err error) {
	return VerifyReplyWithOptions(versions, reply, rootPK, nonce, requestBytes, VerifyOptions{})
}

// VerifyOptions selects compatibility mode and draft-specific checks.
type VerifyOptions struct {
	// Mode selects strict or flex protocol support.
	Mode Mode
	// RequireTYPE requires TYPE=0 in a VersionDraft12 request and TYPE=1 in its
	// response in flex mode. RFC and ML-DSA-44 always require both tags.
	RequireTYPE bool
}

// VerifyReplyWithOptions authenticates a response and returns its midpoint and
// radius. versions must be nonempty and recognized, and nonce must have the
// selected version's length and match the request. RFC, drafts 12+, and
// ML-DSA-44 require requestBytes. Flex legacy profiles reject midpoints outside
// years 2000-3000 to guard against unsigned timestamp-epoch changes. MJD
// leap-second replies include one extra second of uncertainty because Go time
// cannot represent second 60.
func VerifyReplyWithOptions(versions []Version, reply, rootPK, nonce, requestBytes []byte, opts VerifyOptions) (midpoint time.Time, radius time.Duration, err error) {
	if err := checkVersions(opts.Mode, versions); err != nil {
		return time.Time{}, 0, err
	}
	bestVer, bestG, err := clientVersionPreference(versions)
	if err != nil {
		return time.Time{}, 0, err
	}
	offeredVersions := versions
	var parsedRequest *Request
	if len(requestBytes) != 0 {
		parsedRequest, err = ParseRequestWithMode(requestBytes, opts.Mode)
		if err != nil {
			return time.Time{}, 0, fmt.Errorf("protocol: parse request: %w", err)
		}
		if !bytes.Equal(parsedRequest.Nonce, nonce) {
			return time.Time{}, 0, errors.New("protocol: request NONC does not match supplied nonce")
		}
		if len(parsedRequest.Versions) == 0 {
			offeredVersions = []Version{VersionGoogle}
		} else {
			offeredVersions = parsedRequest.Versions
		}
	}

	// unwrap with the client's best version, refine once server VER is known
	respBytes, err := unwrapReply(reply, bestG)
	if err != nil {
		return time.Time{}, 0, err
	}

	resp, err := decodeMessage(respBytes, opts.Mode == Flex)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode reply: %w", err)
	}

	var srep map[uint32][]byte
	if srepBytes, ok := resp[TagSREP]; ok {
		s, derr := decodeMessage(srepBytes, opts.Mode == Flex)
		if derr != nil {
			return time.Time{}, 0, fmt.Errorf("protocol: decode SREP: %w", derr)
		}
		srep = s
	}

	g := bestG
	if bestVer != VersionGoogle {
		if respVer, ok := extractResponseVER(resp, srep); ok {
			if !versionOffered(respVer, versions) || !versionOffered(respVer, offeredVersions) {
				return time.Time{}, 0, errors.New("protocol: server chose version not offered by client")
			}
			if !isRecognizedVersion(respVer) {
				return time.Time{}, 0, fmt.Errorf("protocol: unsupported response version %s", respVer)
			}

			hasRespType := false
			if respVer == Version1 || respVer == VersionDraft12 || respVer == VersionMLDSA44 {
				respTypeBytes, ok := resp[TagTYPE]
				if ok {
					if len(respTypeBytes) != 4 || binary.LittleEndian.Uint32(respTypeBytes) != 1 {
						return time.Time{}, 0, errors.New("protocol: response TYPE must be 1")
					}
					hasRespType = true
				}
				requestHasType := parsedRequest != nil && parsedRequest.HasType
				if respVer == Version1 || respVer == VersionMLDSA44 {
					if !requestHasType {
						return time.Time{}, 0, errors.New("protocol: missing TYPE in request")
					}
					if !hasRespType {
						return time.Time{}, 0, errors.New("protocol: missing TYPE in response")
					}
				}
				if opts.RequireTYPE && !requestHasType {
					return time.Time{}, 0, errors.New("protocol: missing TYPE in request")
				}
				if opts.RequireTYPE && !hasRespType {
					return time.Time{}, 0, errors.New("protocol: missing TYPE in response")
				}
			}
			g = wireGroupOf(respVer, hasRespType)
		}
	}
	if len(nonce) != nonceSize(g) {
		return time.Time{}, 0, fmt.Errorf("protocol: nonce length %d, want %d", len(nonce), nonceSize(g))
	}
	if err := validateMessage(respBytes, resp, g); err != nil {
		return time.Time{}, 0, err
	}
	if srep != nil {
		if err := validateMessage(resp[TagSREP], srep, g); err != nil {
			return time.Time{}, 0, fmt.Errorf("protocol: invalid SREP: %w", err)
		}
	}

	// Drafts 01-11 require a top-level VER. RFC and drafts 12+ use SREP.VER.
	if hasResponseVER(g) {
		vb, ok := resp[TagVER]
		if !ok {
			return time.Time{}, 0, errors.New("protocol: missing VER in response")
		}
		if len(vb) != 4 {
			return time.Time{}, 0, fmt.Errorf("protocol: top-level VER must be 4 bytes, got %d", len(vb))
		}
	}
	if g >= groupD10 && parsedRequest != nil {
		if len(parsedRequest.SRV) != 0 && !bytes.Equal(parsedRequest.SRV, ComputeSRV(rootPK)) {
			return time.Time{}, 0, errors.New("protocol: request SRV does not identify supplied root key")
		}
	}

	_, mintBuf, maxtBuf, err := verifyReplySigs(resp, rootPK, g)
	if err != nil && g == groupRFC && opts.Mode == Flex {
		// Flex mode also authenticates version-1 packets using the draft
		// contexts.
		_, mintBuf, maxtBuf, err = verifyReplySigs(resp, rootPK, groupD14)
	}
	if err != nil {
		return time.Time{}, 0, err
	}

	midpoint, radius, err = verifyReplySREP(srep, resp, nonce, requestBytes, g)
	if err != nil {
		return time.Time{}, 0, err
	}
	if g >= groupD12 {
		if err := verifySREPVersions(srep, offeredVersions, g); err != nil {
			return time.Time{}, 0, err
		}
	}

	return validateDelegationWindow(midpoint, radius, srep[TagMIDP], mintBuf, maxtBuf, g)
}

// verifySREPVersions checks signed VER and VERS. Untyped draft input accepts
// more than 32 versions for compatibility. Typed input has a 32-entry limit.
func verifySREPVersions(srep map[uint32][]byte, clientVersions []Version, g wireGroup) error {
	if srep == nil {
		return errors.New("protocol: missing SREP for downgrade check")
	}
	verBytes, ok := srep[TagVER]
	if !ok || len(verBytes) != 4 {
		return errors.New("protocol: missing VER in SREP")
	}
	chosen := Version(binary.LittleEndian.Uint32(verBytes))
	if !versionOffered(chosen, clientVersions) {
		return fmt.Errorf("protocol: server chose version %s not offered by client", chosen)
	}
	versBytes, ok := srep[TagVERS]
	if !ok || len(versBytes) == 0 || len(versBytes)%4 != 0 {
		return errors.New("protocol: missing or malformed VERS in SREP")
	}
	nv := len(versBytes) / 4
	if g >= groupD14 && nv > maxVersionList {
		return fmt.Errorf("protocol: VERS has %d entries (max %d)", nv, maxVersionList)
	}
	serverSupports := make(map[Version]bool, nv)
	var prev Version
	for i := 0; i < len(versBytes); i += 4 {
		v := Version(binary.LittleEndian.Uint32(versBytes[i : i+4]))
		if i > 0 && v <= prev {
			return errors.New("protocol: VERS not sorted in ascending order")
		}
		prev = v
		serverSupports[v] = true
		if !usesRFCFormat(g) && isRecognizedVersion(v) && (v == VersionMLDSA44) != (chosen == VersionMLDSA44) {
			return errors.New("protocol: VERS mixes incompatible signature schemes")
		}
	}
	if !serverSupports[chosen] {
		return fmt.Errorf("protocol: server chose version %s not present in signed VERS list", chosen)
	}
	return nil
}

// extractResponseVER returns the claimed version, preferring signed SREP.VER.
func extractResponseVER(resp, srep map[uint32][]byte) (Version, bool) {
	if srep != nil {
		if vb, ok := srep[TagVER]; ok && len(vb) == 4 {
			return Version(binary.LittleEndian.Uint32(vb)), true
		}
	}
	if vb, ok := resp[TagVER]; ok && len(vb) == 4 {
		return Version(binary.LittleEndian.Uint32(vb)), true
	}
	return 0, false
}

// ExtractVersion returns the version claimed by a raw server reply. It does not
// authenticate the reply. Call [VerifyReply] before trusting the result.
func ExtractVersion(reply []byte) (Version, bool) {
	// Unframed Google replies have no VER, including in unknown extensions.
	msg, err := unwrapPacket(reply)
	if err != nil {
		return 0, false
	}
	resp, err := decodeMessage(msg, true)
	if err != nil {
		return 0, false
	}
	var srep map[uint32][]byte
	if srepBytes, ok := resp[TagSREP]; ok {
		if s, derr := decodeMessage(srepBytes, true); derr == nil {
			srep = s
		}
	}
	return extractResponseVER(resp, srep)
}

// unwrapReply strips the ROUGHTIM header from framed replies and rejects it for
// Google.
func unwrapReply(reply []byte, g wireGroup) ([]byte, error) {
	if usesRoughtimHeader(g) {
		return unwrapPacket(reply)
	}
	if len(reply) >= 8 && bytes.Equal(reply[:8], packetMagic[:]) {
		return nil, errors.New("protocol: unexpected ROUGHTIM header for Google-Roughtime")
	}
	return reply, nil
}

// verifyReplySigs verifies CERT against rootPK and SREP against the online key.
func verifyReplySigs(resp map[uint32][]byte, rootPK []byte, g wireGroup) ([]byte, []byte, []byte, error) {
	scheme := schemeOfGroup(g)
	if len(rootPK) != publicKeySize(scheme) {
		return nil, nil, nil, fmt.Errorf("protocol: root key is %d bytes, want %d for %s",
			len(rootPK), publicKeySize(scheme), scheme)
	}
	srepBytes, ok := resp[TagSREP]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing SREP")
	}
	srepSig, ok := resp[TagSIG]
	if !ok || len(srepSig) != signatureSize(scheme) {
		return nil, nil, nil, errors.New("protocol: missing or invalid SIG")
	}
	certBytes, ok := resp[TagCERT]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing CERT")
	}

	onlinePK, mintBuf, maxtBuf, err := verifyCert(certBytes, rootPK, g)
	if err != nil {
		return nil, nil, nil, err
	}

	switch scheme {
	case schemeEd25519:
		if !verifyEd25519(ed25519.PublicKey(onlinePK), srepBytes, responseContext(g), srepSig) {
			return nil, nil, nil, errors.New("protocol: SREP signature verification failed")
		}
	case schemeMLDSA44:
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), onlinePK)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("protocol: decode online PUBK: %w", err)
		}
		if !verifyMLDSA44(pk, srepBytes, responseContext(g), srepSig) {
			return nil, nil, nil, errors.New("protocol: SREP signature verification failed")
		}
	default:
		return nil, nil, nil, errSchemeNotSupported
	}

	return onlinePK, mintBuf, maxtBuf, nil
}

// verifyReplySREP verifies the Merkle proof and decodes MIDP/RADI from a
// pre-decoded SREP.
func verifyReplySREP(srep, resp map[uint32][]byte, nonce, requestBytes []byte, g wireGroup) (time.Time, time.Duration, error) {
	if srep == nil {
		return time.Time{}, 0, errors.New("protocol: missing SREP")
	}
	if usesMJDMicroseconds(g) {
		if err := validateOptionalTimeFields(srep); err != nil {
			return time.Time{}, 0, err
		}
	}
	midpBytes, ok := srep[TagMIDP]
	if !ok {
		return time.Time{}, 0, errors.New("protocol: missing MIDP")
	}
	radiBytes, ok := srep[TagRADI]
	if !ok {
		return time.Time{}, 0, errors.New("protocol: missing RADI")
	}
	rootHash, ok := srep[TagROOT]
	if !ok || len(rootHash) != hashSize(g) {
		return time.Time{}, 0, errors.New("protocol: missing or invalid ROOT")
	}

	// RFC and ML-DSA-44 responses require a top-level NONC. Drafts 01-02 put it
	// in SREP. Flex verification allows other draft peers to omit the echo.
	if noncInSREP(g) {
		srepNonce, ok := srep[TagNONC]
		if !ok {
			return time.Time{}, 0, errors.New("protocol: missing NONC in SREP")
		}
		if !bytes.Equal(srepNonce, nonce) {
			return time.Time{}, 0, errors.New("protocol: NONC in SREP does not match request nonce")
		}
	} else if hasResponseNONC(g) {
		if usesRFCFormat(g) {
			if echoed, ok := resp[TagNONC]; !ok || len(echoed) != 32 {
				return time.Time{}, 0, errors.New("protocol: missing or invalid response NONC")
			}
		}
		if echoed, ok := resp[TagNONC]; ok && !bytes.Equal(echoed, nonce) {
			return time.Time{}, 0, errors.New("protocol: response NONC does not match request nonce")
		}
	}

	leafData := nonce
	if usesFullPacketLeaf(g) {
		if len(requestBytes) == 0 {
			return time.Time{}, 0, errors.New("protocol: requestBytes required for full-packet Merkle proof")
		}
		leafData = requestBytes
	}
	if err := verifyMerkle(resp, leafData, rootHash, g); err != nil {
		return time.Time{}, 0, err
	}

	midpoint, err := decodeTimestamp(midpBytes, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode MIDP: %w", err)
	}
	// Reject implausible dates, including epoch misdecodes.
	if !usesRFCFormat(g) && (midpoint.Before(minPlausibleMidpoint) || midpoint.After(maxPlausibleMidpoint)) {
		return time.Time{}, 0, errors.New("protocol: midpoint outside plausible calendar range")
	}
	radius, err := decodeRadius(radiBytes, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode RADI: %w", err)
	}
	// RFC and flex second-based profiles require a positive radius.
	if g >= groupD10 && radius == 0 {
		return time.Time{}, 0, errors.New("protocol: RADI must not be zero")
	}
	return midpoint, radius, nil
}

// validateOptionalTimeFields checks the sign-magnitude fields of drafts 01-07.
func validateOptionalTimeFields(srep map[uint32][]byte) error {
	for _, tag := range []uint32{tagDUT1, tagDTAI, tagLEAP} {
		value, ok := srep[tag]
		if !ok {
			continue
		}
		if len(value)%4 != 0 || tag != tagLEAP && len(value) != 4 {
			return fmt.Errorf("protocol: invalid time field 0x%08x length", tag)
		}
		previous := uint32(0x7fffffff)
		for i := 0; i < len(value); i += 4 {
			n := binary.LittleEndian.Uint32(value[i:])
			if n == 0x80000000 {
				return errors.New("protocol: negative zero in optional time field")
			}
			magnitude := n & 0x7fffffff
			if tag == tagLEAP && magnitude > previous {
				return errors.New("protocol: LEAP events not reverse chronological")
			}
			previous = magnitude
		}
	}
	return nil
}

// validateDelegationWindow checks native delegation bounds and returns a
// conservative Go time interval for leap-second timestamps.
func validateDelegationWindow(midpoint time.Time, radius time.Duration, midpBuf, mintBuf, maxtBuf []byte, g wireGroup) (time.Time, time.Duration, error) {
	// Bounds are unsigned wire values and need not fit Go time. Only MIDP and
	// its returned uncertainty window need that conversion.
	if usesMJDMicroseconds(g) {
		if _, err := decodeTimestamp(mintBuf, g); err != nil {
			return time.Time{}, 0, fmt.Errorf("protocol: decode MINT: %w", err)
		}
		if _, err := decodeTimestamp(maxtBuf, g); err != nil {
			return time.Time{}, 0, fmt.Errorf("protocol: decode MAXT: %w", err)
		}
	}
	value := binary.LittleEndian.Uint64(midpBuf)
	minimum := binary.LittleEndian.Uint64(mintBuf)
	maximum := binary.LittleEndian.Uint64(maxtBuf)
	if value < minimum || value > maximum {
		return time.Time{}, 0, fmt.Errorf("%w (MIDP=%d, MINT=%d, MAXT=%d)",
			ErrDelegationWindow, value, minimum, maximum)
	}
	if usesMJDMicroseconds(g) && value&0xffffffffff >= 86_400_000_000 {
		// Go cannot represent second 60. Cover both sides of its normalization.
		radius += time.Second
	}
	if midpoint.Add(radius).Sub(midpoint) != radius || midpoint.Sub(midpoint.Add(-radius)) != radius {
		return time.Time{}, 0, errors.New("protocol: time window outside Go time range")
	}
	return midpoint, radius, nil
}

// verifyCert verifies the delegation certificate and returns the online PK and
// raw MINT/MAXT bytes.
func verifyCert(certBytes []byte, rootPK []byte, g wireGroup) ([]byte, []byte, []byte, error) {
	scheme := schemeOfGroup(g)
	certMsg, err := decodeProfile(certBytes, g)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("protocol: decode CERT: %w", err)
	}
	deleBytes, ok := certMsg[TagDELE]
	if !ok {
		return nil, nil, nil, errors.New("protocol: missing DELE in CERT")
	}
	certSig, ok := certMsg[TagSIG]
	if !ok || len(certSig) != signatureSize(scheme) {
		return nil, nil, nil, errors.New("protocol: missing or invalid SIG in CERT")
	}

	ctx := delegationContext(g)
	switch scheme {
	case schemeEd25519:
		if !verifyEd25519(ed25519.PublicKey(rootPK), deleBytes, ctx, certSig) {
			return nil, nil, nil, errors.New("protocol: DELE signature verification failed")
		}
	case schemeMLDSA44:
		pk, perr := mldsa.NewPublicKey(mldsa.MLDSA44(), rootPK)
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("protocol: decode root PUBK: %w", perr)
		}
		if !verifyMLDSA44(pk, deleBytes, ctx, certSig) {
			return nil, nil, nil, errors.New("protocol: DELE signature verification failed")
		}
	default:
		return nil, nil, nil, errSchemeNotSupported
	}

	dele, err := decodeProfile(deleBytes, g)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("protocol: decode DELE: %w", err)
	}
	onlinePK, ok := dele[TagPUBK]
	if !ok || len(onlinePK) != publicKeySize(scheme) {
		return nil, nil, nil, errors.New("protocol: missing or invalid PUBK in DELE")
	}
	mintBuf, ok := dele[TagMINT]
	if !ok || len(mintBuf) != 8 {
		return nil, nil, nil, errors.New("protocol: missing or invalid MINT in DELE")
	}
	maxtBuf, ok := dele[TagMAXT]
	if !ok || len(maxtBuf) != 8 {
		return nil, nil, nil, errors.New("protocol: missing or invalid MAXT in DELE")
	}

	return onlinePK, mintBuf, maxtBuf, nil
}
