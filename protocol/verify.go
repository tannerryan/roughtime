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

// VerifyOptions controls strict checks for wire behavior that the shared
// version number cannot disambiguate.
type VerifyOptions struct {
	// RequireTYPE requires TYPE=0 in a VersionDraft12 request and TYPE=1 in its
	// response. Leave it false when draft-12/13 peers must remain acceptable.
	// ML-DSA-44 always requires both tags.
	RequireTYPE bool
}

// VerifyReplyWithOptions authenticates a response and returns its midpoint and
// radius. versions must be nonempty and recognized, and nonce must have the
// selected version's length and match the request. Drafts 12+ and ML-DSA-44
// require requestBytes. Midpoints outside years 2000–3000 are rejected to
// prevent unsigned legacy VER changes from relabeling the timestamp epoch.
func VerifyReplyWithOptions(versions []Version, reply, rootPK, nonce, requestBytes []byte, opts VerifyOptions) (midpoint time.Time, radius time.Duration, err error) {
	bestVer, bestG, err := clientVersionPreference(versions)
	if err != nil {
		return time.Time{}, 0, err
	}
	offeredVersions := versions
	var parsedRequest *Request
	if len(requestBytes) != 0 {
		parsedRequest, err = ParseRequest(requestBytes)
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

	resp, err := Decode(respBytes)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode reply: %w", err)
	}

	var srep map[uint32][]byte
	if srepBytes, ok := resp[TagSREP]; ok {
		s, derr := Decode(srepBytes)
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
			if respVer == VersionDraft12 || respVer == VersionMLDSA44 {
				respTypeBytes, ok := resp[TagTYPE]
				if ok {
					if len(respTypeBytes) != 4 || binary.LittleEndian.Uint32(respTypeBytes) != 1 {
						return time.Time{}, 0, errors.New("protocol: response TYPE must be 1")
					}
					hasRespType = true
				}
				requestHasType := parsedRequest != nil && parsedRequest.HasType
				if respVer == VersionMLDSA44 {
					if !requestHasType {
						return time.Time{}, 0, errors.New("protocol: missing TYPE in ML-DSA-44 request")
					}
					if !hasRespType {
						return time.Time{}, 0, errors.New("protocol: missing TYPE in ML-DSA-44 response")
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

	// Drafts 01-11 require top-level VER, while 12+ moved it into SREP. This
	// checks structure only. Authentication follows below.
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

	return validateDelegationWindow(midpoint, radius, mintBuf, maxtBuf, g)
}

// verifySREPVersions validates the signed version declaration used by drafts
// 12+ and ML-DSA-44. Selection need not use the highest numeric version.
// Untyped draft-12/13 input may exceed 32 entries because those drafts share an
// identifier and draft 12 had no limit. Typed modern input remains capped.
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
		if isRecognizedVersion(v) && (v == VersionMLDSA44) != (chosen == VersionMLDSA44) {
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
	msg := reply
	if len(reply) >= 12 {
		if inner, err := unwrapPacket(reply); err == nil {
			msg = inner
		}
	}
	resp, err := Decode(msg)
	if err != nil {
		return 0, false
	}
	var srep map[uint32][]byte
	if srepBytes, ok := resp[TagSREP]; ok {
		if s, derr := Decode(srepBytes); derr == nil {
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
		if !verifyEd25519(ed25519.PublicKey(onlinePK), srepBytes, responseCtx, srepSig) {
			return nil, nil, nil, errors.New("protocol: SREP signature verification failed")
		}
	case schemeMLDSA44:
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), onlinePK)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("protocol: decode online PUBK: %w", err)
		}
		if !verifyMLDSA44(pk, srepBytes, responseCtx, srepSig) {
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

	// Drafts 01-02 bind NONC through SREP. Later responses commonly echo NONC
	// at top level. Validate it when present. Some deployed historical servers
	// omit that redundant echo, so absence remains accepted for compatibility.
	if noncInSREP(g) {
		srepNonce, ok := srep[TagNONC]
		if !ok {
			return time.Time{}, 0, errors.New("protocol: missing NONC in SREP")
		}
		if !bytes.Equal(srepNonce, nonce) {
			return time.Time{}, 0, errors.New("protocol: NONC in SREP does not match request nonce")
		}
	} else if hasResponseNONC(g) {
		if echoed, ok := resp[TagNONC]; ok && !bytes.Equal(echoed, nonce) {
			return time.Time{}, 0, errors.New("protocol: response NONC does not match request nonce")
		}
	}

	leafData := nonce
	if usesFullPacketLeaf(g) {
		if len(requestBytes) == 0 {
			return time.Time{}, 0, errors.New("protocol: requestBytes required for drafts 12+")
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
	if midpoint.Before(minPlausibleMidpoint) || midpoint.After(maxPlausibleMidpoint) {
		return time.Time{}, 0, errors.New("protocol: midpoint outside plausible calendar range")
	}
	radius, err := decodeRadius(radiBytes, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode RADI: %w", err)
	}
	// Deployed draft-11 servers advertise sub-three-second radii despite the
	// draft's lower bound, so compatibility requires rejecting only zero.
	if g >= groupD10 && radius == 0 {
		return time.Time{}, 0, errors.New("protocol: RADI must not be zero")
	}
	return midpoint, radius, nil
}

// validateDelegationWindow checks the midpoint falls within MINT..MAXT.
func validateDelegationWindow(midpoint time.Time, radius time.Duration, mintBuf, maxtBuf []byte, g wireGroup) (time.Time, time.Duration, error) {
	mintTime, err := decodeTimestamp(mintBuf, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode MINT: %w", err)
	}
	maxtTime, err := decodeTimestamp(maxtBuf, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode MAXT: %w", err)
	}
	if midpoint.Before(mintTime) || midpoint.After(maxtTime) {
		return time.Time{}, 0, fmt.Errorf("%w (MIDP=%s, MINT=%s, MAXT=%s)",
			ErrDelegationWindow,
			midpoint.Format(time.RFC3339), mintTime.Format(time.RFC3339), maxtTime.Format(time.RFC3339))
	}
	return midpoint, radius, nil
}

// verifyCert verifies the delegation certificate and returns the online PK and
// raw MINT/MAXT bytes.
func verifyCert(certBytes []byte, rootPK []byte, g wireGroup) ([]byte, []byte, []byte, error) {
	scheme := schemeOfGroup(g)
	certMsg, err := Decode(certBytes)
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

	dele, err := Decode(deleBytes)
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
