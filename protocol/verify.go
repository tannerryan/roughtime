// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"filippo.io/mldsa"
)

// ErrDelegationWindow is returned by [VerifyReply] when the midpoint falls
// outside MINT..MAXT.
var ErrDelegationWindow = errors.New("protocol: midpoint outside delegation window")

// VerifyReply authenticates a server response and returns the midpoint and
// radius.
func VerifyReply(versions []Version, reply, rootPK, nonce, requestBytes []byte) (midpoint time.Time, radius time.Duration, err error) {
	bestVer, bestG, err := clientVersionPreference(versions)
	if err != nil {
		return time.Time{}, 0, err
	}
	if want := publicKeySize(schemeOfGroup(bestG)); len(rootPK) != want {
		return time.Time{}, 0, fmt.Errorf("protocol: root key is %d bytes, want %d for %s",
			len(rootPK), want, schemeOfGroup(bestG))
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
			if !versionOffered(respVer, versions) {
				return time.Time{}, 0, errors.New("protocol: server chose version not offered by client")
			}
			respTypeBytes, hasRespType := resp[TagTYPE]
			if hasRespType {
				if len(respTypeBytes) != 4 || binary.LittleEndian.Uint32(respTypeBytes) != 1 {
					return time.Time{}, 0, errors.New("protocol: response TYPE must be 1")
				}
			}
			g = wireGroupOf(respVer, hasRespType)
		}
	}

	// drafts 01-11 require top-level VER (4 bytes); 12+ moved it into SREP.
	// Pre-12 VER is unsigned, so forging it just produces a signature mismatch
	// downstream — this is a structural presence/length check only.
	if hasResponseVER(g) {
		vb, ok := resp[TagVER]
		if !ok {
			return time.Time{}, 0, errors.New("protocol: missing VER in response")
		}
		if len(vb) != 4 {
			return time.Time{}, 0, fmt.Errorf("protocol: top-level VER must be 4 bytes, got %d", len(vb))
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
		if err := verifyNoVersionDowngrade(srep, versions); err != nil {
			return time.Time{}, 0, err
		}
	}

	return validateDelegationWindow(midpoint, radius, mintBuf, maxtBuf, g)
}

// verifyNoVersionDowngrade confirms SREP.VER is the highest mutually-supported
// version (drafts 12+).
func verifyNoVersionDowngrade(srep map[uint32][]byte, clientVersions []Version) error {
	if srep == nil {
		return errors.New("protocol: missing SREP for downgrade check")
	}
	verBytes, ok := srep[TagVER]
	if !ok || len(verBytes) != 4 {
		return errors.New("protocol: missing VER in SREP")
	}
	chosen := Version(binary.LittleEndian.Uint32(verBytes))
	versBytes, ok := srep[TagVERS]
	if !ok || len(versBytes) == 0 || len(versBytes)%4 != 0 {
		return errors.New("protocol: missing or malformed VERS in SREP")
	}
	nv := len(versBytes) / 4
	if nv > maxVersionList {
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
	}
	if !serverSupports[chosen] {
		return fmt.Errorf("protocol: server chose version %s not present in signed VERS list", chosen)
	}
	var best Version
	var found bool
	for _, v := range clientVersions {
		if serverSupports[v] && (!found || v > best) {
			best, found = v, true
		}
	}
	if !found {
		return errors.New("protocol: no mutually supported version (VERS check)")
	}
	if chosen != best {
		return fmt.Errorf("protocol: version downgrade detected: server chose %s, expected %s", chosen, best)
	}
	return nil
}

// extractResponseVER returns the negotiated version, preferring signed SREP.VER
// over top-level VER.
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

// ExtractVersion returns the negotiated version from a raw server reply.
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

// unwrapReply strips the ROUGHTIM header for IETF replies and rejects it for
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

	// drafts 01-02 bind nonce only via SREP.NONC; 03+ echo at top-level but the
	// Merkle proof already binds it
	if noncInSREP(g) {
		srepNonce, ok := srep[TagNONC]
		if !ok {
			return time.Time{}, 0, errors.New("protocol: missing NONC in SREP")
		}
		if !bytes.Equal(srepNonce, nonce) {
			return time.Time{}, 0, errors.New("protocol: NONC in SREP does not match request nonce")
		}
	} else if echoed, ok := resp[TagNONC]; ok {
		if !bytes.Equal(echoed, nonce) {
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
	radius, err := decodeRadius(radiBytes, g)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("protocol: decode RADI: %w", err)
	}
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
