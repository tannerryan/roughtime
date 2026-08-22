// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Certificate holds a pre-signed online delegation, with CERT bytes cached per
// distinct encoding. CreateReplies calls may run concurrently, but Wipe must
// run only after callers have stopped using the certificate.
type Certificate struct {
	scheme sigScheme
	mint   time.Time
	maxt   time.Time

	edOnlineSK ed25519.PrivateKey
	edOnlinePK ed25519.PublicKey
	edRootPK   ed25519.PublicKey

	pqOnlineSK *mldsa.PrivateKey
	pqOnlinePK *mldsa.PublicKey
	pqRootPK   []byte

	cache map[certCacheKey][]byte
	// versions is the configured server support set. It is immutable,
	// de-duplicated, and sorted in ascending numerical order.
	versions  []Version
	versBytes []byte
}

// certCacheKey identifies a unique CERT encoding shared across wire groups.
type certCacheKey struct {
	ctx   string
	micro bool
	mjd   bool
}

// NewCertificate creates and signs an Ed25519 delegation certificate enabled
// for every recognized Ed25519 version. Use [NewCertificateWithVersions] when
// the server supports a subset.
func NewCertificate(mint, maxt time.Time, onlineSK, rootSK ed25519.PrivateKey) (*Certificate, error) {
	versions := append([]Version{VersionGoogle}, supportedVersionsEd25519...)
	return NewCertificateWithVersions(mint, maxt, onlineSK, rootSK, versions)
}

// NewCertificateWithVersions creates an Ed25519 delegation certificate whose
// signed SREP VERS lists contain exactly the configured IETF versions. The
// support set may also contain [VersionGoogle], which has no VERS tag.
func NewCertificateWithVersions(mint, maxt time.Time, onlineSK, rootSK ed25519.PrivateKey, versions []Version) (*Certificate, error) {
	if len(onlineSK) != ed25519.PrivateKeySize || len(rootSK) != ed25519.PrivateKeySize {
		return nil, errors.New("protocol: invalid key size")
	}
	if subtle.ConstantTimeCompare(onlineSK, ed25519.NewKeyFromSeed(onlineSK[:ed25519.SeedSize])) != 1 {
		return nil, errors.New("protocol: Ed25519 online private key has inconsistent public half")
	}
	if subtle.ConstantTimeCompare(rootSK, ed25519.NewKeyFromSeed(rootSK[:ed25519.SeedSize])) != 1 {
		return nil, errors.New("protocol: Ed25519 root private key has inconsistent public half")
	}
	if !mint.Before(maxt) {
		return nil, errors.New("protocol: MINT must be before MAXT")
	}
	normalized, err := normalizeCertificateVersions(versions, schemeEd25519)
	if err != nil {
		return nil, err
	}
	// Validate every configured encoding before copying the online secret.
	// Constructor errors must not leave an abandoned private-key clone for the
	// garbage collector to reclaim later.
	for _, v := range normalized {
		g := wireGroupOf(v, false)
		if err := validateTimestampEncoding(mint, g); err != nil {
			return nil, fmt.Errorf("protocol: encode MINT for %s: %w", v, err)
		}
		if err := validateTimestampEncoding(maxt, g); err != nil {
			return nil, fmt.Errorf("protocol: encode MAXT for %s: %w", v, err)
		}
	}
	ownedOnlineSK := slices.Clone(onlineSK)
	c := &Certificate{
		scheme:     schemeEd25519,
		mint:       mint,
		maxt:       maxt,
		edOnlineSK: ownedOnlineSK,
		edOnlinePK: slices.Clone(ownedOnlineSK.Public().(ed25519.PublicKey)),
		edRootPK:   slices.Clone(rootSK.Public().(ed25519.PublicKey)),
		cache:      make(map[certCacheKey][]byte),
		versions:   normalized,
		versBytes:  encodeCertificateVERS(normalized),
	}
	// Build every configured encoding from immutable certificate-owned data.
	// This keeps exported preference slices out of certificate internals and
	// makes an unsupported group a normal error instead of a cache panic.
	for _, v := range normalized {
		g := wireGroupOf(v, false)
		k := c.cacheKeyFor(g)
		if _, ok := c.cache[k]; ok {
			continue
		}
		b, err := c.buildCERT(g, rootSK, nil)
		if err != nil {
			return nil, err
		}
		c.cache[k] = b
	}
	return c, nil
}

// NewCertificateMLDSA44 creates and signs an ML-DSA-44 delegation certificate.
func NewCertificateMLDSA44(mint, maxt time.Time, onlineSK, rootSK *mldsa.PrivateKey) (*Certificate, error) {
	if onlineSK == nil || rootSK == nil {
		return nil, errors.New("protocol: nil ML-DSA key")
	}
	if !mint.Before(maxt) {
		return nil, errors.New("protocol: MINT must be before MAXT")
	}
	c := &Certificate{
		scheme:     schemeMLDSA44,
		mint:       mint,
		maxt:       maxt,
		pqOnlineSK: onlineSK,
		cache:      make(map[certCacheKey][]byte),
		versions:   []Version{VersionMLDSA44},
		versBytes:  encodeCertificateVERS([]Version{VersionMLDSA44}),
	}
	ownedOnlinePK, err := mldsa.NewPublicKey(mldsa.MLDSA44(), onlineSK.PublicKey().Bytes())
	if err != nil {
		return nil, fmt.Errorf("protocol: clone ML-DSA-44 online public key: %w", err)
	}
	c.pqOnlinePK = ownedOnlinePK
	c.pqRootPK = rootSK.PublicKey().Bytes()
	g := wireGroupOf(VersionMLDSA44, true)
	if err := validateTimestampEncoding(mint, g); err != nil {
		return nil, fmt.Errorf("protocol: encode MINT: %w", err)
	}
	if err := validateTimestampEncoding(maxt, g); err != nil {
		return nil, fmt.Errorf("protocol: encode MAXT: %w", err)
	}
	// The root private key is used only for this delegation signature. The
	// public key retained above supports SRV identity checks.
	b, err := c.buildCERT(g, nil, rootSK)
	if err != nil {
		return nil, err
	}
	c.cache[c.cacheKeyFor(g)] = b
	return c, nil
}

// Wipe clears the certificate's Ed25519 key or releases its ML-DSA-44 key
// reference. Constructor arguments are never modified.
func (c *Certificate) Wipe() {
	if c == nil {
		return
	}
	switch c.scheme {
	case schemeEd25519:
		clear(c.edOnlineSK)
		c.edOnlineSK = nil
	case schemeMLDSA44:
		c.pqOnlineSK = nil
	}
}

// cacheKeyFor returns the cache key for g's CERT encoding.
func (c *Certificate) cacheKeyFor(g wireGroup) certCacheKey {
	ctx := string(delegationContext(g))
	switch {
	case g == groupGoogle:
		return certCacheKey{ctx: ctx, micro: true, mjd: false}
	case g <= groupD07:
		return certCacheKey{ctx: ctx, micro: true, mjd: true}
	default:
		return certCacheKey{ctx: ctx, micro: false, mjd: false}
	}
}

// certBytes returns the pre-built CERT for g, or nil if g is unavailable.
func (c *Certificate) certBytes(g wireGroup) []byte {
	return c.cache[c.cacheKeyFor(g)]
}

// supportsVersion reports whether v is in the certificate's immutable server
// support set.
func (c *Certificate) supportsVersion(v Version) bool {
	return slices.Contains(c.versions, v)
}

// signedVERS returns the configured non-Google support set encoded for SREP.
func (c *Certificate) signedVERS() []byte {
	return c.versBytes
}

// rootPublicKey returns the immutable long-term public key for SRV matching.
func (c *Certificate) rootPublicKey() []byte {
	if c.scheme == schemeMLDSA44 {
		return c.pqRootPK
	}
	return c.edRootPK
}

// encodeCertificateVERS encodes configured non-Google versions in wire order.
func encodeCertificateVERS(versions []Version) []byte {
	out := make([]byte, 0, 4*len(versions))
	for _, v := range versions {
		if v == VersionGoogle {
			continue
		}
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(v))
		out = append(out, buf[:]...)
	}
	return out
}

// normalizeCertificateVersions validates, sorts, and de-duplicates a server
// support set for one signature scheme.
func normalizeCertificateVersions(versions []Version, scheme sigScheme) ([]Version, error) {
	if len(versions) == 0 {
		return nil, errors.New("protocol: empty certificate version set")
	}
	out := slices.Clone(versions)
	slices.Sort(out)
	out = slices.Compact(out)
	for _, v := range out {
		if !isRecognizedVersion(v) {
			return nil, fmt.Errorf("protocol: unsupported certificate version %s", v)
		}
		if schemeOf(v) != scheme {
			return nil, fmt.Errorf("protocol: version %s does not use %s", v, scheme)
		}
	}
	return out, nil
}

// onlinePublicKey returns the online delegation key in on-wire form.
func (c *Certificate) onlinePublicKey() []byte {
	if c.scheme == schemeMLDSA44 {
		return c.pqOnlinePK.Bytes()
	}
	return []byte(c.edOnlinePK)
}

// buildCERT constructs the CERT message for g.
func (c *Certificate) buildCERT(g wireGroup, edRootSK ed25519.PrivateKey, pqRootSK *mldsa.PrivateKey) ([]byte, error) {
	mintBuf := encodeTimestamp(c.mint, g)
	maxtBuf := encodeTimestamp(c.maxt, g)

	dele, err := encode(map[uint32][]byte{
		TagPUBK: c.onlinePublicKey(),
		TagMINT: mintBuf[:],
		TagMAXT: maxtBuf[:],
	})
	if err != nil {
		return nil, err
	}

	ctx := delegationContext(g)
	var sig []byte
	switch c.scheme {
	case schemeEd25519:
		sig = signEd25519(edRootSK, dele, ctx)
	case schemeMLDSA44:
		sig, err = signMLDSA44(pqRootSK, dele, ctx)
		if err != nil {
			return nil, fmt.Errorf("protocol: ML-DSA-44 sign DELE: %w", err)
		}
	default:
		return nil, errSchemeNotSupported
	}

	return encode(map[uint32][]byte{TagSIG: sig, TagDELE: dele})
}
