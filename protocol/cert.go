// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"filippo.io/mldsa"
)

// Certificate holds a pre-signed online delegation, with CERT bytes built once
// per wire group and reused.
type Certificate struct {
	scheme sigScheme
	mint   time.Time
	maxt   time.Time

	edOnlineSK ed25519.PrivateKey
	edOnlinePK ed25519.PublicKey
	edRootPK   ed25519.PublicKey

	pqOnlineSK *mldsa.PrivateKey
	pqOnlinePK *mldsa.PublicKey

	cache map[certCacheKey][]byte
}

// certCacheKey identifies a unique CERT encoding shared across wire groups.
type certCacheKey struct {
	ctx   string
	micro bool
	mjd   bool
}

// NewCertificate creates and signs an Ed25519 delegation certificate.
func NewCertificate(mint, maxt time.Time, onlineSK, rootSK ed25519.PrivateKey) (*Certificate, error) {
	if len(onlineSK) != ed25519.PrivateKeySize || len(rootSK) != ed25519.PrivateKeySize {
		return nil, errors.New("protocol: invalid key size")
	}
	if !mint.Before(maxt) {
		return nil, errors.New("protocol: MINT must be before MAXT")
	}
	c := &Certificate{
		scheme:     schemeEd25519,
		mint:       mint,
		maxt:       maxt,
		edOnlineSK: onlineSK,
		edOnlinePK: onlineSK.Public().(ed25519.PublicKey),
		edRootPK:   rootSK.Public().(ed25519.PublicKey),
		cache:      make(map[certCacheKey][]byte),
	}
	for _, v := range ServerPreferenceEd25519 {
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
		pqOnlinePK: onlineSK.PublicKey(),
		cache:      make(map[certCacheKey][]byte),
	}
	g := wireGroupOf(VersionMLDSA44, true)
	b, err := c.buildCERT(g, nil, rootSK)
	if err != nil {
		return nil, err
	}
	c.cache[c.cacheKeyFor(g)] = b
	return c, nil
}

// Wipe releases the online signing key.
func (c *Certificate) Wipe() {
	if c == nil {
		return
	}
	switch c.scheme {
	case schemeEd25519:
		clear(c.edOnlineSK)
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

// certBytes returns the pre-built CERT for g and panics on cache miss.
func (c *Certificate) certBytes(g wireGroup) []byte {
	b, ok := c.cache[c.cacheKeyFor(g)]
	if !ok {
		panic(fmt.Sprintf("protocol: certificate cache miss for wire group %d", g))
	}
	return b
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
