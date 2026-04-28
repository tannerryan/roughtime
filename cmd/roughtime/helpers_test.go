// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/mldsa"
	"github.com/tannerryan/roughtime/protocol"
)

// pickFreeTCPPort returns an ephemeral TCP port after closing the holder
// socket.
func pickFreeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatalf("pick free TCP port: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// pickFreeUDPPort returns an ephemeral UDP port after closing the holder
// socket.
func pickFreeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0})
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return p
}

// newUnitCertState builds an unwrapped Ed25519 certState valid for one hour
// either side of now.
func newUnitCertState(t *testing.T) (ed25519.PublicKey, *certState) {
	t.Helper()
	rootPK, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen online: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificate(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	return rootPK, &certState{cert: cert, expiry: now.Add(time.Hour), srvHash: protocol.ComputeSRV(rootPK)}
}

// newCertState builds an in-memory Ed25519 certState valid across the standard
// delegation window.
func newCertState(t *testing.T) (ed25519.PublicKey, *atomic.Pointer[certState]) {
	t.Helper()
	rootPK, rootSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 root: %v", err)
	}
	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 online: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificate(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	st := &atomic.Pointer[certState]{}
	st.Store(&certState{cert: cert, expiry: now.Add(certEndOffset), srvHash: protocol.ComputeSRV(rootPK)})
	return rootPK, st
}

// newPQCertState builds an in-memory ML-DSA-44 certState valid across the
// standard delegation window.
func newPQCertState(t *testing.T) ([]byte, *atomic.Pointer[certState]) {
	t.Helper()
	rootSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa root: %v", err)
	}
	onlineSK, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa online: %v", err)
	}
	now := time.Now()
	cert, err := protocol.NewCertificateMLDSA44(now.Add(certStartOffset), now.Add(certEndOffset), onlineSK, rootSK)
	if err != nil {
		t.Fatalf("NewCertificateMLDSA44: %v", err)
	}
	rootPK := rootSK.PublicKey().Bytes()
	st := &atomic.Pointer[certState]{}
	st.Store(&certState{cert: cert, expiry: now.Add(certEndOffset), srvHash: protocol.ComputeSRV(rootPK)})
	return rootPK, st
}
