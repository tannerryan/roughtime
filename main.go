// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package main implements a Roughtime server that listens for UDP requests and
// responds with signed timestamps. The server automatically refreshes its
// online signing certificate before expiry. See the protocol package for
// supported versions.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

var (
	port               = flag.Int("port", 2002, "port to listen on")
	rootKeySeedHexFile = flag.String("root-key", "", "hex-encoded private key seed")
)

const (
	// radius is the Roughtime uncertainty radius included in responses.
	radius = time.Second

	// certStartOffset is how far before now the certificate validity begins.
	certStartOffset = -7 * 24 * time.Hour

	// certEndOffset is how far after now the certificate validity ends.
	certEndOffset = 42 * 24 * time.Hour

	// certRefreshThreshold is the remaining validity at which a new certificate
	// is provisioned.
	certRefreshThreshold = 14 * 24 * time.Hour

	// certCheckInterval is how often the refresh loop checks certificate
	// expiry.
	certCheckInterval = time.Hour

	// refreshRetryCooldown is the minimum delay between failed refresh
	// attempts.
	refreshRetryCooldown = 5 * time.Minute

	// maxPacketSize is the maximum Roughtime UDP packet size.
	maxPacketSize = 1280

	// socketRecvBuffer is the kernel UDP receive buffer size. A larger buffer
	// reduces packet drops under burst traffic.
	socketRecvBuffer = 4 * 1024 * 1024

	// workerQueueSize is the capacity of the dispatch channel. Requests beyond
	// this are dropped to provide backpressure under extreme load.
	workerQueueSize = 4096
)

// certState holds the current online certificate and its expiry. It is swapped
// atomically so the request path is lock-free.
type certState struct {
	cert   *protocol.Certificate
	expiry time.Time
}

// request is a unit of work dispatched from the read loop to a worker.
type request struct {
	bufPtr *[]byte
	len    int
	peer   *net.UDPAddr
}

// bufPool recycles read buffers to reduce GC pressure under high packet rates.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPacketSize)
		return &b
	},
}

func main() {
	flag.Parse()

	cert, expiry, err := provisionCertificateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	state := &atomic.Pointer[certState]{}
	state.Store(&certState{cert: cert, expiry: expiry})
	go refreshLoop(state)

	if err := listen(state); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

// provisionCertificateKey generates a fresh online signing certificate. It
// reads the root key seed from disk, derives the root Ed25519 key, generates a
// new online key pair, and signs a delegation valid from certStartOffset to
// certEndOffset relative to the current time.
func provisionCertificateKey() (*protocol.Certificate, time.Time, error) {
	rootKeySeedHex, err := os.ReadFile(*rootKeySeedHexFile)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to open root signing key file: " + err.Error())
	}
	rootKeySeed, err := hex.DecodeString(string(bytes.TrimSpace(rootKeySeedHex)))
	if err != nil {
		return nil, time.Time{}, errors.New("failed to decode root signing key seed: " + err.Error())
	}
	rootSK := ed25519.NewKeyFromSeed(rootKeySeed)

	_, onlineSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to generate online signing key: " + err.Error())
	}

	now := time.Now()
	startTime := now.Add(certStartOffset)
	endTime := now.Add(certEndOffset)

	cert, err := protocol.NewCertificate(startTime, endTime, onlineSK, rootSK)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to generate online certificate: " + err.Error())
	}
	return cert, endTime, nil
}

// refreshLoop periodically checks whether the certificate is within
// certRefreshThreshold of expiring and provisions a replacement. On failure it
// retries no more frequently than refreshRetryCooldown.
func refreshLoop(state *atomic.Pointer[certState]) {
	ticker := time.NewTicker(certCheckInterval)
	defer ticker.Stop()
	var lastAttempt time.Time

	for range ticker.C {
		cur := state.Load()
		if time.Until(cur.expiry) > certRefreshThreshold {
			continue
		}
		now := time.Now()
		if now.Sub(lastAttempt) < refreshRetryCooldown {
			continue
		}
		lastAttempt = now

		newCert, newExpiry, err := provisionCertificateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to refresh certificate: %s\n", err)
			continue
		}
		state.Store(&certState{cert: newCert, expiry: newExpiry})
	}
}

// listen starts the UDP server, spawns a fixed worker pool sized to the number
// of CPUs, and dispatches incoming requests. If workers cannot keep up, excess
// requests are dropped to maintain throughput.
func listen(state *atomic.Pointer[certState]) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		return errors.New("failed to start UDP server: " + err.Error())
	}
	_ = conn.SetReadBuffer(socketRecvBuffer)

	work := make(chan request, workerQueueSize)
	for range runtime.NumCPU() {
		go worker(conn, state, work)
	}

	for {
		bufPtr := bufPool.Get().(*[]byte)
		reqLen, peer, err := conn.ReadFromUDP(*bufPtr)
		if err != nil {
			bufPool.Put(bufPtr)
			continue
		}
		select {
		case work <- request{bufPtr: bufPtr, len: reqLen, peer: peer}:
		default:
			bufPool.Put(bufPtr)
		}
	}
}

// worker drains the work channel and processes each request for the lifetime of
// the server. It returns the read buffer to the pool after each request.
func worker(conn *net.UDPConn, state *atomic.Pointer[certState], work <-chan request) {
	for req := range work {
		handleRequest(conn, req.peer, (*req.bufPtr)[:req.len], state.Load().cert)
		bufPool.Put(req.bufPtr)
	}
}

// handleRequest parses a Roughtime request, negotiates the protocol version,
// generates a signed response, and sends it back to the peer. Invalid or
// unsupported requests are silently discarded. Responses larger than the
// request are dropped to prevent amplification attacks.
func handleRequest(conn *net.UDPConn, peer *net.UDPAddr, requestBytes []byte, cert *protocol.Certificate) {
	req, err := protocol.ParseRequest(requestBytes)
	if err != nil {
		return
	}
	responseVer, err := protocol.SelectVersion(req.Versions, len(req.Nonce))
	if err != nil {
		return
	}
	replies, err := protocol.CreateReplies(responseVer, []protocol.Request{*req}, time.Now(), radius, cert)
	if err != nil {
		return
	}
	if len(replies) != 1 {
		return
	}
	// Amplification protection: response must not exceed request size (draft-08
	// §13, draft-15 §9.7)
	if len(replies[0]) > len(requestBytes) {
		return
	}
	_, _ = conn.WriteToUDP(replies[0], peer)
}
