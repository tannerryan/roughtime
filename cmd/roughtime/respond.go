// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	mrand "math/rand/v2"
	"net"
	"sync/atomic"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// validatedRequest is a parsed UDP request ready for batch signing.
type validatedRequest struct {
	req         protocol.Request
	peer        *net.UDPAddr
	requestSize int
	bufPtr      *[]byte
	version     protocol.Version
}

// batchKey groups requests that can share a single signing operation.
type batchKey struct {
	version protocol.Version
	hasType bool
}

// readyReply is a response awaiting send.
type readyReply struct {
	peer  *net.UDPAddr
	bytes []byte
}

// validateRequest parses a request, validates SRV, and negotiates a version. On
// failure the dropReason classifies the rejection.
func validateRequest(log *zap.Logger, requestBytes []byte, peer *net.UDPAddr, reqSize int, bufPtr *[]byte, st *certState) (validatedRequest, dropReason, bool) {
	req, err := protocol.ParseRequest(requestBytes)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "request parse failed"); ce != nil {
			ce.Write(
				zap.Stringer("peer", peer),
				zap.Int("size", len(requestBytes)),
				zap.Error(err),
			)
		}
		return validatedRequest{}, dropParse, false
	}
	// drafts 10+: reject when SRV does not address a long-term key
	if req.SRV != nil && !bytes.Equal(req.SRV, st.srvHash) {
		if ce := log.Check(zap.DebugLevel, "SRV mismatch"); ce != nil {
			ce.Write(zap.Stringer("peer", peer))
		}
		return validatedRequest{}, dropSRV, false
	}
	responseVer, err := protocol.SelectVersion(req.Versions, len(req.Nonce), protocol.ServerPreferenceEd25519)
	if err != nil {
		if ce := log.Check(zap.DebugLevel, "version negotiation failed"); ce != nil {
			ce.Write(zap.Stringer("peer", peer), zap.Error(err))
		}
		return validatedRequest{}, dropVersion, false
	}
	return validatedRequest{
		req:         *req,
		peer:        peer,
		requestSize: reqSize,
		bufPtr:      bufPtr,
		version:     responseVer,
	}, dropNone, true
}

// rejectUDPBatch records a certificate-state failure for every item.
func rejectUDPBatch(log *zap.Logger, ver protocol.Version, items []validatedRequest, message string) []readyReply {
	statsBatchErrs.Add(1)
	for range items {
		incDropped(transportUDP, dropBatchErr)
	}
	log.Warn(message,
		zap.Stringer("version", ver),
		zap.Int("batch_size", len(items)),
	)
	return nil
}

// signAndBuildRepliesCurrent signs a homogeneous UDP batch with the currently
// published certificate.
func signAndBuildRepliesCurrent(log *zap.Logger, state *atomic.Pointer[certState], ver protocol.Version, items []validatedRequest) []readyReply {
	st := acquireCurrent(state)
	if st == nil {
		return rejectUDPBatch(log, ver, items, "active certificate unavailable before signing")
	}
	defer st.release()

	now := wallClockNow()
	if now.Before(st.notBefore) {
		return rejectUDPBatch(log, ver, items, "not-yet-valid certificate rejected before signing")
	}
	if !now.Before(st.expiry) {
		return rejectUDPBatch(log, ver, items, "expired certificate rejected before signing")
	}
	reqs := make([]protocol.Request, len(items))
	for i := range items {
		reqs[i] = items[i].req
	}

	// zero midpoint defers timestamping to CreateReplies
	replies, err := protocol.CreateReplies(ver, reqs, time.Time{}, radius, st.cert)
	if err != nil {
		statsBatchErrs.Add(1)
		// per-item bumps keep dropped/batch_err parity with the TCP path
		for range items {
			incDropped(transportUDP, dropBatchErr)
		}
		log.Warn("batch CreateReplies failed",
			zap.Stringer("version", ver),
			zap.Int("batch_size", len(items)),
			zap.Error(err),
		)
		return nil
	}

	statsBatches.Add(1)
	statsBatchedReqs.Add(uint64(len(items)))

	out := make([]readyReply, 0, len(replies))
	for i, reply := range replies {
		// fall back to ungreased if grease would exceed the amplification
		// budget
		if *greaseRate > 0 && mrand.Float64() < *greaseRate {
			if greased := protocol.Grease(reply, ver); len(greased) <= items[i].requestSize {
				reply = greased
				if ce := log.Check(zap.DebugLevel, "greased response"); ce != nil {
					ce.Write(zap.Stringer("peer", items[i].peer))
				}
			}
		}

		// amplification protection: reply MUST NOT exceed request size on UDP
		if len(reply) > items[i].requestSize {
			statsAmpDropped.Add(1)
			log.Warn("amplification-blocked response",
				zap.Stringer("peer", items[i].peer),
				zap.Int("request_size", items[i].requestSize),
				zap.Int("reply_size", len(reply)),
				zap.Stringer("version", ver),
			)
			continue
		}
		out = append(out, readyReply{peer: items[i].peer, bytes: reply})
	}
	return out
}
