// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package protocol is the low-level Roughtime wire layer (Google-Roughtime,
// IETF drafts 01-19, and an experimental ML-DSA-44 post-quantum variant — see
// [VersionMLDSA44] and README.md). End-user applications should use the
// high-level [github.com/tannerryan/roughtime] package; this package stays
// exposed for the cmd/ binaries (server, client, bench, debug, stamp).
//
// Drafts 12-19 share wire version 0x8000000c, disambiguated by [TagTYPE] (draft
// 14+). Multi-request batches to draft 14-15 peers are not strictly conformant
// (node-first vs hash-first Merkle ordering); single-request replies are
// unaffected.
//
// File layout:
//   - tags.go       — IANA Roughtime tag constants
//   - version.go    — Version type, negotiation, server preference lists
//   - wiregroup.go  — wireGroup type and per-group capability flags
//   - codec.go      — packet header, tag-value encoding/decoding
//   - timestamp.go  — MJD-µs and Unix timestamp encoding/decoding
//   - merkle.go     — Merkle tree primitives + verification
//   - signature.go  — Ed25519 / ML-DSA-44 sign/verify dispatch
//   - cert.go       — delegation certificate construction
//   - request.go    — Request type, ParseRequest, CreateRequest, CreateRequestWithNonce, ComputeSRV
//   - reply.go      — CreateReplies and SREP construction
//   - verify.go     — VerifyReply, ExtractVersion, signature/Merkle verification
//   - grease.go     — Grease for client-resilience testing
//   - chain.go      — causal chain mechanics
//   - malfeasance.go — JSON malfeasance report serialization
//   - transport.go  — UDP/TCP round-trip helpers
package protocol
