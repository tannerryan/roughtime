// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package protocol is the low-level Roughtime wire layer (Google-Roughtime,
// IETF drafts 01-19, and an experimental ML-DSA-44 post-quantum variant, see
// [VersionMLDSA44] and README.md). End-user applications should use the
// high-level [github.com/tannerryan/roughtime] package. This package stays
// exposed for the cmd/ binaries (server, client, bench, debug, stamp).
//
// Drafts 12-19 share wire version 0x8000000c, disambiguated by [TagTYPE] (draft
// 14+). Multi-request batches to draft 14-15 peers are not strictly conformant
// because of node-first versus hash-first Merkle ordering. Single-request
// replies are unaffected.
package protocol
