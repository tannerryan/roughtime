// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package protocol is the low-level Roughtime wire layer (Google-Roughtime,
// IETF drafts 01-19, and an experimental ML-DSA-44 post-quantum variant, see
// [VersionMLDSA44] and README.md). End-user applications should use the
// high-level [github.com/tannerryan/roughtime] package.
//
// Drafts 12-19 share wire version 0x8000000c, disambiguated by [TagTYPE] (draft
// 14+). Drafts 14-15 and 16-19 specify opposite Merkle child orderings under
// those same identifiers. [CreateReplies] defaults to the draft-16+ form,
// [CreateRepliesWithOptions] can emit the draft-14/15 form, and verification
// accepts either. Request builders include TYPE by default. [RequestOptions]
// can emit the draft-12/13 form, and [VerifyOptions] can require TYPE when a
// caller intentionally targets draft 14+.
package protocol
