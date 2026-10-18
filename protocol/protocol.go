// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package protocol implements RFC 10049 with strict defaults. Flex mode also
// supports Google-Roughtime, IETF drafts 01-19, and the experimental
// [VersionMLDSA44] extension. Applications can use the high-level
// [github.com/tannerryan/roughtime] package.
//
// Drafts 12-19 share wire version 0x8000000c. Flex options distinguish typed
// and untyped forms and support both draft Merkle orderings.
package protocol
