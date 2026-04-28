// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

// Tag constants from the IANA Roughtime tag registry.
const (
	// TagSIG is the signature tag.
	TagSIG uint32 = 0x00474953
	// TagVER is the version tag.
	TagVER uint32 = 0x00524556
	// TagSRV is the server-identifier tag.
	TagSRV uint32 = 0x00565253
	// TagNONC is the nonce tag.
	TagNONC uint32 = 0x434e4f4e
	// TagDELE is the delegation tag.
	TagDELE uint32 = 0x454c4544
	// TagTYPE is the response-type tag.
	TagTYPE uint32 = 0x45505954
	// TagPATH is the Merkle path tag.
	TagPATH uint32 = 0x48544150
	// TagRADI is the radius tag.
	TagRADI uint32 = 0x49444152
	// TagPUBK is the public key tag.
	TagPUBK uint32 = 0x4b425550
	// TagMIDP is the midpoint tag.
	TagMIDP uint32 = 0x5044494d
	// TagSREP is the signed response tag.
	TagSREP uint32 = 0x50455253
	// TagVERS is the supported-versions tag.
	TagVERS uint32 = 0x53524556
	// TagROOT is the Merkle root tag.
	TagROOT uint32 = 0x544f4f52
	// TagCERT is the certificate tag.
	TagCERT uint32 = 0x54524543
	// TagMINT is the delegation MINT tag.
	TagMINT uint32 = 0x544e494d
	// TagMAXT is the delegation MAXT tag.
	TagMAXT uint32 = 0x5458414d
	// TagINDX is the Merkle index tag.
	TagINDX uint32 = 0x58444e49
	// TagZZZZ is the drafts 08+ client padding tag.
	TagZZZZ uint32 = 0x5a5a5a5a
	// TagPAD is the Google-Roughtime client padding tag.
	TagPAD uint32 = 0xff444150

	// tagPADIETF is the drafts 01-07 client padding tag.
	tagPADIETF uint32 = 0x00444150
)
