// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"encoding/binary"
	mrand "math/rand/v2"
)

// Grease applies a random grease transformation to a signed reply.
func Grease(reply []byte, ver Version) []byte {
	mode := mrand.IntN(4)
	switch mode {
	case 1:
		if out := greaseDropTag(reply, ver); out != nil {
			return out
		}
	case 2:
		if out := greaseWrongVersion(reply, ver); out != nil {
			return out
		}
	case 3:
		if out := greaseUndefinedTag(reply, ver); out != nil {
			return out
		}
	}
	// mode 0 or fallback; if no SIG location is found, fall back to
	// undefined-tag grease so the reply is never returned unchanged
	if greaseCorruptSig(reply, ver) {
		return reply
	}
	if out := greaseUndefinedTag(reply, ver); out != nil {
		return out
	}
	return reply
}

// greaseSplit separates a reply into its ROUGHTIM header and body.
func greaseSplit(reply []byte, ver Version) (header, body []byte) {
	if ver == VersionGoogle {
		return nil, reply
	}
	if len(reply) < 12 {
		return nil, nil
	}
	return reply[:12], reply[12:]
}

// greaseJoin prepends the ROUGHTIM header to a re-encoded body, fixing the
// length field.
func greaseJoin(header, body []byte) []byte {
	if header == nil {
		return body
	}
	out := make([]byte, len(header)+len(body))
	copy(out, header)
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(body)))
	copy(out[len(header):], body)
	return out
}

// greaseCorruptSig corrupts a randomly chosen signature and MIDP in place.
func greaseCorruptSig(reply []byte, ver Version) bool {
	_, body := greaseSplit(reply, ver)
	if body == nil {
		return false
	}
	base := uint32(len(reply) - len(body))

	sigCorrupted := false
	if mrand.IntN(2) == 0 {
		if certLo, certHi, ok := findTagRange(body, TagCERT); ok && certHi > certLo {
			cert := body[certLo:certHi]
			if sigLo, sigHi, ok := findTagRange(cert, TagSIG); ok && sigHi > sigLo {
				reply[base+certLo+sigLo+uint32(mrand.IntN(int(sigHi-sigLo)))] ^= 0xff
				sigCorrupted = true
			}
		}
	} else {
		if lo, hi, ok := findTagRange(body, TagSIG); ok && hi > lo {
			reply[base+lo+uint32(mrand.IntN(int(hi-lo)))] ^= 0xff
			sigCorrupted = true
		}
	}
	if !sigCorrupted {
		return false
	}
	if srepLo, srepHi, ok := findTagRange(body, TagSREP); ok && srepHi > srepLo {
		srep := body[srepLo:srepHi]
		if midpLo, midpHi, ok := findTagRange(srep, TagMIDP); ok && midpHi > midpLo {
			reply[base+srepLo+midpLo+uint32(mrand.IntN(int(midpHi-midpLo)))] ^= 0xff
		}
	}
	return true
}

// greaseDropTag removes a randomly chosen mandatory tag from the response,
// SREP, or CERT.
func greaseDropTag(reply []byte, ver Version) []byte {
	header, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	msg, err := Decode(body)
	if err != nil {
		return nil
	}
	scopes := []uint32{0, TagSREP, TagCERT}
	mrand.Shuffle(len(scopes), func(i, j int) { scopes[i], scopes[j] = scopes[j], scopes[i] })
	// drop only tags whose absence breaks verification; NONC echo and TYPE are
	// tolerated, so neither is a valid drop target
	for _, scope := range scopes {
		if scope == 0 {
			candidates := []uint32{TagSIG, TagSREP, TagCERT, TagPATH, TagINDX}
			if out, ok := dropOneTag(msg, candidates); ok {
				encoded, err := encode(out)
				if err != nil {
					return nil
				}
				return greaseJoin(header, encoded)
			}
			continue
		}
		inner, ok := msg[scope]
		if !ok {
			continue
		}
		innerMsg, err := Decode(inner)
		if err != nil {
			continue
		}
		var candidates []uint32
		if scope == TagSREP {
			candidates = []uint32{TagRADI, TagMIDP, TagROOT}
		} else {
			candidates = []uint32{TagSIG, TagDELE}
		}
		modified, ok := dropOneTag(innerMsg, candidates)
		if !ok {
			continue
		}
		reencoded, err := encode(modified)
		if err != nil {
			return nil
		}
		msg[scope] = reencoded
		out, err := encode(msg)
		if err != nil {
			return nil
		}
		return greaseJoin(header, out)
	}
	return nil
}

// dropOneTag removes one randomly chosen candidate tag from msg.
func dropOneTag(msg map[uint32][]byte, candidates []uint32) (map[uint32][]byte, bool) {
	shuffled := append([]uint32(nil), candidates...)
	mrand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	for _, tag := range shuffled {
		if _, ok := msg[tag]; ok {
			delete(msg, tag)
			return msg, true
		}
	}
	return nil, false
}

// greaseWrongVersion overwrites top-level VER with an unsupported version.
func greaseWrongVersion(reply []byte, ver Version) []byte {
	_, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	lo, hi, ok := findTagRange(body, TagVER)
	if !ok || hi-lo != 4 {
		return nil
	}
	base := uint32(len(reply) - len(body))
	binary.LittleEndian.PutUint32(reply[base+lo:], 0xFFFFFFFF)
	return reply
}

// greaseUndefinedTag adds an undefined tag with random content.
func greaseUndefinedTag(reply []byte, ver Version) []byte {
	header, body := greaseSplit(reply, ver)
	if body == nil {
		return nil
	}
	msg, err := Decode(body)
	if err != nil {
		return nil
	}
	// GRSE (0x45535247) is not in the IANA Roughtime tag registry
	const tagGRSE uint32 = 0x45535247
	var val [4]byte
	binary.LittleEndian.PutUint32(val[:], mrand.Uint32())
	msg[tagGRSE] = val[:]
	out, err := encode(msg)
	if err != nil {
		return nil
	}
	return greaseJoin(header, out)
}
