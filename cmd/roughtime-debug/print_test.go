// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// TestDiagnosticDraft01UnsortedMaps prints an authenticated draft-01 exchange
// with unsorted request, response, SREP, CERT, and DELE maps.
func TestDiagnosticDraft01UnsortedMaps(t *testing.T) {
	rootSK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	onlineSK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	midpoint := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	cert, err := protocol.NewCertificateWithVersions(midpoint.Add(-time.Hour), midpoint.Add(time.Hour), onlineSK, rootSK, []protocol.Version{protocol.VersionDraft01})
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Wipe()
	nonce := bytes.Repeat([]byte{3}, 64)
	request, err := protocol.CreateRequestWithNonceOptions([]protocol.Version{protocol.VersionDraft01}, nonce, nil, protocol.RequestOptions{Mode: protocol.Flex})
	if err != nil {
		t.Fatal(err)
	}
	req, err := protocol.ParseRequestWithMode(request, protocol.Flex)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := protocol.CreateRepliesWithOptions(protocol.VersionDraft01, []protocol.Request{*req}, midpoint, time.Second, cert, protocol.ReplyOptions{Mode: protocol.Flex})
	if err != nil {
		t.Fatal(err)
	}
	// These maps start in canonical order, so the generic decoder is
	// sufficient.
	readMap := func(data []byte) map[uint32][]byte {
		t.Helper()
		msg, err := protocol.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}
	response := readMap(msgBody(replies[0]))
	srep := readMap(response[protocol.TagSREP])
	certificate := readMap(response[protocol.TagCERT])
	delegation := readMap(certificate[protocol.TagDELE])
	certificate[protocol.TagDELE] = reverseDiagnosticMap(delegation)
	certificate[protocol.TagSIG] = ed25519.Sign(rootSK, append([]byte("RoughTime v1 delegation signature--\x00"), certificate[protocol.TagDELE]...))
	response[protocol.TagCERT] = reverseDiagnosticMap(certificate)
	response[protocol.TagSREP] = reverseDiagnosticMap(srep)
	response[protocol.TagSIG] = ed25519.Sign(onlineSK, append([]byte("RoughTime v1 response signature\x00"), response[protocol.TagSREP]...))
	reply := bytes.Clone(replies[0])
	copy(reply[protocol.PacketHeaderSize:], reverseDiagnosticMap(response))
	copy(request[protocol.PacketHeaderSize:], reverseDiagnosticMap(readMap(msgBody(request))))
	if _, _, err := protocol.VerifyReplyWithOptions([]protocol.Version{protocol.VersionDraft01}, reply, rootSK.Public().(ed25519.PublicKey), nonce, request, protocol.VerifyOptions{Mode: protocol.Flex}); err != nil {
		t.Fatalf("independently signed unsorted exchange: %v", err)
	}
	result := probeResult{
		plan: probePlan{version: protocol.VersionDraft01}, request: request,
		reply: reply, midpoint: midpoint, radius: time.Second, localNow: midpoint,
	}
	output := captureStdout(t, func() { printDiagnostic(result) })
	if strings.Contains(output, "debug: decode:") {
		t.Fatalf("valid draft-01 exchange failed diagnostic decoding: %s", output)
	}
	for _, want := range []string{"=== Signed Response ===", "=== Certificate ===", "Online key:", "Not before:", "Not after:", "Cert validity:   true"} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q: %s", want, output)
		}
	}
}

// reverseDiagnosticMap independently encodes tags in descending numeric order.
func reverseDiagnosticMap(msg map[uint32][]byte) []byte {
	keys := make([]uint32, 0, len(msg))
	size := 8 * len(msg)
	for tag, value := range msg {
		keys = append(keys, tag)
		size += len(value)
	}
	slices.Sort(keys)
	slices.Reverse(keys)
	out := make([]byte, size)
	binary.LittleEndian.PutUint32(out, uint32(len(keys)))
	offset := 0
	for i, tag := range keys {
		if i > 0 {
			binary.LittleEndian.PutUint32(out[4*i:], uint32(offset))
		}
		binary.LittleEndian.PutUint32(out[4*len(keys)+4*i:], tag)
		copy(out[8*len(keys)+offset:], msg[tag])
		offset += len(msg[tag])
	}
	return out
}
