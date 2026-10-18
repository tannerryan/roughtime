// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
)

// encodeGoogleReplyForTest encodes Google tags without using the protocol encoder.
func encodeGoogleReplyForTest(tags map[uint32][]byte) []byte {
	keys := make([]uint32, 0, len(tags))
	size := 8 * len(tags)
	for tag, value := range tags {
		keys = append(keys, tag)
		size += len(value)
	}
	slices.Sort(keys)
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw, uint32(len(keys)))
	off := 0
	for i, k := range keys {
		if i > 0 {
			binary.LittleEndian.PutUint32(raw[4*i:], uint32(off))
		}
		binary.LittleEndian.PutUint32(raw[4*len(keys)+4*i:], k)
		copy(raw[8*len(keys)+off:], tags[k])
		off += len(tags[k])
	}
	return raw
}

// TestGoogleVersionMetadata checks that unsigned VER extensions cannot relabel Google proofs.
func TestGoogleVersionMetadata(t *testing.T) {
	rootPK, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	_, onlineSK, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	cert, err := protocol.NewCertificateWithVersions(now.Add(-time.Hour), now.Add(time.Hour), onlineSK, rootSK, []protocol.Version{protocol.VersionGoogle})
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Wipe()
	chain := protocol.Chain{Mode: protocol.Flex}
	link, err := chain.NextRequest([]protocol.Version{protocol.VersionGoogle}, rootPK, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req, err := protocol.ParseRequestWithMode(link.Request, protocol.Flex)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := protocol.CreateRepliesWithOptions(protocol.VersionGoogle, []protocol.Request{*req}, now, time.Second, cert, protocol.ReplyOptions{Mode: protocol.Flex})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := protocol.Decode(replies[0])
	if err != nil {
		t.Fatal(err)
	}
	tags[protocol.TagVER] = []byte{8, 0, 0, 128}
	link.Response = encodeGoogleReplyForTest(tags)
	chain.Append(link)
	if err := chain.Verify(); err != nil {
		t.Fatal(err)
	}
	response := buildResponse(Server{Version: VersionLabelGoogle, PublicKey: rootPK}, Address{}, link.Request, link.Response, now, time.Second, time.Millisecond, now)
	if response.Version != protocol.VersionGoogle {
		t.Fatalf("Google response version=%v", response.Version)
	}
	proof := &Proof{chain: &chain}
	links, err := proof.Links()
	if err != nil {
		t.Fatal(err)
	}
	if links[0].Version != protocol.VersionGoogle {
		t.Fatal("Google proof relabeled by unsigned VER")
	}
	report, err := chain.MalfeasanceReport()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := protocol.ParseMalfeasanceReportWithMode(report, protocol.Flex)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(); err != nil {
		t.Fatalf("Google report lost verification: %v", err)
	}
}
