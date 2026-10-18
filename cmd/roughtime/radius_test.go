// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// TestServerMidpoint checks second and microsecond alignment without discarding
// the fractional precision available to legacy profiles.
func TestServerMidpoint(t *testing.T) {
	now := time.Date(2026, 10, 17, 22, 0, 0, 987654321, time.UTC)
	for _, tc := range []struct {
		version protocol.Version // profile whose timestamp precision is checked
		nsec    int              // expected fractional nanoseconds on the wire
	}{
		{protocol.VersionGoogle, 987654000},
		{protocol.VersionDraft01, 987654000},
		{protocol.VersionDraft07, 987654000},
		{protocol.VersionDraft08, 0},
		{protocol.VersionDraft12, 0},
		{protocol.Version1, 0},
		{protocol.VersionMLDSA44, 0},
	} {
		t.Run(tc.version.ShortString(), func(t *testing.T) {
			want := time.Date(2026, 10, 17, 22, 0, 0, tc.nsec, time.UTC)
			if got := serverMidpoint(now, tc.version); !got.Equal(want) {
				t.Fatalf("midpoint = %v, want %v", got, want)
			}
		})
	}
}

// TestServerRadius checks the total advertised uncertainty through both batch
// signing paths for every supported profile.
func TestServerRadius(t *testing.T) {
	savedPort := *flexPort
	*flexPort = 2002
	t.Cleanup(func() { *flexPort = savedPort })
	disableGrease(t)
	edPK, edState := newCertState(t)
	pqPK, pqState := newPQCertState(t)
	t.Cleanup(edState.Load().cert.Wipe)
	t.Cleanup(pqState.Load().cert.Wipe)

	for _, ver := range protocol.SupportedWithMode(protocol.Flex) {
		t.Run(ver.ShortString(), func(t *testing.T) {
			rootPK, state := []byte(edPK), edState
			if ver == protocol.VersionMLDSA44 {
				rootPK, state = pqPK, pqState
			}
			nonce, packet, err := protocol.CreateRequestWithOptions([]protocol.Version{ver}, rand.Reader,
				protocol.ComputeSRV(rootPK), protocol.RequestOptions{Mode: protocol.Flex})
			if err != nil {
				t.Fatal(err)
			}
			req, err := protocol.ParseRequestWithMode(packet, protocol.Flex)
			if err != nil {
				t.Fatal(err)
			}
			for _, transport := range []string{"udp", "tcp"} {
				if transport == "udp" && ver == protocol.VersionMLDSA44 || transport == "tcp" && ver == protocol.VersionGoogle {
					continue
				}
				t.Run(transport, func(t *testing.T) {
					var reply []byte
					if transport == "udp" {
						replies := signAndBuildRepliesCurrent(zap.NewNop(), state, ver,
							[]validatedRequest{{req: *req, requestSize: len(packet), version: ver}})
						if len(replies) != 1 {
							t.Fatal("missing UDP reply")
						}
						reply = replies[0].bytes
					} else {
						ch := make(chan tcpBatchReply, 1)
						flushTCPBatchCurrent(zap.NewNop(), state, ver,
							[]tcpBatchItem{{req: *req, version: ver, hasType: req.HasType, reply: ch}})
						result := awaitTest(t, ch, time.Second, "signed TCP reply")
						if result.err != nil {
							t.Fatal(result.err)
						}
						reply = result.bytes
					}
					_, got, err := protocol.VerifyReplyWithOptions([]protocol.Version{ver}, reply, rootPK, nonce, packet,
						protocol.VerifyOptions{Mode: protocol.Flex})
					if err != nil {
						t.Fatal(err)
					}
					if got != 3*time.Second {
						t.Fatalf("advertised radius = %v, want 3s", got)
					}
				})
			}
		})
	}
}
