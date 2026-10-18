// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// TestRetryResponseFreshness checks replay rejection in both modes, including
// fixed document seeds and regenerated later-chain blinds.
func TestRetryResponseFreshness(t *testing.T) {
	for _, kind := range []string{"query", "chain", "seeded chain", "caller nonce", "seeded first", "flex query", "flex chain", "flex seeded chain", "flex caller nonce", "flex seeded first", "flex draft query", "flex draft chain", "flex draft caller nonce"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			mode := protocol.Strict
			if strings.HasPrefix(kind, "flex ") {
				mode = protocol.Flex
			}
			kind := strings.TrimPrefix(kind, "flex ")
			f := newFakeServer(t)
			defer f.Close()
			draftProfile := strings.HasPrefix(kind, "draft ")
			if draftProfile {
				f.setVersions(protocol.VersionDraft12)
				kind = strings.TrimPrefix(kind, "draft ")
			}
			listener, err := net.Listen("tcp", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			expected := 3
			requests := make(chan [][]byte, 1)
			go func() {
				var seen [][]byte
				defer func() { requests <- seen }()
				var original []byte
				for i := range expected {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					var header [protocol.PacketHeaderSize]byte
					_, err = io.ReadFull(conn, header[:])
					length, headerErr := protocol.ParsePacketHeader(header[:])
					if err != nil || headerErr != nil || length > 8192 {
						_ = conn.Close()
						return
					}
					raw := make([]byte, len(header)+int(length))
					copy(raw, header[:])
					_, err = io.ReadFull(conn, raw[len(header):])
					if err != nil {
						_ = conn.Close()
						return
					}
					seen = append(seen, raw)
					reply, err := f.handle(raw)
					if err != nil {
						_ = conn.Close()
						return
					}
					if i == 0 {
						original = bytes.Clone(reply)
						reply[0] ^= 1
					} else if i == 1 {
						reply = original
					}
					_, _ = conn.Write(reply)
					_ = conn.Close()
				}
			}()
			server := roughtime.Server{PublicKey: f.rootPK, Addresses: []roughtime.Address{{Transport: "tcp", Address: listener.Addr().String()}}}
			client := &roughtime.Client{Mode: mode, Timeout: 250 * time.Millisecond, MaxAttempts: 3}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var response *roughtime.Response
			switch kind {
			case "chain", "seeded chain", "seeded first":
				first := f.server()
				if draftProfile {
					first.Version = ""
				}
				servers := []roughtime.Server{first, server}
				if kind == "seeded first" {
					servers = []roughtime.Server{server}
				}
				var result *roughtime.ChainResult
				if kind == "chain" {
					result, err = client.QueryChain(ctx, servers)
				} else {
					result, err = client.QueryChainWithNonce(ctx, servers, bytes.Repeat([]byte{0x42}, 32))
				}
				if err == nil {
					if len(servers) > 1 && result.Results[0].Err != nil {
						t.Fatalf("first chain link: %v", result.Results[0].Err)
					}
					last := result.Results[len(servers)-1]
					response, err = last.Response, last.Err
				}
				if err == nil {
					proof, proofErr := result.Proof()
					if proofErr != nil {
						t.Fatal(proofErr)
					}
					if err := proof.Verify(); err != nil {
						t.Fatalf("retry broke nonce linkage: %v", err)
					}
				}
			case "caller nonce":
				response, err = client.QueryWithNonce(ctx, server, bytes.Repeat([]byte{0x42}, 32))
			default:
				response, err = client.Query(ctx, server)
			}
			if kind == "caller nonce" || kind == "seeded first" {
				if err == nil || response != nil {
					t.Fatal("fixed nonce accepted a response after its delay limit")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var seen [][]byte
			select {
			case seen = <-requests:
			case <-ctx.Done():
				t.Fatal("proxy did not finish")
			}
			if len(seen) != expected {
				t.Fatalf("got %d requests, want %d", len(seen), expected)
			}
			wantSame := kind == "caller nonce" || kind == "seeded first"
			if bytes.Equal(seen[0], seen[1]) != wantSame {
				t.Fatal("retry did not follow nonce policy")
			}
			if response != nil && !bytes.Equal(response.Request, seen[expected-1]) {
				t.Fatal("response archived a different request")
			}
			if draftProfile && response != nil && response.Version != protocol.VersionDraft12 {
				t.Fatalf("expected draft response, got %s", response.Version)
			}
		})
	}
}
