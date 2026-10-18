// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// TestStrictServerTransports serves RFC requests and rejects legacy formats.
func TestStrictServerTransports(t *testing.T) {
	savedMode, savedPort := *flexPort, *port
	*flexPort = 0
	t.Cleanup(func() { *flexPort, *port = savedMode, savedPort })
	disableGrease(t)
	rootPK, state := newCertState(t)
	nonce, request, err := protocol.CreateRequest([]protocol.Version{1}, rand.Reader, protocol.ComputeSRV(rootPK))
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv6loopback, Port: 5319}
	item, reason, ok := validateRequest(zap.NewNop(), request, peer, len(request), nil, state.Load(), false)
	if !ok || reason != dropNone || item.version != protocol.Version1 {
		t.Fatalf("RFC request rejected: %v", reason)
	}
	replies := signAndBuildRepliesCurrent(zap.NewNop(), state, item.version, []validatedRequest{item})
	if len(replies) != 1 {
		t.Fatal("no UDP reply")
	}
	if _, got, err := protocol.VerifyReply([]protocol.Version{1}, replies[0].bytes, rootPK, nonce, request); err != nil || got != 3*time.Second {
		t.Fatalf("strict UDP radius = %v, error = %v", got, err)
	}

	p, done, cancel := startListenTCP(t, state, nil)
	conn := dialTCP(t, p)
	reply := tcpRoundTrip(t, conn, request)
	_ = conn.Close()
	if _, got, err := protocol.VerifyReply([]protocol.Version{1}, reply, rootPK, nonce, request); err != nil || got != 3*time.Second {
		t.Fatalf("strict TCP radius = %v, error = %v", got, err)
	}
	for _, version := range protocol.SupportedWithMode(protocol.Flex) {
		if version == protocol.Version1 {
			continue
		}
		_, legacy, err := protocol.CreateRequestWithOptions([]protocol.Version{version}, rand.Reader, nil, protocol.RequestOptions{Mode: protocol.Flex})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := validateRequest(zap.NewNop(), legacy, peer, len(legacy), nil, state.Load(), false); ok {
			t.Fatalf("strict UDP accepted %s", version)
		}
		if version != protocol.VersionGoogle {
			conn := dialTCP(t, p)
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write(legacy); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if _, err := conn.Read(b[:]); err == nil {
				t.Fatalf("strict TCP accepted %s", version)
			}
			_ = conn.Close()
		}
	}
	cancel()
	if err := awaitTest(t, done, 6*time.Second, "strict TCP shutdown"); err != nil {
		t.Fatal(err)
	}
}

// TestTCPReplyRequestBudget checks short RFC, draft, and ML-DSA-44 requests
// with padded controls.
func TestTCPReplyRequestBudget(t *testing.T) {
	savedMode := *flexPort
	t.Cleanup(func() { *flexPort = savedMode })
	disableGrease(t)
	for _, tc := range []struct {
		mode    protocol.Mode    // server compatibility mode
		version protocol.Version // selected request version
	}{
		{protocol.Strict, protocol.Version1},
		{protocol.Strict, protocol.VersionMLDSA44},
		{protocol.Flex, protocol.Version1},
		{protocol.Flex, protocol.VersionDraft10},
		{protocol.Flex, protocol.VersionDraft11},
		{protocol.Flex, protocol.VersionDraft12},
		{protocol.Flex, protocol.VersionMLDSA44},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.mode, tc.version.ShortString()), func(t *testing.T) {
			*flexPort = 0
			if tc.mode == protocol.Flex {
				*flexPort = 2002
			}
			var rootPK []byte
			var edState, pqState *atomic.Pointer[certState]
			if tc.version == protocol.VersionMLDSA44 {
				rootPK, pqState = newPQCertState(t)
			} else {
				rootPK, edState = newCertState(t)
			}
			requestMode := tc.mode
			if tc.version == protocol.VersionMLDSA44 {
				requestMode = protocol.Flex
			}
			nonce, padded, err := protocol.CreateRequestWithOptions([]protocol.Version{tc.version}, rand.Reader,
				protocol.ComputeSRV(rootPK), protocol.RequestOptions{Mode: requestMode})
			if err != nil {
				t.Fatal(err)
			}
			tags, err := protocol.Decode(padded[protocol.PacketHeaderSize:])
			if err != nil {
				t.Fatal(err)
			}
			request := append([]byte(nil), padded[:len(padded)-len(tags[protocol.TagZZZZ])]...)
			binary.LittleEndian.PutUint32(request[8:12], uint32(len(request)-protocol.PacketHeaderSize))
			p, done, cancel := startListenTCP(t, edState, pqState)
			_, _, _, err = protocol.RoundTripTCP(context.Background(), fmt.Sprintf("[::1]:%d", p), request, time.Second)
			if !errors.Is(err, protocol.ErrPeerClosedNoReply) {
				t.Fatalf("short request: %v", err)
			}
			reply, _, _, err := protocol.RoundTripTCP(context.Background(), fmt.Sprintf("[::1]:%d", p), padded, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if len(reply) > len(padded) {
				t.Fatal("TCP reply exceeds request")
			}
			if _, got, err := protocol.VerifyReplyWithOptions([]protocol.Version{tc.version}, reply, rootPK, nonce, padded,
				protocol.VerifyOptions{Mode: requestMode}); err != nil || got != 3*time.Second {
				t.Fatalf("TCP radius = %v, error = %v", got, err)
			}
			cancel()
			if err := awaitTest(t, done, 6*time.Second, "TCP shutdown"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
