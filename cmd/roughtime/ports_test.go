// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

// TestServerPortDefaults checks the RFC default and the replacement
// compatibility flag.
func TestServerPortDefaults(t *testing.T) {
	if got := flag.Lookup("port").DefValue; got != "5319" {
		t.Fatalf("default port = %s, want 5319", got)
	}
	if got := flag.Lookup("flex-port").DefValue; got != "0" {
		t.Fatalf("default compatibility port = %s, want disabled", got)
	}
	if flag.Lookup("flex") != nil {
		t.Fatal("obsolete server -flex flag is registered")
	}
}

// TestFlexPortValidation rejects invalid ports and duplicate listeners.
func TestFlexPortValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string // subtest label
		extra int    // optional second port
		want  string // expected error fragment, empty for valid flags
	}{
		{"disabled", 0, ""},
		{"negative", -1, "1-65535"},
		{"too large", 65536, "1-65535"},
		{"duplicate", 5319, "must differ"},
		{"standard", 2002, ""},
		{"custom", 6000, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFlagGlobals(t, "root.key", "", "error", 5319, 0)
			*flexPort = tc.extra
			err := validateFlags()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation = %v, want %q", err, tc.want)
			}
		})
	}
	withFlagGlobals(t, "", "pq.key", "error", 5319, 0)
	if err := validateFlags(); err != nil {
		t.Fatalf("ML-DSA-44 without compatibility listener: %v", err)
	}
}

// TestTCPSecondPortBindFailure checks that partial startup releases earlier
// listeners.
func TestTCPSecondPortBindFailure(t *testing.T) {
	withFlagGlobals(t, "root.key", "", "error", 5319, 0)
	occupied, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	first := pickFreeTCPPort(t)
	second := occupied.Addr().(*net.TCPAddr).Port
	_, state := newCertState(t)
	err = listenTCP(context.Background(), state, nil, []int{first, second})
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("binding occupied second port: %v", err)
	}
	for _, network := range listenNetworks("tcp", serverListenAddr(first)) {
		ln, err := net.Listen(network, serverListenAddr(first))
		if err != nil {
			t.Fatalf("first listener retained: %v", err)
		}
		_ = ln.Close()
	}
}

// TestTCPBatcherSeparatesPortProfiles checks RFC requests from both listeners
// cannot share a signed VERS advertisement when they reach one batcher.
func TestTCPBatcherSeparatesPortProfiles(t *testing.T) {
	disableGrease(t)
	rootPK, state := newCertState(t)
	nonce, packet, err := protocol.CreateRequest([]protocol.Version{protocol.Version1}, rand.Reader, protocol.ComputeSRV(rootPK))
	if err != nil {
		t.Fatal(err)
	}
	request, err := protocol.ParseRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	queue := make(chan tcpBatchItem, 2)
	results := make([]chan tcpBatchReply, 2)
	for i := range results {
		results[i] = make(chan tcpBatchReply, 1)
		queue <- tcpBatchItem{req: *request, version: protocol.Version1, hasType: true, rfcOnly: i == 0, reply: results[i]}
	}
	close(queue)
	tcpBatcher(zap.NewNop(), state, queue, 4, time.Second)
	for i, resultCh := range results {
		result := <-resultCh
		if result.err != nil {
			t.Fatal(result.err)
		}
		if _, _, err := protocol.VerifyReply([]protocol.Version{protocol.Version1}, result.bytes, rootPK, nonce, packet); err != nil {
			t.Fatal(err)
		}
		checkListenerVERS(t, result.bytes, i == 0)
	}
}
