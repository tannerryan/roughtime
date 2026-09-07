// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
	"github.com/tannerryan/roughtime/protocol"
)

// TestQueryChainSkipsFailedMiddleServer checks that later links derive from the
// last successful response and that the partial chain remains verifiable.
func TestQueryChainSkipsFailedMiddleServer(t *testing.T) {
	first := newFakeServer(t)
	defer first.Close()
	middle := newFakeServer(t)
	last := newFakeServer(t)
	defer last.Close()
	middleServer := middle.server()
	middle.Close()
	servers := []roughtime.Server{first.server(), middleServer, last.server()}
	c := roughtime.Client{Timeout: 100 * time.Millisecond, MaxAttempts: 1}

	result, err := c.QueryChain(context.Background(), servers)
	if err != nil {
		t.Fatalf("QueryChain: %v", err)
	}
	if len(result.Results) != len(servers) {
		t.Fatalf("results=%d want %d", len(result.Results), len(servers))
	}
	if result.Results[0].Err != nil || result.Results[0].Response == nil {
		t.Fatalf("first result=%+v", result.Results[0])
	}
	if result.Results[1].Err == nil || result.Results[1].Response != nil {
		t.Fatalf("middle result=%+v", result.Results[1])
	}
	if result.Results[1].Address != (roughtime.Address{}) {
		t.Fatalf("failed address=%+v want zero value", result.Results[1].Address)
	}
	if result.Results[2].Err != nil || result.Results[2].Response == nil {
		t.Fatalf("last result=%+v", result.Results[2])
	}

	proof, err := result.Proof()
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	if proof.Len() != 2 {
		t.Fatalf("proof links=%d want 2", proof.Len())
	}
	if err := proof.Verify(); err != nil {
		t.Fatalf("partial proof Verify: %v", err)
	}
	if err := proof.Trust(servers); err != nil {
		t.Fatalf("partial proof Trust: %v", err)
	}
}

// TestClientNumericVersionCaps checks that decimal ecosystem versions limit the
// advertised wire list instead of acting as opaque labels.
func TestClientNumericVersionCaps(t *testing.T) {
	server := newFakeServer(t)
	defer server.Close()
	client := new(roughtime.Client)
	for _, want := range []protocol.Version{
		protocol.VersionDraft10,
		protocol.VersionDraft11,
		protocol.VersionDraft12,
	} {
		t.Run(want.ShortString(), func(t *testing.T) {
			s := server.server()
			s.Version = strconv.FormatUint(uint64(want), 10)
			response, err := client.Query(context.Background(), s)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if response.Version != want {
				t.Fatalf("version=%s want %s", response.Version, want)
			}
		})
	}

	tooOld := server.server()
	tooOld.Version = strconv.FormatUint(uint64(protocol.VersionDraft05)-1, 10)
	if _, err := roughtime.NormalizeServer(tooOld); err == nil || !strings.Contains(err.Error(), "no supported compatible wire version") {
		t.Fatalf("NormalizeServer below minimum error=%v", err)
	}
}
