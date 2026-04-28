// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"context"
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
)

// TestResponseDriftAndInSync verifies Drift accounts for RTT/2 and InSync
// compares against Radius.
func TestResponseDriftAndInSync(t *testing.T) {
	now := time.Unix(1000, 0)
	r := roughtime.Response{
		Midpoint: now,
		Radius:   2 * time.Second,
		RTT:      10 * time.Millisecond,
		LocalNow: now.Add(1 * time.Second),
	}
	// RTT-corrected clock at now+995ms vs midpoint now → drift ≈ -995ms
	if d := r.Drift(); d > -990*time.Millisecond || d < -1000*time.Millisecond {
		t.Fatalf("Drift = %s; want ~-995ms", d)
	}
	if !r.InSync() {
		t.Fatal("InSync = false; expected true")
	}
	r.Radius = 100 * time.Millisecond
	if r.InSync() {
		t.Fatal("InSync = true with small Radius; expected false")
	}
}

// TestResponseRawBytesPopulated verifies a successful query populates Request,
// Reply, and AmplificationOK.
func TestResponseRawBytesPopulated(t *testing.T) {
	f := newFakeServer(t)
	defer f.Close()

	var c roughtime.Client
	resp, err := c.Query(context.Background(), f.server())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Request) == 0 || len(resp.Reply) == 0 {
		t.Fatalf("raw bytes empty: req=%d reply=%d", len(resp.Request), len(resp.Reply))
	}
	if !resp.AmplificationOK {
		t.Fatalf("AmplificationOK=false; reply (%d) > request (%d)", len(resp.Reply), len(resp.Request))
	}
}
