// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime_test

import (
	"testing"
	"time"

	"github.com/tannerryan/roughtime"
)

// TestResponseDrift covers RTT centering, sign, and odd-duration truncation.
func TestResponseDrift(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	r := &roughtime.Response{
		Midpoint: base.Add(13 * time.Nanosecond),
		LocalNow: base.Add(10 * time.Nanosecond),
		RTT:      5 * time.Nanosecond,
	}
	if got := r.Drift(); got != 5*time.Nanosecond {
		t.Fatalf("Drift = %s, want 5ns", got)
	}
	r.Midpoint = base
	if got := r.Drift(); got != -8*time.Nanosecond {
		t.Fatalf("negative Drift = %s, want -8ns", got)
	}
}

// TestResponseInSyncStrictPointEstimate documents the compatibility-preserved
// semantics: the RTT-center estimate, not the whole exchange interval, is
// compared with the signed server interval.
func TestResponseInSyncStrictPointEstimate(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name string
		r    *roughtime.Response
		want bool
	}{
		{"nil", nil, false},
		{"negative radius", &roughtime.Response{Radius: -time.Nanosecond}, false},
		{"zero exact", &roughtime.Response{Midpoint: base, LocalNow: base}, true},
		{"positive boundary", &roughtime.Response{Midpoint: base.Add(time.Millisecond), LocalNow: base, Radius: time.Millisecond}, true},
		{"negative boundary", &roughtime.Response{Midpoint: base.Add(-time.Millisecond), LocalNow: base, Radius: time.Millisecond}, true},
		{"outside", &roughtime.Response{Midpoint: base.Add(time.Millisecond + time.Nanosecond), LocalNow: base, Radius: time.Millisecond}, false},
		{
			"asymmetric route remains strict",
			&roughtime.Response{
				Midpoint: base.Add(70 * time.Millisecond),
				Radius:   time.Millisecond,
				RTT:      100 * time.Millisecond,
				LocalNow: base.Add(100 * time.Millisecond),
			},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.InSync(); got != tc.want {
				t.Fatalf("InSync = %v, want %v", got, tc.want)
			}
		})
	}
}
