// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"slices"
	"time"
)

// ConsensusReport summarizes drift across the successful subset of a
// [Client.QueryAll] result slice.
type ConsensusReport struct {
	// Median is the upper-middle drift across successful results.
	Median time.Duration
	// Min is the smallest drift among successful results.
	Min time.Duration
	// Max is the largest drift among successful results.
	Max time.Duration
	// Samples is the count of successful results contributing to the report.
	Samples int
}

// Consensus computes drift statistics across the successful entries in results.
func Consensus(results []Result) ConsensusReport {
	drifts := make([]time.Duration, 0, len(results))
	for _, r := range results {
		if r.Err == nil && r.Response != nil {
			drifts = append(drifts, r.Response.Drift())
		}
	}
	if len(drifts) == 0 {
		return ConsensusReport{}
	}
	slices.Sort(drifts)
	// Even-N picks the upper middle, not the mean: averaging would synthesize a
	// drift no server actually reported.
	return ConsensusReport{
		Median:  drifts[len(drifts)/2],
		Min:     drifts[0],
		Max:     drifts[len(drifts)-1],
		Samples: len(drifts),
	}
}
