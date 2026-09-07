// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package version

import "testing"

// TestFull covers version metadata formatting.
func TestFull(t *testing.T) {
	oldCommit, oldDate := Commit, Date
	defer func() { Commit, Date = oldCommit, oldDate }()
	for _, test := range []struct {
		commit, date, want string
	}{
		{"", "", Version},
		{"abc123", "", Version + " (abc123)"},
		{"", "2026-07-14T00:00:00Z", Version + " (2026-07-14T00:00:00Z)"},
		{"abc123", "2026-07-14T00:00:00Z", Version + " (abc123, 2026-07-14T00:00:00Z)"},
	} {
		Commit, Date = test.commit, test.date
		if got := Full(); got != test.want {
			t.Errorf("Full() = %q, want %q", got, test.want)
		}
	}
}
