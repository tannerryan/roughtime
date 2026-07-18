// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"context"
	"testing"
	"time"
)

// TestResetRetryWakesWaiter covers concurrent backoff reset.
func TestResetRetryWakesWaiter(t *testing.T) {
	wake := make(chan struct{})
	c := Client{retry: &retryTracker{retries: map[string]retryState{
		"server": {notBefore: time.Now().Add(time.Hour), reset: wake},
	}}}
	done := make(chan bool, 1)
	go func() { done <- c.waitForRetry(context.Background(), "server") }()

	select {
	case <-done:
		t.Fatal("waitForRetry returned before reset")
	case <-time.After(20 * time.Millisecond):
	}
	c.resetRetry("server")
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("waitForRetry returned false after reset")
		}
	case <-time.After(time.Second):
		t.Fatal("resetRetry did not wake waiter")
	}
}
