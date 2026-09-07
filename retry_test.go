// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package roughtime

import (
	"context"
	"sync"
	"testing"
	"time"
)

// failedClient returns a client whose key is already in a failed cooldown.
func failedClient(key string, notBefore time.Time) Client {
	return Client{retry: &retryTracker{retries: map[string]*retryState{
		key: {
			interval:   retryBackoffInitial,
			notBefore:  notBefore,
			generation: 1,
			changed:    make(chan struct{}),
		},
	}}}
}

// TestResetRetryWakesWaiter covers a verified response clearing a cooldown.
func TestResetRetryWakesWaiter(t *testing.T) {
	c := failedClient("server", time.Now().Add(time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	wakeAttempt := retryAttempt{
		key:        "server",
		state:      c.retry.retries["server"],
		generation: 0, // success may come from an older parallel generation
	}
	wakeAttempt.state.active++
	done := make(chan retryAttempt, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		attempt, ok := c.waitForRetry(ctx, "server")
		if ok {
			done <- attempt
		}
	}()

	select {
	case <-done:
		t.Fatal("waitForRetry returned before reset")
	case <-time.After(20 * time.Millisecond):
	}
	c.resetRetry(wakeAttempt)
	select {
	case attempt := <-done:
		c.releaseRetry(attempt)
	case <-ctx.Done():
		t.Fatalf("resetRetry did not wake waiter: %v", ctx.Err())
	}
}

// TestRetryCooldownReservesOneProbe covers the same-root thundering-herd
// regression: expiry admits exactly one exchange until its outcome is known.
func TestRetryCooldownReservesOneProbe(t *testing.T) {
	c := failedClient("server", time.Now().Add(25*time.Millisecond))
	const waiters = 8
	started := make(chan retryAttempt, waiters)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	wg.Add(waiters)
	for range waiters {
		go func() {
			defer wg.Done()
			attempt, ok := c.waitForRetry(ctx, "server")
			if ok {
				started <- attempt
			}
		}()
	}

	var probe retryAttempt
	select {
	case probe = <-started:
		if !probe.probe {
			t.Fatal("cooldown expiry admitted an unreserved attempt")
		}
	case <-ctx.Done():
		t.Fatalf("no probe admitted at cooldown expiry: %v", ctx.Err())
	}
	select {
	case <-started:
		t.Fatal("more than one same-root probe admitted")
	case <-time.After(25 * time.Millisecond):
	}

	// A failed probe advances the schedule once and keeps peers queued.
	c.recordRetryFailure(probe)
	if got := c.retry.retries["server"].interval; got != 1500*time.Millisecond {
		t.Fatalf("retry interval = %s, want 1.5s", got)
	}
	cancel()
}

// TestRetryCanceledProbeHandsOff covers cancellation after reservation. It is
// not recorded as another server failure, and another waiter can proceed.
func TestRetryCanceledProbeHandsOff(t *testing.T) {
	c := failedClient("server", time.Now().Add(-time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	first, ok := c.waitForRetry(context.Background(), "server")
	if !ok || !first.probe {
		t.Fatal("first probe was not reserved")
	}
	done := make(chan retryAttempt, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		attempt, ok := c.waitForRetry(ctx, "server")
		if ok {
			done <- attempt
		}
	}()
	select {
	case <-done:
		t.Fatal("second probe admitted while first was active")
	case <-time.After(20 * time.Millisecond):
	}
	c.releaseRetry(first)
	select {
	case second := <-done:
		if !second.probe {
			t.Fatal("replacement attempt was not a probe")
		}
		c.releaseRetry(second)
	case <-ctx.Done():
		t.Fatalf("canceled probe did not hand reservation off: %v", ctx.Err())
	}
}

// TestRetrySuccessWinsFailureRace covers an older failure completing after a
// properly verified parallel response reset the state.
func TestRetrySuccessWinsFailureRace(t *testing.T) {
	var c Client
	success, ok := c.waitForRetry(context.Background(), "server")
	if !ok {
		t.Fatal("success attempt not admitted")
	}
	failure, ok := c.waitForRetry(context.Background(), "server")
	if !ok {
		t.Fatal("failure attempt not admitted in healthy state")
	}
	c.resetRetry(success)
	c.recordRetryFailure(failure)

	next, ok := c.waitForRetry(context.Background(), "server")
	if !ok || next.probe {
		t.Fatal("stale failure reinstated cooldown after success")
	}
	c.releaseRetry(next)
}

// TestRetryConcurrentHealthyFailuresCountOnce covers the initial healthy burst:
// all exchanges run, but their one shared failure cohort advances the cooldown
// only once.
func TestRetryConcurrentHealthyFailuresCountOnce(t *testing.T) {
	var c Client
	attempts := make([]retryAttempt, 8)
	for i := range attempts {
		var ok bool
		attempts[i], ok = c.waitForRetry(context.Background(), "server")
		if !ok || attempts[i].probe {
			t.Fatalf("healthy attempt %d was not admitted normally", i)
		}
	}
	for _, attempt := range attempts {
		c.recordRetryFailure(attempt)
	}
	if got := c.retry.retries["server"].interval; got != retryBackoffInitial {
		t.Fatalf("retry interval = %s, want one initial %s penalty", got, retryBackoffInitial)
	}
}

// TestRetryDistinctRootsReserveIndependently covers per-root rather than global
// coordination.
func TestRetryDistinctRootsReserveIndependently(t *testing.T) {
	c := failedClient("a", time.Now().Add(-time.Second))
	c.retry.retries["b"] = &retryState{
		interval:   retryBackoffInitial,
		notBefore:  time.Now().Add(-time.Second),
		generation: 1,
		changed:    make(chan struct{}),
	}
	a, okA := c.waitForRetry(context.Background(), "a")
	b, okB := c.waitForRetry(context.Background(), "b")
	if !okA || !okB || !a.probe || !b.probe {
		t.Fatalf("distinct probes: a=(%v,%v) b=(%v,%v)", okA, a.probe, okB, b.probe)
	}
	c.releaseRetry(a)
	c.releaseRetry(b)
}

// TestWaitForRetryContext covers cancellation while queued behind a failure.
func TestWaitForRetryContext(t *testing.T) {
	c := failedClient("server", time.Now().Add(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := c.waitForRetry(ctx, "server"); ok {
		t.Fatal("waitForRetry ignored canceled context")
	}
}

// TestNextBackoff covers the exact progression and cap.
func TestNextBackoff(t *testing.T) {
	if got := nextBackoff(time.Second); got != 1500*time.Millisecond {
		t.Fatalf("nextBackoff(1s) = %s, want 1.5s", got)
	}
	if got := nextBackoff(20 * time.Hour); got != retryBackoffMax {
		t.Fatalf("nextBackoff(20h) = %s, want %s", got, retryBackoffMax)
	}
	if got := nextBackoff(retryBackoffMax); got != retryBackoffMax {
		t.Fatalf("nextBackoff(cap) = %s, want %s", got, retryBackoffMax)
	}
}
