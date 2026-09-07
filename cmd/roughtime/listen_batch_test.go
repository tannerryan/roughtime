// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type batchWriteResult struct {
	n   int
	err error
}

func TestDrainUDPBatch(t *testing.T) {
	tests := []struct {
		name          string
		count         int
		results       []batchWriteResult
		wantOffsets   []int
		wantSent      int
		wantDropped   int
		wantRemaining int
		wantErr       error
		wantErrText   string
		wantLastN     int
	}{
		{
			name: "empty batch",
		},
		{
			name:        "partial progress",
			count:       4,
			results:     []batchWriteResult{{n: 2}, {n: 1}, {n: 1}},
			wantOffsets: []int{0, 2, 3},
			wantSent:    4,
		},
		{
			name:          "zero progress",
			count:         3,
			results:       []batchWriteResult{{}},
			wantOffsets:   []int{0},
			wantRemaining: 3,
			wantErrText:   "without progress",
		},
		{
			name:          "negative count",
			count:         3,
			results:       []batchWriteResult{{n: -1}},
			wantOffsets:   []int{0},
			wantRemaining: 3,
			wantErrText:   "without progress",
			wantLastN:     -1,
		},
		{
			name:          "oversized count",
			count:         3,
			results:       []batchWriteResult{{n: 4}},
			wantOffsets:   []int{0},
			wantRemaining: 3,
			wantErrText:   "without progress",
			wantLastN:     4,
		},
		{
			name:        "interrupted",
			count:       2,
			results:     []batchWriteResult{{err: syscall.EINTR}, {n: 2}},
			wantOffsets: []int{0, 0},
			wantSent:    2,
		},
		{
			name:          "destination error",
			count:         3,
			results:       []batchWriteResult{{err: fmt.Errorf("send: %w", syscall.EHOSTUNREACH)}, {n: 2}},
			wantOffsets:   []int{0, 1},
			wantSent:      2,
			wantDropped:   1,
			wantRemaining: 0,
		},
		{
			name:          "socket error",
			count:         3,
			results:       []batchWriteResult{{err: syscall.EIO}},
			wantOffsets:   []int{0},
			wantRemaining: 3,
			wantErr:       syscall.EIO,
		},
		{
			name:          "wrapped timeout",
			count:         3,
			results:       []batchWriteResult{{err: fmt.Errorf("write: %w", os.ErrDeadlineExceeded)}},
			wantOffsets:   []int{0},
			wantRemaining: 3,
			wantErr:       os.ErrDeadlineExceeded,
		},
		{
			name:          "progress before socket error",
			count:         3,
			results:       []batchWriteResult{{n: 2, err: syscall.EIO}, {err: syscall.EIO}},
			wantOffsets:   []int{0, 2},
			wantSent:      2,
			wantRemaining: 1,
			wantErr:       syscall.EIO,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var offsets []int
			calls := 0
			sent := 0
			dropped := 0
			remaining, lastN, err := drainUDPBatch(
				context.Background(),
				tt.count,
				func(offset int) (int, error) {
					offsets = append(offsets, offset)
					if calls >= len(tt.results) {
						t.Fatal("unexpected batch write")
					}
					result := tt.results[calls]
					calls++
					return result.n, result.err
				},
				func(n int) { sent += n },
				func(error) { dropped++ },
			)
			if tt.wantErr == nil && tt.wantErrText == "" && err != nil {
				t.Fatalf("drainUDPBatch error = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("drainUDPBatch error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrText)) {
				t.Fatalf("drainUDPBatch error = %v, want text %q", err, tt.wantErrText)
			}
			if !slices.Equal(offsets, tt.wantOffsets) {
				t.Fatalf("write offsets = %v, want %v", offsets, tt.wantOffsets)
			}
			if sent != tt.wantSent || dropped != tt.wantDropped || remaining != tt.wantRemaining {
				t.Fatalf("sent=%d dropped=%d remaining=%d, want %d %d %d", sent, dropped, remaining, tt.wantSent, tt.wantDropped, tt.wantRemaining)
			}
			if lastN != tt.wantLastN {
				t.Fatalf("last count = %d, want %d", lastN, tt.wantLastN)
			}
		})
	}
}

func TestDrainUDPBatchStopsAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	remaining, _, err := drainUDPBatch(ctx, 2, func(int) (int, error) {
		calls++
		cancel()
		return 0, syscall.EINTR
	}, nil, nil)
	if err != nil {
		t.Fatalf("drainUDPBatch error = %v", err)
	}
	if calls != 1 || remaining != 2 {
		t.Fatalf("calls=%d remaining=%d, want 1 and 2", calls, remaining)
	}
}

func TestDropsOneDatagram(t *testing.T) {
	for _, errno := range []syscall.Errno{
		unix.EHOSTUNREACH,
		unix.EHOSTDOWN,
		unix.ENETUNREACH,
		unix.EMSGSIZE,
		unix.EACCES,
		unix.EPERM,
		unix.EINVAL,
		unix.EAFNOSUPPORT,
	} {
		if !dropsOneDatagram(errno) {
			t.Errorf("dropsOneDatagram(%v) = false", errno)
		}
	}
	for _, errno := range []syscall.Errno{unix.EBADF, unix.EIO, unix.EINTR} {
		if dropsOneDatagram(errno) {
			t.Errorf("dropsOneDatagram(%v) = true", errno)
		}
	}
}
