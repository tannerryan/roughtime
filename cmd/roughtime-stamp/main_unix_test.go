// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestStampRejectsFIFO covers document and receipt inputs.
func TestStampRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashDocument(context.Background(), path); err == nil {
		t.Fatal("hashDocument accepted a FIFO")
	}
	if _, err := readBoundedFile(path); err == nil {
		t.Fatal("readBoundedFile accepted a FIFO")
	}
}
