// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestLoadServersFileRejectsFIFO checks for rejection without a writer.
func TestLoadServersFileRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := loadServersFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("loadServersFile(FIFO) = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("loadServersFile blocked opening a FIFO")
	}
}
