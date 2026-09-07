// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestOpenRegular covers regular files, symlinks, and rejected special files.
func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("document"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{regular, true},
		{link, true},
		{dir, false},
		{fifo, false},
		{filepath.Join(dir, "missing"), false},
	} {
		t.Run(filepath.Base(tc.path), func(t *testing.T) {
			f, err := OpenRegular(tc.path)
			if !tc.ok {
				if f != nil {
					_ = f.Close()
					t.Fatal("returned a file on failure")
				}
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) {
					t.Fatalf("error = %v, want PathError", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			data := make([]byte, len("document"))
			if n, err := f.Read(data); err != nil || n != len(data) || string(data) != "document" {
				t.Fatalf("read = %q, %d, %v", data, n, err)
			}
		})
	}
}
