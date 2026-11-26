// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// TestOpenRegular covers regular files, symlinks, and invalid paths.
func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("document"), 0600); err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		path string
		ok   bool
	}
	cases := []testCase{
		{regular, true},
		{dir, false},
		{filepath.Join(dir, "missing"), false},
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		const privilegeNotHeld = syscall.Errno(1314)
		if runtime.GOOS != "windows" || !errors.Is(err, privilegeNotHeld) {
			t.Fatal(err)
		}
	} else {
		cases = append(cases, testCase{link, true})
	}
	for _, tc := range cases {
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
