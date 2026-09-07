// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReadPrivateKeyFile checks descriptor validation and preserves seed bytes.
func TestReadPrivateKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed")
	const seed = "seed bytes\n"
	if err := os.WriteFile(path, []byte(seed), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, wantErr string
	}{
		{"regular", path, ""},
		{"symlink", link, "symlink"},
		{"directory", dir, "not a regular file"},
		{"missing", filepath.Join(dir, "missing"), "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPrivateKeyFile(tc.path, "root")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || got != nil {
					t.Fatalf("read = %q, %v, want %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || string(got) != seed {
				t.Fatalf("read = %q, %v, want %q", got, err, seed)
			}
		})
	}
}

// TestReadPrivateKeyFileFIFO uses a subprocess so a blocking open cannot hang
// tests.
func TestReadPrivateKeyFileFIFO(t *testing.T) {
	const fifoEnv = "ROUGHTIME_TEST_KEY_FIFO"
	if path := os.Getenv(fifoEnv); path != "" {
		for _, role := range []string{"root", "PQ root"} {
			if _, err := readPrivateKeyFile(path, role); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("%s FIFO error = %v, want non-regular file", role, err)
			}
		}
		return
	}
	path := filepath.Join(t.TempDir(), "seed.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestReadPrivateKeyFileFIFO$")
	cmd.Env = append(os.Environ(), fifoEnv+"="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("FIFO read did not reject promptly: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}
