// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package fileutil provides regular-file input for the command-line tools.
package fileutil

import (
	"errors"
	"os"
	"syscall"
)

// OpenRegular opens a regular file without waiting for a FIFO peer. Symlinks
// are accepted when their target is a regular file.
func OpenRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err != nil {
		_ = f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return f, nil
}
