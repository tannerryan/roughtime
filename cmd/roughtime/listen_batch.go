// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// dropsOneDatagram reports whether errno is specific to the destination or the
// message rather than the socket, so a batch send can skip it and continue.
// Socket and system errors abort the rest instead.
func dropsOneDatagram(errno syscall.Errno) bool {
	switch errno {
	case unix.EHOSTUNREACH, unix.EHOSTDOWN, unix.ENETUNREACH, unix.EMSGSIZE,
		unix.EACCES, unix.EPERM, unix.EINVAL, unix.EAFNOSUPPORT:
		return true
	}
	return false
}

// drainUDPBatch preserves progress across short sendmmsg results. A short count
// stops before the failing destination, so a recognized datagram error skips
// that item while a socket-wide error abandons the remaining batch.
func drainUDPBatch(ctx context.Context, count int, write func(offset int) (int, error), onSent func(int), onDrop func(error)) (remaining, lastN int, err error) {
	offset := 0
	for offset < count {
		if ctx.Err() != nil {
			return count - offset, 0, nil
		}
		n, writeErr := write(offset)
		if n > 0 && n <= count-offset {
			if onSent != nil {
				onSent(n)
			}
			offset += n
			continue
		}
		if errors.Is(writeErr, syscall.EINTR) {
			continue
		}
		errno, ok := errors.AsType[syscall.Errno](writeErr)
		if ok && dropsOneDatagram(errno) {
			if onDrop != nil {
				onDrop(writeErr)
			}
			offset++
			continue
		}
		if writeErr == nil {
			writeErr = fmt.Errorf("batch write returned %d of %d without progress", n, count-offset)
		}
		return count - offset, n, writeErr
	}
	return 0, 0, nil
}
