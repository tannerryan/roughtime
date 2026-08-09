// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build linux || openbsd

package main

import (
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
