// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build openbsd

package main

import (
	"syscall"
	"unsafe"
)

// openBSDSyscall6 calls a dynamically imported libc function with six
// arguments.
//
//go:linkname openBSDSyscall6 syscall.syscall6
func openBSDSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

var libcRecvmmsgTrampolineAddr uintptr

//go:cgo_import_dynamic libc_recvmmsg recvmmsg "libc.so"

var libcSendmmsgTrampolineAddr uintptr

//go:cgo_import_dynamic libc_sendmmsg sendmmsg "libc.so"

// openBSDRecvMmsg invokes libc recvmmsg for the supplied message headers.
func openBSDRecvMmsg(fd uintptr, headers []openBSDMmsghdr, flags int) (int, error) {
	if len(headers) == 0 {
		return 0, nil
	}
	r0, _, errno := openBSDSyscall6(
		libcRecvmmsgTrampolineAddr,
		fd,
		uintptr(unsafe.Pointer(&headers[0])),
		uintptr(len(headers)),
		uintptr(flags),
		0,
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}

// openBSDSendMmsg invokes libc sendmmsg for the supplied message headers.
func openBSDSendMmsg(fd uintptr, headers []openBSDMmsghdr, flags int) (int, error) {
	if len(headers) == 0 {
		return 0, nil
	}
	r0, _, errno := openBSDSyscall6(
		libcSendmmsgTrampolineAddr,
		fd,
		uintptr(unsafe.Pointer(&headers[0])),
		uintptr(len(headers)),
		uintptr(flags),
		0,
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}
