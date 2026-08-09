// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build openbsd && (amd64 || arm64 || riscv64)

#include "textflag.h"

TEXT libc_recvmmsg_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_recvmmsg(SB)
GLOBL	·libcRecvmmsgTrampolineAddr(SB), RODATA, $8
DATA	·libcRecvmmsgTrampolineAddr(SB)/8, $libc_recvmmsg_trampoline<>(SB)

TEXT libc_sendmmsg_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_sendmmsg(SB)
GLOBL	·libcSendmmsgTrampolineAddr(SB), RODATA, $8
DATA	·libcSendmmsgTrampolineAddr(SB)/8, $libc_sendmmsg_trampoline<>(SB)
