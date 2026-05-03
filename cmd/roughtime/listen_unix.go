// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"net"
	"runtime"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// applyReadBuffer sets SO_RCVBUF on conn and logs any kernel truncation.
func applyReadBuffer(log *zap.Logger, conn *net.UDPConn) {
	if err := conn.SetReadBuffer(socketRecvBuffer); err != nil {
		log.Warn("setting UDP receive buffer failed",
			zap.Int("requested", socketRecvBuffer),
			zap.Error(err),
		)
		return
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		log.Warn("reading effective UDP receive buffer failed", zap.Error(err))
		return
	}
	var (
		effective int
		getErr    error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		effective, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	})
	if ctrlErr != nil || getErr != nil {
		log.Warn("reading effective UDP receive buffer failed",
			zap.NamedError("control", ctrlErr),
			zap.NamedError("getsockopt", getErr),
		)
		return
	}
	if effective < socketRecvBuffer {
		level := zap.WarnLevel
		// BSD/Darwin default kern.ipc.maxsockbuf is well under socketRecvBuffer
		// and rarely raised; demote to info there to avoid alarming logs
		if runtime.GOOS != "linux" {
			level = zap.InfoLevel
		}
		if ce := log.Check(level, "kernel truncated UDP receive buffer"); ce != nil {
			ce.Write(
				zap.Int("requested", socketRecvBuffer),
				zap.Int("effective", effective),
				zap.String("remediation", "raise net.core.rmem_max (Linux) or kern.ipc.maxsockbuf (BSD/Darwin)"),
			)
		}
		return
	}
	if ce := log.Check(zap.DebugLevel, "UDP receive buffer applied"); ce != nil {
		ce.Write(zap.Int("requested", socketRecvBuffer), zap.Int("effective", effective))
	}
}
