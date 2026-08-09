// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"net"
	"runtime"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// udpWriteTimeout bounds a blocked datagram send during normal operation and
// shutdown.
const udpWriteTimeout = 2 * time.Second

// listenNetworks returns the networks to bind. OpenBSD lacks IPv4-mapped IPv6,
// so a wildcard needs one socket per family. It is a variable so tests can
// force the split off OpenBSD.
var listenNetworks = func(network, addr string) []string {
	if runtime.GOOS != "openbsd" {
		return []string{network}
	}
	// an explicit host already pins the family
	if host, _, err := net.SplitHostPort(addr); err != nil || host != "" {
		return []string{network}
	}
	return []string{network + "4", network + "6"}
}

// applyReadBuffer sets SO_RCVBUF and logs if the kernel clamps its size.
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
	// Linux reports twice the usable payload buffer for accounting overhead.
	if runtime.GOOS == "linux" {
		effective /= 2
	}
	if effective < socketRecvBuffer {
		level := zap.WarnLevel
		// Non-Linux limits are commonly below the requested size, so avoid an
		// alarming warning there.
		if runtime.GOOS != "linux" {
			level = zap.InfoLevel
		}
		if ce := log.Check(level, "kernel truncated UDP receive buffer"); ce != nil {
			ce.Write(
				zap.Int("requested", socketRecvBuffer),
				zap.Int("effective", effective),
				zap.String("remediation", "raise the operating system's UDP receive-buffer limit"),
			)
		}
		return
	}
	if ce := log.Check(zap.DebugLevel, "UDP receive buffer applied"); ce != nil {
		ce.Write(zap.Int("requested", socketRecvBuffer), zap.Int("effective", effective))
	}
}
