// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build openbsd

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// socketRecvBuffer is OpenBSD's maximum per-socket receive-buffer size.
const socketRecvBuffer = 2 * 1024 * 1024

// openBSDMmsghdr matches OpenBSD's struct mmsghdr.
type openBSDMmsghdr struct {
	header unix.Msghdr
	length uint32
}

// openBSDMmsgConn owns the preallocated read and write vectors used by recvmmsg
// and sendmmsg.
type openBSDMmsgConn struct {
	conn *net.UDPConn
	raw  syscall.RawConn

	readHeaders []openBSDMmsghdr
	readIovecs  []unix.Iovec
	readAddrs   []unix.RawSockaddrAny
	readBuffers []*[]byte

	writeHeaders []openBSDMmsghdr
	writeIovecs  []unix.Iovec
	writeAddrs   []unix.RawSockaddrAny
	writePeers   []*net.UDPAddr
}

func newOpenBSDMmsgConn(conn *net.UDPConn, batchSize int) (*openBSDMmsgConn, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	c := &openBSDMmsgConn{
		conn:         conn,
		raw:          raw,
		readHeaders:  make([]openBSDMmsghdr, batchSize),
		readIovecs:   make([]unix.Iovec, batchSize),
		readAddrs:    make([]unix.RawSockaddrAny, batchSize),
		readBuffers:  make([]*[]byte, batchSize),
		writeHeaders: make([]openBSDMmsghdr, batchSize),
		writeIovecs:  make([]unix.Iovec, batchSize),
		writeAddrs:   make([]unix.RawSockaddrAny, batchSize),
		writePeers:   make([]*net.UDPAddr, batchSize),
	}
	for i := range c.readBuffers {
		c.replaceReadBuffer(i)
	}
	return c, nil
}

func (c *openBSDMmsgConn) replaceReadBuffer(i int) {
	bufPtr := bufPool.Get().(*[]byte)
	c.readBuffers[i] = bufPtr
	c.readIovecs[i].Base = &(*bufPtr)[0]
	c.readIovecs[i].SetLen(len(*bufPtr))
	c.readHeaders[i].header.Iov = &c.readIovecs[i]
	c.readHeaders[i].header.SetIovlen(1)
}

func (c *openBSDMmsgConn) readBatch() (int, error) {
	for i := range c.readHeaders {
		c.readHeaders[i].length = 0
		c.readHeaders[i].header.Name = (*byte)(unsafe.Pointer(&c.readAddrs[i]))
		c.readHeaders[i].header.Namelen = uint32(unix.SizeofSockaddrAny)
		c.readHeaders[i].header.Flags = 0
	}

	var (
		n     int
		opErr error
	)
	err := c.raw.Read(func(fd uintptr) bool {
		n, opErr = openBSDRecvMmsg(fd, c.readHeaders, 0)
		return !errors.Is(opErr, syscall.EAGAIN) && !errors.Is(opErr, syscall.EWOULDBLOCK)
	})
	runtime.KeepAlive(c)
	if err != nil {
		return 0, err
	}
	return n, opErr
}

func (c *openBSDMmsgConn) writeReplies(ctx context.Context, log *zap.Logger, ver protocol.Version, replies []readyReply) {
	count := 0
	for _, reply := range replies {
		if err := udpAddrToOpenBSD(&c.writeAddrs[count], reply.peer); err != nil {
			log.Warn("invalid UDP reply address", zap.Stringer("peer", reply.peer), zap.Error(err))
			incDropped(transportUDP, dropWrite)
			continue
		}
		c.writeIovecs[count].Base = &reply.bytes[0]
		c.writeIovecs[count].SetLen(len(reply.bytes))
		c.writeHeaders[count] = openBSDMmsghdr{}
		c.writeHeaders[count].header.Name = (*byte)(unsafe.Pointer(&c.writeAddrs[count]))
		c.writeHeaders[count].header.Namelen = uint32(c.writeAddrs[count].Addr.Len)
		c.writeHeaders[count].header.Iov = &c.writeIovecs[count]
		c.writeHeaders[count].header.SetIovlen(1)
		c.writePeers[count] = reply.peer
		count++
	}

	for sent := 0; sent < count; {
		if ctx.Err() != nil {
			for range count - sent {
				incDropped(transportUDP, dropWrite)
			}
			return
		}
		_ = c.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
		n, err := c.writeBatch(c.writeHeaders[sent:count])
		if err != nil || n <= 0 || n > count-sent {
			log.Warn("sendmmsg failed",
				zap.Error(err),
				zap.Int("written", n),
				zap.Int("dropped", count-sent),
			)
			for range count - sent {
				incDropped(transportUDP, dropWrite)
			}
			return
		}
		udpRespondedEd.Add(uint64(n))
		if ce := log.Check(zap.DebugLevel, "sent response batch"); ce != nil {
			ce.Write(
				zap.Int("batch_size", n),
				zap.Stringer("version", ver),
			)
		}
		sent += n
	}
	runtime.KeepAlive(replies)
}

func (c *openBSDMmsgConn) writeBatch(headers []openBSDMmsghdr) (int, error) {
	var (
		n     int
		opErr error
	)
	err := c.raw.Write(func(fd uintptr) bool {
		n, opErr = openBSDSendMmsg(fd, headers, 0)
		return !errors.Is(opErr, syscall.EAGAIN) && !errors.Is(opErr, syscall.EWOULDBLOCK)
	})
	runtime.KeepAlive(c)
	if err != nil {
		return 0, err
	}
	return n, opErr
}

// listen uses OpenBSD's recvmmsg/sendmmsg syscalls on one UDP socket.
func listen(ctx context.Context, state *atomic.Pointer[certState]) error {
	listenLog := logger.Named("listener")
	addr, err := net.ResolveUDPAddr("udp", serverListenAddr())
	if err != nil {
		return fmt.Errorf("resolving UDP listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("starting UDP server: %w", err)
	}
	applyReadBuffer(listenLog, conn)

	mmsg, err := newOpenBSDMmsgConn(conn, batchMaxSize)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("preparing batched UDP socket: %w", err)
	}
	batchCh := make(chan validatedRequest, batchQueueSize)

	var batcherWg sync.WaitGroup
	batcherWg.Go(func() {
		batcher(ctx, logger.Named("batcher"), mmsg, state, batchCh, batchMaxSize, batchMaxLatency)
	})

	listenLog.Info("listening",
		zap.String("addr", conn.LocalAddr().String()),
		zap.Int("port", *port),
		zap.Int("queue_size", batchQueueSize),
		zap.String("io", "recvmmsg/sendmmsg"),
	)
	go func() {
		<-ctx.Done()
		listenLog.Info("shutdown initiated, unblocking reads")
		_ = conn.SetDeadline(time.Unix(1, 0))
	}()

	readOneBatch := func() bool {
		defer recoverGoroutine(listenLog, "listen")

		n, err := mmsg.readBatch()
		if err != nil {
			if ctx.Err() != nil {
				return true
			}
			listenLog.Warn("recvmmsg failed", zap.Error(err))
			select {
			case <-ctx.Done():
				return true
			case <-time.After(readErrorBackoff):
			}
			return false
		}

		st := state.Load()
		for i := range n {
			header := &mmsg.readHeaders[i]
			bufPtr := mmsg.readBuffers[i]
			reqLen := int(header.length)
			if header.header.Flags&unix.MSG_TRUNC != 0 || reqLen > maxPacketSize {
				incDropped(transportUDP, dropOversize)
				if ce := listenLog.Check(zap.DebugLevel, "dropped truncated UDP request"); ce != nil {
					ce.Write(zap.Int("reported_size", reqLen), zap.Int("buffer_size", len(*bufPtr)))
				}
				continue
			}
			if reqLen < minRequestSize {
				incDropped(transportUDP, dropUndersize)
				if ce := listenLog.Check(zap.DebugLevel, "dropped undersize request"); ce != nil {
					ce.Write(zap.Int("size", reqLen))
				}
				continue
			}
			peer, err := openBSDUDPAddr(&mmsg.readAddrs[i], header.header.Namelen)
			if err != nil {
				incDropped(transportUDP, dropParse)
				continue
			}
			vr, reason, ok := validateRequest(listenLog, (*bufPtr)[:reqLen], peer, reqLen, bufPtr, st)
			if !ok {
				incDropped(transportUDP, reason)
				continue
			}
			udpReceivedEd.Add(1)
			select {
			case batchCh <- vr:
				mmsg.replaceReadBuffer(i)
			default:
				incDropped(transportUDP, dropQueue)
				if ce := listenLog.Check(zap.DebugLevel, "dropped request: batcher queue full"); ce != nil {
					ce.Write(zap.Stringer("peer", peer), zap.Int("size", reqLen), zap.Int("queue_size", batchQueueSize))
				}
			}
		}
		return false
	}
	for !readOneBatch() {
	}

	drainStart := time.Now()
	close(batchCh)
	batcherWg.Wait()
	for _, bufPtr := range mmsg.readBuffers {
		bufPool.Put(bufPtr)
	}
	_ = conn.Close()
	listenLog.Info("shutdown complete",
		zap.Uint64("received_total", requestsReceived.total()),
		zap.Uint64("responded_total", requestsResponded.total()),
		zap.Uint64("dropped_total", requestsDropped.total()),
		zap.Uint64("amp_suppressed_total", statsAmpDropped.Load()),
		zap.Uint64("panics_total", statsPanics.Load()),
		zap.Uint64("batches_total", statsBatches.Load()),
		zap.Uint64("batched_reqs_total", statsBatchedReqs.Load()),
		zap.Uint64("batch_errs_total", statsBatchErrs.Load()),
		zap.Duration("drain_duration", time.Since(drainStart)),
	)
	return nil
}

func openBSDUDPAddr(raw *unix.RawSockaddrAny, namelen uint32) (*net.UDPAddr, error) {
	switch raw.Addr.Family {
	case unix.AF_INET:
		if namelen < unix.SizeofSockaddrInet4 {
			return nil, syscall.EINVAL
		}
		addr := (*unix.RawSockaddrInet4)(unsafe.Pointer(raw))
		return &net.UDPAddr{IP: append(net.IP(nil), addr.Addr[:]...), Port: rawPort(addr.Port)}, nil
	case unix.AF_INET6:
		if namelen < unix.SizeofSockaddrInet6 {
			return nil, syscall.EINVAL
		}
		addr := (*unix.RawSockaddrInet6)(unsafe.Pointer(raw))
		zone := ""
		if addr.Scope_id != 0 {
			zone = strconv.FormatUint(uint64(addr.Scope_id), 10)
		}
		return &net.UDPAddr{IP: append(net.IP(nil), addr.Addr[:]...), Port: rawPort(addr.Port), Zone: zone}, nil
	default:
		return nil, syscall.EAFNOSUPPORT
	}
}

func udpAddrToOpenBSD(raw *unix.RawSockaddrAny, addr *net.UDPAddr) error {
	if addr == nil || addr.Port < 0 || addr.Port > 65535 {
		return syscall.EINVAL
	}
	*raw = unix.RawSockaddrAny{}
	if len(addr.IP) == net.IPv4len {
		out := (*unix.RawSockaddrInet4)(unsafe.Pointer(raw))
		out.Len = unix.SizeofSockaddrInet4
		out.Family = unix.AF_INET
		setRawPort(&out.Port, addr.Port)
		copy(out.Addr[:], addr.IP)
		return nil
	}
	ip := addr.IP.To16()
	if ip == nil {
		return syscall.EINVAL
	}
	out := (*unix.RawSockaddrInet6)(unsafe.Pointer(raw))
	out.Len = unix.SizeofSockaddrInet6
	out.Family = unix.AF_INET6
	setRawPort(&out.Port, addr.Port)
	copy(out.Addr[:], ip)
	if addr.Zone != "" {
		zone, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			iface, lookupErr := net.InterfaceByName(addr.Zone)
			if lookupErr != nil {
				return lookupErr
			}
			zone = uint64(iface.Index)
		}
		out.Scope_id = uint32(zone)
	}
	return nil
}

func rawPort(port uint16) int {
	b := (*[2]byte)(unsafe.Pointer(&port))
	return int(b[0])<<8 | int(b[1])
}

func setRawPort(raw *uint16, port int) {
	b := (*[2]byte)(unsafe.Pointer(raw))
	b[0] = byte(port >> 8)
	b[1] = byte(port)
}
