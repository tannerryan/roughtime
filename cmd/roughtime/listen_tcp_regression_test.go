// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tannerryan/roughtime/protocol"
	"go.uber.org/zap"
)

type scriptedTCPConn struct {
	read    *bytes.Reader
	write   func([]byte) (int, error)
	written int
}

func (c *scriptedTCPConn) Read(p []byte) (int, error) { return c.read.Read(p) }
func (c *scriptedTCPConn) Write(p []byte) (int, error) {
	c.written++
	return c.write(p)
}
func (*scriptedTCPConn) Close() error                     { return nil }
func (*scriptedTCPConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*scriptedTCPConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*scriptedTCPConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedTCPConn) SetWriteDeadline(time.Time) error { return nil }

func tcpTestRequest(t *testing.T, rootPK []byte) []byte {
	t.Helper()
	_, request, err := protocol.CreateRequest(
		[]protocol.Version{protocol.VersionDraft12}, rand.Reader, protocol.ComputeSRV(rootPK))
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	return request
}

// TestHandleTCPConnDropsFullQueue covers the bounded submission wait without a
// live listener or batcher.
func TestHandleTCPConnDropsFullQueue(t *testing.T) {
	rootPK, state := newCertState(t)
	queue := make(chan tcpBatchItem, 1)
	queue <- tcpBatchItem{}
	previousWait := tcpBatchSubmitWait
	tcpBatchSubmitWait = time.Millisecond
	t.Cleanup(func() { tcpBatchSubmitWait = previousWait })
	startDrops := droppedFor(transportTCP, dropQueue)
	conn := &scriptedTCPConn{
		read:  bytes.NewReader(tcpTestRequest(t, rootPK)),
		write: func(p []byte) (int, error) { return len(p), nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleTCPConn(ctx, zap.NewNop(), conn, state, nil, queue, nil,
			[]protocol.Version{protocol.VersionDraft12})
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("handler did not return after queue timeout")
	}

	if got := droppedFor(transportTCP, dropQueue); got != startDrops+1 {
		t.Fatalf("queue drops=%d want %d", got, startDrops+1)
	}
	if conn.written != 0 {
		t.Fatalf("writes=%d want 0", conn.written)
	}
	if len(queue) != 1 {
		t.Fatalf("queue length=%d want original item only", len(queue))
	}
}

// TestHandleTCPConnDropsWriteFailures covers errors and short writes after a
// batch reply has been delivered.
func TestHandleTCPConnDropsWriteFailures(t *testing.T) {
	wantErr := errors.New("write failed")
	for _, tc := range []struct {
		name  string
		write func([]byte) (int, error)
	}{
		{name: "error", write: func([]byte) (int, error) { return 0, wantErr }},
		{name: "short", write: func(p []byte) (int, error) { return len(p) - 1, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootPK, state := newCertState(t)
			queue := make(chan tcpBatchItem)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			batchDone := make(chan bool, 1)
			go func() {
				select {
				case item := <-queue:
					select {
					case item.reply <- tcpBatchReply{bytes: []byte("reply")}:
						batchDone <- true
					case <-ctx.Done():
						batchDone <- false
					}
				case <-ctx.Done():
					batchDone <- false
				}
			}()
			startDrops := droppedFor(transportTCP, dropWrite)
			conn := &scriptedTCPConn{
				read:  bytes.NewReader(tcpTestRequest(t, rootPK)),
				write: tc.write,
			}
			handled := make(chan struct{})
			go func() {
				handleTCPConn(ctx, zap.NewNop(), conn, state, nil, queue, nil,
					[]protocol.Version{protocol.VersionDraft12})
				close(handled)
			}()

			select {
			case <-handled:
			case <-ctx.Done():
				t.Fatal("handler did not return after write failure")
			}
			select {
			case responded := <-batchDone:
				if !responded {
					t.Fatal("request did not reach scripted batcher")
				}
			case <-ctx.Done():
				t.Fatal("scripted batcher did not finish")
			}

			if got := droppedFor(transportTCP, dropWrite); got != startDrops+1 {
				t.Fatalf("write drops=%d want %d", got, startDrops+1)
			}
			if conn.written != 1 {
				t.Fatalf("writes=%d want 1", conn.written)
			}
		})
	}
}
