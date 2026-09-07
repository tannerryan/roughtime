// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// TestAuthenticatedTransports exercises complete exchanges for each wire group,
// using nonempty Merkle paths where batching is supported.
func TestAuthenticatedTransports(t *testing.T) {
	for _, tc := range []struct {
		name      string
		version   Version
		request   RequestOptions
		nodeFirst bool
	}{
		{name: "Google", version: VersionGoogle},
		{name: "draft01", version: VersionDraft01},
		{name: "draft02", version: VersionDraft02},
		{name: "draft03", version: VersionDraft03},
		{name: "draft05", version: VersionDraft05},
		{name: "draft07", version: VersionDraft07},
		{name: "draft08", version: VersionDraft08},
		{name: "draft10", version: VersionDraft10},
		{name: "draft12", version: VersionDraft12, request: RequestOptions{OmitTYPE: true}},
		{name: "draft14", version: VersionDraft12, nodeFirst: true},
		{name: "draft16", version: VersionDraft12},
		{name: "MLDSA44", version: VersionMLDSA44},
	} {
		for _, transport := range []string{"udp", "tcp"} {
			if tc.version == VersionGoogle && transport == "tcp" || tc.version == VersionMLDSA44 && transport == "udp" {
				continue
			}
			t.Run(tc.name+"/"+transport, func(t *testing.T) {
				var cert *Certificate
				var rootPK []byte
				if tc.version == VersionMLDSA44 {
					cert, rootPK = testPQCert(t)
				} else {
					cert, _ = testCert(t)
					rootPK = cert.edRootPK
				}
				defer cert.Wipe()
				versions := []Version{tc.version}
				nonce, request, err := CreateRequestWithOptions(versions, rand.Reader, ComputeSRV(rootPK), tc.request)
				if err != nil {
					t.Fatal(err)
				}
				_, siblingBytes, err := CreateRequestWithOptions(versions, rand.Reader, ComputeSRV(rootPK), tc.request)
				if err != nil {
					t.Fatal(err)
				}
				sibling, err := ParseRequest(siblingBytes)
				if err != nil {
					t.Fatal(err)
				}
				midpoint := time.Now().UTC().Truncate(time.Second)
				respond := func(raw []byte) ([]byte, error) {
					parsed, err := ParseRequest(raw)
					if err != nil {
						return nil, err
					}
					batch := []Request{*sibling, *parsed}
					if tc.version == VersionDraft01 || tc.version == VersionDraft02 {
						batch = batch[1:]
					}
					replies, err := CreateRepliesWithOptions(tc.version, batch, midpoint, 3*time.Second, cert,
						ReplyOptions{Draft14NodeFirst: tc.nodeFirst})
					if err != nil {
						return nil, err
					}
					return replies[len(replies)-1], nil
				}
				address, done := serveAuthenticatedPacket(t, transport, respond)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				roundTrip := RoundTripUDP
				if transport == "tcp" {
					roundTrip = RoundTripTCP
				}
				reply, rtt, localNow, err := roundTrip(ctx, address, request, 2*time.Second)
				serverErr := <-done
				if err != nil || serverErr != nil {
					t.Fatalf("exchange: client=%v server=%v", err, serverErr)
				}
				got, radius, err := VerifyReply(versions, reply, rootPK, nonce, request)
				if err != nil || !got.Equal(midpoint) || radius != 3*time.Second || rtt <= 0 || localNow.IsZero() {
					t.Fatalf("verified exchange: midpoint=%s radius=%s RTT=%s local=%s error=%v", got, radius, rtt, localNow, err)
				}
			})
		}
	}
}

// serveAuthenticatedPacket serves one bounded loopback exchange and reports
// errors.
func serveAuthenticatedPacket(t *testing.T, transport string, respond func([]byte) ([]byte, error)) (string, <-chan error) {
	t.Helper()
	done := make(chan error, 1)
	if transport == "udp" {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		go func() {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, MaxUDPReply)
			n, peer, err := conn.ReadFromUDP(buf)
			if err == nil {
				var reply []byte
				reply, err = respond(buf[:n])
				if err == nil {
					_, err = conn.WriteToUDP(reply, peer)
				}
			}
			done <- err
		}()
		return conn.LocalAddr().String(), done
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = listener.SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := listener.AcceptTCP()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var header [PacketHeaderSize]byte
		if _, err = io.ReadFull(conn, header[:]); err == nil {
			var size uint32
			size, err = ParsePacketHeader(header[:])
			if err == nil && size > MaxTCPReplyBody {
				err = fmt.Errorf("request too large: %d", size)
			}
			if err == nil {
				packet := make([]byte, PacketHeaderSize+int(size))
				copy(packet, header[:])
				if _, err = io.ReadFull(conn, packet[PacketHeaderSize:]); err == nil {
					var reply []byte
					reply, err = respond(packet)
					if err == nil {
						_, err = conn.Write(reply)
					}
				}
			}
		}
		done <- err
	}()
	return listener.Addr().String(), done
}
