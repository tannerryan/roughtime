// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

//go:build openbsd

package main

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestOpenBSDSockaddrRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		addr   *net.UDPAddr
		family uint8
	}{
		{
			name:   "IPv4",
			addr:   &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 65535},
			family: unix.AF_INET,
		},
		{
			name:   "IPv6",
			addr:   &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 2002, Zone: "7"},
			family: unix.AF_INET6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw unix.RawSockaddrAny
			if err := udpAddrToOpenBSD(&raw, tt.addr); err != nil {
				t.Fatal(err)
			}
			if raw.Addr.Family != tt.family {
				t.Fatalf("family = %d, want %d", raw.Addr.Family, tt.family)
			}
			got, err := openBSDUDPAddr(&raw, uint32(raw.Addr.Len))
			if err != nil {
				t.Fatal(err)
			}
			if !got.IP.Equal(tt.addr.IP) || got.Port != tt.addr.Port || got.Zone != tt.addr.Zone {
				t.Fatalf("decoded address = %v, want %v", got, tt.addr)
			}
		})
	}
}

func TestOpenBSDSockaddrEncoding(t *testing.T) {
	var raw unix.RawSockaddrAny
	addr := &net.UDPAddr{IP: net.IP{198, 51, 100, 4}, Port: 0x1234}
	if err := udpAddrToOpenBSD(&raw, addr); err != nil {
		t.Fatal(err)
	}
	ipv4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(&raw))
	if ipv4.Len != unix.SizeofSockaddrInet4 || ipv4.Family != unix.AF_INET {
		t.Fatalf("IPv4 header = len %d family %d", ipv4.Len, ipv4.Family)
	}
	ipv4Port := *(*[2]byte)(unsafe.Pointer(&ipv4.Port))
	if ipv4.Addr != [4]byte{198, 51, 100, 4} || ipv4Port != [2]byte{0x12, 0x34} {
		t.Fatalf("IPv4 payload = %v port bytes %x", ipv4.Addr, ipv4Port)
	}

	addr = &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 0xabcd, Zone: "9"}
	if err := udpAddrToOpenBSD(&raw, addr); err != nil {
		t.Fatal(err)
	}
	ipv6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(&raw))
	if ipv6.Len != unix.SizeofSockaddrInet6 || ipv6.Family != unix.AF_INET6 {
		t.Fatalf("IPv6 header = len %d family %d", ipv6.Len, ipv6.Family)
	}
	wantIPv6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	ipv6Port := *(*[2]byte)(unsafe.Pointer(&ipv6.Port))
	if ipv6.Addr != wantIPv6 || ipv6Port != [2]byte{0xab, 0xcd} || ipv6.Scope_id != 9 {
		t.Fatalf("IPv6 address=%x port bytes=%x scope=%d", ipv6.Addr, ipv6Port, ipv6.Scope_id)
	}
}

func TestOpenBSDSockaddrErrors(t *testing.T) {
	for _, addr := range []*net.UDPAddr{
		nil,
		{Port: 2002},
		{IP: net.IP{192, 0, 2, 1}, Port: -1},
		{IP: net.IP{192, 0, 2, 1}, Port: 65536},
		{IP: net.IP{1, 2, 3}, Port: 2002},
		{IP: net.ParseIP("2001:db8::1"), Port: 2002, Zone: "roughtime-invalid-zone"},
	} {
		var raw unix.RawSockaddrAny
		if err := udpAddrToOpenBSD(&raw, addr); err == nil {
			t.Fatalf("udpAddrToOpenBSD(%v) succeeded", addr)
		}
	}

	var raw unix.RawSockaddrAny
	raw.Addr.Family = unix.AF_INET
	if _, err := openBSDUDPAddr(&raw, unix.SizeofSockaddrInet4-1); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short IPv4 error = %v, want EINVAL", err)
	}
	raw.Addr.Family = unix.AF_INET6
	if _, err := openBSDUDPAddr(&raw, unix.SizeofSockaddrInet6-1); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short IPv6 error = %v, want EINVAL", err)
	}
	raw.Addr.Family = unix.AF_UNIX
	if _, err := openBSDUDPAddr(&raw, unix.SizeofSockaddrAny); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("unsupported family error = %v, want EAFNOSUPPORT", err)
	}
}

func TestOpenBSDMmsgWrappers(t *testing.T) {
	if n, err := openBSDRecvMmsg(0, nil, 0); n != 0 || err != nil {
		t.Fatalf("empty recvmmsg = n %d err %v", n, err)
	}
	if n, err := openBSDSendMmsg(0, nil, 0); n != 0 || err != nil {
		t.Fatalf("empty sendmmsg = n %d err %v", n, err)
	}

	headers := make([]openBSDMmsghdr, 1)
	badFD := ^uintptr(0)
	if n, err := openBSDRecvMmsg(badFD, headers, 0); n != 0 || !errors.Is(err, syscall.EBADF) {
		t.Fatalf("failed recvmmsg = n %d err %v, want EBADF", n, err)
	}
	if n, err := openBSDSendMmsg(badFD, headers, 0); n != 0 || !errors.Is(err, syscall.EBADF) {
		t.Fatalf("failed sendmmsg = n %d err %v, want EBADF", n, err)
	}
}
