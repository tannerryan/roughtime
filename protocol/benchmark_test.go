// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// BenchmarkParseRequest measures request parsing.
func BenchmarkParseRequest(b *testing.B) {
	_, raw, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := ParseRequest(raw); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCreateReplies measures batched reply creation.
func BenchmarkCreateReplies(b *testing.B) {
	cert, _ := testCert(b)
	now := time.Now().UTC().Truncate(time.Second)
	for _, size := range []int{1, 16} {
		b.Run(fmt.Sprintf("batch-%d", size), func(b *testing.B) {
			requests := make([]Request, size)
			for i := range requests {
				_, raw, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
				if err != nil {
					b.Fatal(err)
				}
				req, err := ParseRequest(raw)
				if err != nil {
					b.Fatal(err)
				}
				requests[i] = *req
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := CreateReplies(VersionDraft12, requests, now, time.Second, cert); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerifyReply measures response verification.
func BenchmarkVerifyReply(b *testing.B) {
	cert, _ := testCert(b)
	now := time.Now().UTC().Truncate(time.Second)
	nonce, raw, err := CreateRequest([]Version{VersionDraft12}, rand.Reader, nil)
	if err != nil {
		b.Fatal(err)
	}
	req, err := ParseRequest(raw)
	if err != nil {
		b.Fatal(err)
	}
	replies, err := CreateReplies(VersionDraft12, []Request{*req}, now, time.Second, cert)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(replies[0]) + len(raw)))
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := VerifyReply([]Version{VersionDraft12}, replies[0], cert.edRootPK, nonce, raw); err != nil {
			b.Fatal(err)
		}
	}
}
