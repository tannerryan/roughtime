// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"crypto/rand"
	"testing"
	"time"
)

// TestGreaseMalformedInput covers invalid reply handling.
func TestGreaseMalformedInput(t *testing.T) {
	for _, ver := range []Version{VersionGoogle, VersionDraft08, VersionDraft12} {
		t.Run(ver.String(), func(t *testing.T) {
			for _, input := range [][]byte{nil, {}, {0x00}, make([]byte, 11)} {
				Grease(input, ver)
			}
		})
	}
}

// TestGreaseDoesNotPanicMLDSA44 covers large ML-DSA-44 replies.
func TestGreaseDoesNotPanicMLDSA44(t *testing.T) {
	cert, rootPK := testPQCert(t)
	versions := []Version{VersionMLDSA44}
	srv := ComputeSRV(rootPK)
	_, request, err := CreateRequest(versions, rand.Reader, srv)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	parsed, err := ParseRequest(request)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	replies, err := CreateReplies(VersionMLDSA44, []Request{*parsed}, time.Now(), 3*time.Second, cert)
	if err != nil {
		t.Fatalf("CreateReplies: %v", err)
	}
	Grease(replies[0], VersionMLDSA44)
}
