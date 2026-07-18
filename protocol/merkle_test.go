// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"testing"
)

// TestLeafHash covers domain-separated leaf hashing.
func TestLeafHash(t *testing.T) {
	data := []byte("test input")
	want := sha512.Sum512(append([]byte{0x00}, data...))

	got := leafHash(groupGoogle, data)
	if !bytes.Equal(got, want[:]) {
		t.Fatal("Google leafHash mismatch")
	}
	got = leafHash(groupD12, data)
	if !bytes.Equal(got, want[:32]) {
		t.Fatal("IETF leafHash mismatch")
	}
}

// TestNodeHash covers domain-separated node hashing.
func TestNodeHash(t *testing.T) {
	left := bytes.Repeat([]byte{0xaa}, 32)
	right := bytes.Repeat([]byte{0xbb}, 32)
	buf := append([]byte{0x01}, left...)
	buf = append(buf, right...)
	want := sha512.Sum512(buf)
	if !bytes.Equal(nodeHash(groupD08, left, right), want[:32]) {
		t.Fatal("nodeHash mismatch")
	}
}

// TestMerkleTreeNonPowerOfTwo covers incomplete tree levels.
func TestMerkleTreeNonPowerOfTwo(t *testing.T) {
	for _, n := range []int{3, 5, 6, 7, 9, 15, 17} {
		t.Run("", func(t *testing.T) {
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = randBytes(t, 32)
			}
			tree := newMerkleTreeWithOrder(groupD12, leaves, merkleNodeFirst(groupD12))

			for i, d := range leaves {
				hash := leafHash(groupD12, d)
				index := uint32(i)
				for _, sib := range tree.paths[i] {
					if index&1 == 0 {
						hash = nodeHash(groupD12, sib, hash)
					} else {
						hash = nodeHash(groupD12, hash, sib)
					}
					index >>= 1
				}
				if index != 0 {
					t.Fatalf("leaf %d: trailing INDX bits non-zero", i)
				}
				if !bytes.Equal(hash, tree.rootHash) {
					t.Fatalf("leaf %d: root mismatch", i)
				}
			}
		})
	}
}

// TestMerkleNodeFirstConvention covers default ordering across wire groups.
func TestMerkleNodeFirstConvention(t *testing.T) {
	d0 := bytes.Repeat([]byte{0xaa}, 32)
	d1 := bytes.Repeat([]byte{0xbb}, 32)

	treeG := newMerkleTreeWithOrder(groupGoogle, [][]byte{d0, d1}, merkleNodeFirst(groupGoogle))
	h0g, h1g := leafHash(groupGoogle, d0), leafHash(groupGoogle, d1)
	if !bytes.Equal(treeG.rootHash, nodeHash(groupGoogle, h0g, h1g)) {
		t.Fatal("groupGoogle: expected hash-first")
	}

	tree08 := newMerkleTreeWithOrder(groupD08, [][]byte{d0, d1}, merkleNodeFirst(groupD08))
	h0_08, h1_08 := leafHash(groupD08, d0), leafHash(groupD08, d1)
	if !bytes.Equal(tree08.rootHash, nodeHash(groupD08, h1_08, h0_08)) {
		t.Fatal("groupD08: expected node-first")
	}

	// groupD14 reverted to hash-first in draft 16+
	tree14 := newMerkleTreeWithOrder(groupD14, [][]byte{d0, d1}, merkleNodeFirst(groupD14))
	h0_14, h1_14 := leafHash(groupD14, d0), leafHash(groupD14, d1)
	if !bytes.Equal(tree14.rootHash, nodeHash(groupD14, h0_14, h1_14)) {
		t.Fatal("groupD14: expected hash-first")
	}
}

// TestMerkleDraft14AcceptsBothConventions covers shared-version compatibility.
func TestMerkleDraft14AcceptsBothConventions(t *testing.T) {
	leaf0 := bytes.Repeat([]byte{0xaa}, 32)
	leaf1 := bytes.Repeat([]byte{0xbb}, 32)
	leaves := [][]byte{leaf0, leaf1}

	nodeFirst := newMerkleTreeWithOrder(groupD08, leaves, merkleNodeFirst(groupD08))
	hashFirst := newMerkleTreeWithOrder(groupD14, leaves, merkleNodeFirst(groupD14))

	var indx0 [4]byte
	binary.LittleEndian.PutUint32(indx0[:], 0)

	nfResp := map[uint32][]byte{
		TagINDX: indx0[:],
		TagPATH: bytes.Join(nodeFirst.paths[0], nil),
	}
	if err := verifyMerkle(nfResp, leaf0, nodeFirst.rootHash, groupD08); err != nil {
		t.Fatalf("node-first self-verify: %v", err)
	}
	if err := verifyMerkle(nfResp, leaf0, nodeFirst.rootHash, groupD14); err != nil {
		t.Fatalf("draft-14 node-first compatibility: %v", err)
	}

	hfResp := map[uint32][]byte{
		TagINDX: indx0[:],
		TagPATH: bytes.Join(hashFirst.paths[0], nil),
	}
	if err := verifyMerkle(hfResp, leaf0, hashFirst.rootHash, groupD14); err != nil {
		t.Fatalf("hash-first self-verify: %v", err)
	}
	if err := verifyMerkle(hfResp, leaf0, hashFirst.rootHash, groupD08); !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("hash-first proof under node-first verifier: err=%v want ErrMerkleMismatch", err)
	}
}

// TestVerifyMerkleRejectsTrailingINDXBits covers noncanonical indexes.
func TestVerifyMerkleRejectsTrailingINDXBits(t *testing.T) {
	// one PATH entry but INDX=4 leaves index>>1 = 2 (non-zero)
	var indx [4]byte
	binary.LittleEndian.PutUint32(indx[:], 4)
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: make([]byte, 32),
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for trailing INDX bits")
	}
}

// TestVerifyMerkleReturnsErrMerkleMismatch covers the mismatch sentinel.
func TestVerifyMerkleReturnsErrMerkleMismatch(t *testing.T) {
	var indx [4]byte
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: nil,
	}
	leaf := make([]byte, 32)
	root := bytes.Repeat([]byte{0xFF}, 32)
	err := verifyMerkle(resp, leaf, root, groupD12)
	if err == nil {
		t.Fatal("expected Merkle mismatch error")
	}
	if !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("expected ErrMerkleMismatch, got %v", err)
	}
}
