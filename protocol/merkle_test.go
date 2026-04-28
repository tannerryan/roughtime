// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// TestLeafHash verifies leafHash matches the spec for Google and IETF wire
// groups.
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

// TestNodeHash verifies nodeHash matches H(0x01 || left || right).
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

// TestMerkleTreeEmpty verifies newMerkleTree panics on zero leaves.
func TestMerkleTreeEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on zero leaves")
		}
	}()
	newMerkleTree(groupD12, nil)
}

// TestMerkleTreeSingleLeaf verifies a single-leaf tree's root equals the leaf
// hash with empty path.
func TestMerkleTreeSingleLeaf(t *testing.T) {
	data := [][]byte{bytes.Repeat([]byte{0xaa}, 32)}
	tree := newMerkleTree(groupD12, data)
	if len(tree.paths[0]) != 0 || !bytes.Equal(tree.rootHash, leafHash(groupD12, data[0])) {
		t.Fatal("single leaf mismatch")
	}
}

// TestMerkleTreeTwoLeaves verifies groupD12's node-first convention.
func TestMerkleTreeTwoLeaves(t *testing.T) {
	d0 := bytes.Repeat([]byte{0xaa}, 32)
	d1 := bytes.Repeat([]byte{0xbb}, 32)
	tree := newMerkleTree(groupD12, [][]byte{d0, d1})
	h0, h1 := leafHash(groupD12, d0), leafHash(groupD12, d1)
	if !bytes.Equal(tree.rootHash, nodeHash(groupD12, h1, h0)) {
		t.Fatal("root mismatch")
	}
	if !bytes.Equal(tree.paths[0][0], h1) || !bytes.Equal(tree.paths[1][0], h0) {
		t.Fatal("sibling path mismatch")
	}
}

// TestMerkleTreeThreeLeaves verifies a three-leaf tree's root for groupD12.
func TestMerkleTreeThreeLeaves(t *testing.T) {
	d := [][]byte{
		bytes.Repeat([]byte{0xaa}, 32),
		bytes.Repeat([]byte{0xbb}, 32),
		bytes.Repeat([]byte{0xcc}, 32),
	}
	tree := newMerkleTree(groupD12, d)
	h0 := leafHash(groupD12, d[0])
	h1 := leafHash(groupD12, d[1])
	h2 := leafHash(groupD12, d[2])

	n01 := nodeHash(groupD12, h1, h0)
	n22 := nodeHash(groupD12, h2, h2)
	wantRoot := nodeHash(groupD12, n22, n01)
	if !bytes.Equal(tree.rootHash, wantRoot) {
		t.Fatal("three-leaf root mismatch")
	}
}

// TestMerkleTreeFourLeaves verifies a four-leaf tree's root and paths for
// groupD12.
func TestMerkleTreeFourLeaves(t *testing.T) {
	leaves := make([][]byte, 4)
	for i := range leaves {
		leaves[i] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	tree := newMerkleTree(groupD12, leaves)
	h := make([][]byte, 4)
	for i := range h {
		h[i] = leafHash(groupD12, leaves[i])
	}
	n01, n23 := nodeHash(groupD12, h[1], h[0]), nodeHash(groupD12, h[3], h[2])
	if !bytes.Equal(tree.rootHash, nodeHash(groupD12, n23, n01)) {
		t.Fatal("root mismatch")
	}
	if len(tree.paths[0]) != 2 || !bytes.Equal(tree.paths[0][0], h[1]) || !bytes.Equal(tree.paths[0][1], n23) {
		t.Fatal("path mismatch")
	}
}

// TestMerkleTreeNonPowerOfTwo verifies trees with non-power-of-two leaf counts.
func TestMerkleTreeNonPowerOfTwo(t *testing.T) {
	for _, n := range []int{3, 5, 6, 7, 9, 15, 17} {
		t.Run("", func(t *testing.T) {
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = randBytes(t, 32)
			}
			tree := newMerkleTree(groupD12, leaves)

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

// TestMerkleNodeFirstConvention verifies hash-first vs node-first ordering
// across wire groups.
func TestMerkleNodeFirstConvention(t *testing.T) {
	d0 := bytes.Repeat([]byte{0xaa}, 32)
	d1 := bytes.Repeat([]byte{0xbb}, 32)

	treeG := newMerkleTree(groupGoogle, [][]byte{d0, d1})
	h0g, h1g := leafHash(groupGoogle, d0), leafHash(groupGoogle, d1)
	if !bytes.Equal(treeG.rootHash, nodeHash(groupGoogle, h0g, h1g)) {
		t.Fatal("groupGoogle: expected hash-first")
	}

	tree08 := newMerkleTree(groupD08, [][]byte{d0, d1})
	h0_08, h1_08 := leafHash(groupD08, d0), leafHash(groupD08, d1)
	if !bytes.Equal(tree08.rootHash, nodeHash(groupD08, h1_08, h0_08)) {
		t.Fatal("groupD08: expected node-first")
	}

	// groupD14 reverted to hash-first in draft 16+
	tree14 := newMerkleTree(groupD14, [][]byte{d0, d1})
	h0_14, h1_14 := leafHash(groupD14, d0), leafHash(groupD14, d1)
	if !bytes.Equal(tree14.rootHash, nodeHash(groupD14, h0_14, h1_14)) {
		t.Fatal("groupD14: expected hash-first")
	}
}

// TestMerkleCrossConventionRejected verifies a proof from one ordering
// convention fails under the other.
func TestMerkleCrossConventionRejected(t *testing.T) {
	leaf0 := bytes.Repeat([]byte{0xaa}, 32)
	leaf1 := bytes.Repeat([]byte{0xbb}, 32)
	leaves := [][]byte{leaf0, leaf1}

	nodeFirst := newMerkleTree(groupD08, leaves)
	hashFirst := newMerkleTree(groupD14, leaves)

	var indx0 [4]byte
	binary.LittleEndian.PutUint32(indx0[:], 0)

	nfResp := map[uint32][]byte{
		TagINDX: indx0[:],
		TagPATH: bytes.Join(nodeFirst.paths[0], nil),
	}
	if err := verifyMerkle(nfResp, leaf0, nodeFirst.rootHash, groupD08); err != nil {
		t.Fatalf("node-first self-verify: %v", err)
	}
	if err := verifyMerkle(nfResp, leaf0, nodeFirst.rootHash, groupD14); !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("node-first proof under hash-first verifier: err=%v want ErrMerkleMismatch", err)
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

// TestLeafHashSHA512_256 verifies leafHash uses SHA-512/256 for groupD02 and
// groupD07.
func TestLeafHashSHA512_256(t *testing.T) {
	data := []byte("test SHA-512/256 leaf")
	h256 := sha512.Sum512_256(append([]byte{0x00}, data...))
	h512 := sha512.Sum512(append([]byte{0x00}, data...))

	for _, g := range []wireGroup{groupD02, groupD07} {
		got := leafHash(g, data)
		if !bytes.Equal(got, h256[:]) {
			t.Fatalf("group %d leafHash should use SHA-512/256", g)
		}
		if bytes.Equal(got, h512[:32]) {
			t.Fatalf("group %d leafHash matches SHA-512 truncated (should be SHA-512/256)", g)
		}
	}
}

// TestNodeHashSHA512_256 verifies nodeHash uses SHA-512/256 for groupD02 and
// groupD07.
func TestNodeHashSHA512_256(t *testing.T) {
	left := bytes.Repeat([]byte{0xcc}, 32)
	right := bytes.Repeat([]byte{0xdd}, 32)
	buf := append([]byte{0x01}, left...)
	buf = append(buf, right...)
	want256 := sha512.Sum512_256(buf)
	want512 := sha512.Sum512(buf)

	for _, g := range []wireGroup{groupD02, groupD07} {
		got := nodeHash(g, left, right)
		if !bytes.Equal(got, want256[:]) {
			t.Fatalf("group %d nodeHash should use SHA-512/256", g)
		}
		if bytes.Equal(got, want512[:32]) {
			t.Fatalf("group %d nodeHash matches SHA-512 truncated (should be SHA-512/256)", g)
		}
	}
}

// TestMerkleTreeNonPowerOfTwoD14 verifies non-power-of-two trees for groupD14's
// hash-first convention.
func TestMerkleTreeNonPowerOfTwoD14(t *testing.T) {
	for _, n := range []int{3, 5, 6, 7, 9, 15, 17} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := make([][]byte, n)
			for i := range leaves {
				leaves[i] = randBytes(t, 32)
			}
			tree := newMerkleTree(groupD14, leaves)

			for i, d := range leaves {
				hash := leafHash(groupD14, d)
				index := uint32(i)
				for _, sib := range tree.paths[i] {
					if index&1 == 0 {
						hash = nodeHash(groupD14, hash, sib)
					} else {
						hash = nodeHash(groupD14, sib, hash)
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

// TestMerkleTreeGoogleBatch verifies a Google-Roughtime batch tree round-trips
// proofs.
func TestMerkleTreeGoogleBatch(t *testing.T) {
	g := groupGoogle
	leaves := make([][]byte, 5)
	for i := range leaves {
		leaves[i] = randBytes(t, 64)
	}
	tree := newMerkleTree(g, leaves)
	if len(tree.rootHash) != 64 {
		t.Fatalf("Google Merkle root length = %d, want 64", len(tree.rootHash))
	}
	for i, leaf := range leaves {
		path := tree.paths[i]
		hash := leafHash(g, leaf)
		index := uint32(i)
		for _, sibling := range path {
			if index&1 == 0 {
				hash = nodeHash(g, hash, sibling)
			} else {
				hash = nodeHash(g, sibling, hash)
			}
			index >>= 1
		}
		if !bytes.Equal(hash, tree.rootHash) {
			t.Fatalf("proof %d: Merkle root mismatch", i)
		}
	}
}

// TestMerkleTreeLargeBatchD14 verifies a 32-leaf groupD14 batch (max PATH
// depth).
func TestMerkleTreeLargeBatchD14(t *testing.T) {
	g := groupD14
	const n = 32
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = randBytes(t, 1024)
	}
	tree := newMerkleTree(g, leaves)
	if len(tree.rootHash) != 32 {
		t.Fatalf("root hash length = %d, want 32", len(tree.rootHash))
	}
	for i, leaf := range leaves {
		path := tree.paths[i]
		hash := leafHash(g, leaf)
		index := uint32(i)
		for _, sibling := range path {
			if index&1 == 0 {
				hash = nodeHash(g, hash, sibling)
			} else {
				hash = nodeHash(g, sibling, hash)
			}
			index >>= 1
		}
		if !bytes.Equal(hash, tree.rootHash) {
			t.Fatalf("leaf %d: Merkle root mismatch", i)
		}
	}
}

// TestVerifyMerkleRejectsMissingINDX verifies verifyMerkle rejects responses
// lacking INDX.
func TestVerifyMerkleRejectsMissingINDX(t *testing.T) {
	resp := map[uint32][]byte{
		TagPATH: {},
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for missing INDX")
	}
}

// TestVerifyMerkleRejectsBadPATHLength verifies verifyMerkle rejects PATH not a
// multiple of hash size.
func TestVerifyMerkleRejectsBadPATHLength(t *testing.T) {
	var indx [4]byte
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: make([]byte, 17),
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for bad PATH length")
	}
}

// TestVerifyMerkleRejectsTrailingINDXBits verifies verifyMerkle rejects INDX
// with trailing non-zero bits.
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

// TestVerifyMerkleRejectsLongPATH verifies verifyMerkle rejects PATH longer
// than 32 hashes.
func TestVerifyMerkleRejectsLongPATH(t *testing.T) {
	var indx [4]byte
	resp := map[uint32][]byte{
		TagINDX: indx[:],
		TagPATH: make([]byte, 33*32),
	}
	if err := verifyMerkle(resp, make([]byte, 32), make([]byte, 32), groupD12); err == nil {
		t.Fatal("expected error for PATH exceeding 32 entries")
	}
}

// TestVerifyMerkleReturnsErrMerkleMismatch verifies a wrong-root proof wraps
// ErrMerkleMismatch.
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
