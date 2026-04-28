// Copyright (c) 2026 Tanner Ryan. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
)

// ErrMerkleMismatch is returned by [VerifyReply] when the Merkle path does not
// authenticate the request.
var ErrMerkleMismatch = errors.New("protocol: Merkle root mismatch")

var (
	// sha512Pool reuses SHA-512 hashers.
	sha512Pool = sync.Pool{New: func() any { return sha512.New() }}
	// sha512_256Pool reuses SHA-512/256 hashers (drafts 02 and 07).
	sha512_256Pool = sync.Pool{New: func() any { return sha512.New512_256() }}
)

// getHasher returns a reset hasher for g.
func getHasher(g wireGroup) hash.Hash {
	var h hash.Hash
	if usesSHA512_256(g) {
		h = sha512_256Pool.Get().(hash.Hash)
	} else {
		h = sha512Pool.Get().(hash.Hash)
	}
	h.Reset()
	return h
}

// putHasher returns h to its pool.
func putHasher(g wireGroup, h hash.Hash) {
	if usesSHA512_256(g) {
		sha512_256Pool.Put(h)
	} else {
		sha512Pool.Put(h)
	}
}

// leafHash computes H(0x00 || data) truncated to the wire group's hash size.
func leafHash(g wireGroup, data []byte) []byte {
	h := getHasher(g)
	defer putHasher(g, h)
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(data)
	return h.Sum(nil)[:hashSize(g)]
}

// nodeHash computes H(0x01 || left || right) truncated to the wire group's hash
// size.
func nodeHash(g wireGroup, left, right []byte) []byte {
	h := getHasher(g)
	defer putHasher(g, h)
	_, _ = h.Write([]byte{0x01})
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	return h.Sum(nil)[:hashSize(g)]
}

// merkleTree holds the pre-computed root and per-leaf paths for a batch of
// requests.
type merkleTree struct {
	rootHash []byte
	paths    [][][]byte
}

// merkleNodeFirst reports whether node precedes hash when INDX bit is 0 (drafts
// 05-13 and 14-19 without TYPE).
func merkleNodeFirst(g wireGroup) bool {
	return g >= groupD05 && g <= groupD12
}

// maxMerkleLeaves caps batch size at 2^32, the maximum 32-deep tree.
const maxMerkleLeaves = 1 << 32

// newMerkleTree builds the tree and per-leaf paths and panics on out-of-range
// leaf counts.
func newMerkleTree(g wireGroup, leafInputs [][]byte) *merkleTree {
	n := len(leafInputs)

	if n == 0 {
		panic("protocol: newMerkleTree called with zero leaves")
	}
	if uint64(n) > maxMerkleLeaves {
		panic(fmt.Sprintf("protocol: Merkle tree with %d leaves exceeds 2^32 (PATH > 32 hash values)", n))
	}

	hashes := make([][]byte, n)
	for i, d := range leafInputs {
		hashes[i] = leafHash(g, d)
	}

	if n == 1 {
		return &merkleTree{rootHash: hashes[0], paths: make([][][]byte, 1)}
	}

	// pad to next power of two by repeating the last hash
	size := 1
	for size < n {
		size *= 2
	}
	level := make([][]byte, size)
	copy(level, hashes)
	for i := n; i < size; i++ {
		level[i] = hashes[n-1]
	}

	indices := make([]int, n)
	paths := make([][][]byte, n)
	for i := range indices {
		indices[i] = i
	}

	for len(level) > 1 {
		for i := range n {
			sib := indices[i] ^ 1
			paths[i] = append(paths[i], level[sib])
			indices[i] /= 2
		}
		next := make([][]byte, len(level)/2)
		for j := 0; j < len(level); j += 2 {
			if merkleNodeFirst(g) {
				next[j/2] = nodeHash(g, level[j+1], level[j])
			} else {
				next[j/2] = nodeHash(g, level[j], level[j+1])
			}
		}
		level = next
	}

	return &merkleTree{rootHash: level[0], paths: paths}
}

// verifyMerkle verifies the Merkle proof that leafInput is in the tree rooted
// at rootHash.
func verifyMerkle(resp map[uint32][]byte, leafInput, rootHash []byte, g wireGroup) error {
	indexBytes, ok := resp[TagINDX]
	if !ok || len(indexBytes) != 4 {
		return errors.New("protocol: missing or invalid INDX")
	}
	index := binary.LittleEndian.Uint32(indexBytes)

	pathBytes, pathOK := resp[TagPATH]
	if !pathOK {
		return errors.New("protocol: missing PATH in response")
	}
	hs := hashSize(g)
	if len(pathBytes)%hs != 0 {
		return errors.New("protocol: PATH length not a multiple of hash size")
	}
	if len(pathBytes)/hs > 32 {
		return errors.New("protocol: PATH exceeds 32 hash values")
	}

	hash := leafHash(g, leafInput)
	steps := len(pathBytes) / hs
	nf := merkleNodeFirst(g)
	for i := range steps {
		sibling := pathBytes[i*hs : (i+1)*hs]
		if index&1 == 0 {
			if nf {
				hash = nodeHash(g, sibling, hash)
			} else {
				hash = nodeHash(g, hash, sibling)
			}
		} else {
			if nf {
				hash = nodeHash(g, hash, sibling)
			} else {
				hash = nodeHash(g, sibling, hash)
			}
		}
		index >>= 1
	}

	if index != 0 {
		return errors.New("protocol: INDX has trailing non-zero bits")
	}

	if !bytes.Equal(hash, rootHash) {
		return ErrMerkleMismatch
	}
	return nil
}
