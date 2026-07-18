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

// merkleNodeFirst reports whether the sibling precedes the running hash when
// the INDX bit is 0. Drafts 05-15 specify node-first, but drafts 16-19 changed
// back to hash-first without changing the shared version or TYPE value. The
// ambiguous groupD14 defaults to the current hash-first convention.
func merkleNodeFirst(g wireGroup) bool {
	return g >= groupD05 && g <= groupD12
}

// maxMerkleLeaves caps batch size at 2^32, the maximum 32-deep tree.
const maxMerkleLeaves = 1 << 32

// newMerkleTreeWithOrder builds a tree with an explicit inner-node ordering.
func newMerkleTreeWithOrder(g wireGroup, leafInputs [][]byte, nodeFirst bool) *merkleTree {
	n := len(leafInputs)

	if n == 0 {
		panic("protocol: Merkle tree requires at least one leaf")
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
			if nodeFirst {
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

	err := verifyMerkleOrder(index, pathBytes, leafInput, rootHash, g, merkleNodeFirst(g))
	if errors.Is(err, ErrMerkleMismatch) && g == groupD14 {
		// Drafts 14-15 and 16-19 use opposite orders under the same wire
		// identifiers, so a verifier must try the other convention.
		return verifyMerkleOrder(index, pathBytes, leafInput, rootHash, g, !merkleNodeFirst(g))
	}
	return err
}

// verifyMerkleOrder verifies a structurally validated path with one child
// ordering convention.
func verifyMerkleOrder(index uint32, pathBytes, leafInput, rootHash []byte, g wireGroup, nodeFirst bool) error {
	acc := leafHash(g, leafInput)
	hs := hashSize(g)
	steps := len(pathBytes) / hs
	for i := range steps {
		sibling := pathBytes[i*hs : (i+1)*hs]
		if index&1 == 0 {
			if nodeFirst {
				acc = nodeHash(g, sibling, acc)
			} else {
				acc = nodeHash(g, acc, sibling)
			}
		} else {
			if nodeFirst {
				acc = nodeHash(g, acc, sibling)
			} else {
				acc = nodeHash(g, sibling, acc)
			}
		}
		index >>= 1
	}

	if index != 0 {
		return errors.New("protocol: INDX has trailing non-zero bits")
	}

	if !bytes.Equal(acc, rootHash) {
		return ErrMerkleMismatch
	}
	return nil
}
