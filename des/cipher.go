// Copyright 2011 The Go Authors. All rights reserved.
// Copyright 2020 Andrew Archibald. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

// The DES block size in bytes.
const BlockSize = 8

// Cipher is an instance of DES encryption.
type Cipher struct {
	subkeys [16]uint64
}

// NewCipher creates and returns a new Cipher.
func NewCipher(key uint64) *Cipher {
	c := new(Cipher)
	c.generateSubkeys(key)
	return c
}

func (c *Cipher) EncryptBlock(block uint64) uint64 {
	return c.cryptBlock(block, false)
}

func (c *Cipher) DecryptBlock(block uint64) uint64 {
	return c.cryptBlock(block, true)
}

func (c *Cipher) cryptBlock(block uint64, decrypt bool) (dst uint64) {
	b := permuteInitialBlock(block)
	left, right := uint32(b>>32), uint32(b)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	if decrypt {
		for i := 0; i < 8; i++ {
			left, right = feistel(left, right, c.subkeys[15-2*i], c.subkeys[15-(2*i+1)])
		}
	} else {
		for i := 0; i < 8; i++ {
			left, right = feistel(left, right, c.subkeys[2*i], c.subkeys[2*i+1])
		}
	}

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	// switch left & right and perform final permutation
	preOutput := (uint64(right) << 32) | uint64(left)
	return permuteFinalBlock(preOutput)
}

// A TripleDESCipher is an instance of TripleDES encryption.
type TripleDESCipher struct {
	cipher1, cipher2, cipher3 Cipher
}

// NewTripleDESCipher creates and returns a new TripleDESCipher.
func NewTripleDESCipher(key [3]uint64) *TripleDESCipher {
	c := new(TripleDESCipher)
	c.cipher1.generateSubkeys(key[0])
	c.cipher2.generateSubkeys(key[1])
	c.cipher3.generateSubkeys(key[2])
	return c
}

func (c *TripleDESCipher) EncryptBlock(block uint64) uint64 {
	b := permuteInitialBlock(block)
	left, right := uint32(b>>32), uint32(b)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher1.subkeys[2*i], c.cipher1.subkeys[2*i+1])
	}
	for i := 0; i < 8; i++ {
		right, left = feistel(right, left, c.cipher2.subkeys[15-2*i], c.cipher2.subkeys[15-(2*i+1)])
	}
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher3.subkeys[2*i], c.cipher3.subkeys[2*i+1])
	}

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	preOutput := (uint64(right) << 32) | uint64(left)
	return permuteFinalBlock(preOutput)
}

func (c *TripleDESCipher) DecryptBlock(block uint64) uint64 {
	b := permuteInitialBlock(block)
	left, right := uint32(b>>32), uint32(b)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher3.subkeys[15-2*i], c.cipher3.subkeys[15-(2*i+1)])
	}
	for i := 0; i < 8; i++ {
		right, left = feistel(right, left, c.cipher2.subkeys[2*i], c.cipher2.subkeys[2*i+1])
	}
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher1.subkeys[15-2*i], c.cipher1.subkeys[15-(2*i+1)])
	}

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	preOutput := (uint64(right) << 32) | uint64(left)
	return permuteFinalBlock(preOutput)
}
