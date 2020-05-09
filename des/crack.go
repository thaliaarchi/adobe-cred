// Copyright 2020 Andrew Archibald. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

// Cracker is an instance of DES encryption.
type Cracker struct {
	cipher uint64
	plain  uint64
}

// NewCracker creates and returns a new Cracker.
func NewCracker(cipher, plain uint64) *Cracker {
	c := new(Cracker)
	c.cipher = permuteInitialBlock(cipher)
	c.plain = permuteInitialBlock(plain)
	return c
}

func (c *Cracker) CheckKey(key uint64) bool {
	// apply PC1 permutation to key
	permutedKey := permuteBlock(key, permutedChoice1[:])

	// rotate halves of permuted key according to the rotation schedule
	leftRotations := ksRotate(uint32(permutedKey >> 28))
	rightRotations := ksRotate(uint32(permutedKey<<4) >> 4)

	// generate subkeys
	var subkeys [16]uint64
	for i := 0; i < 16; i++ {
		// combine halves to form 56-bit input to PC2
		pc2Input := uint64(leftRotations[i])<<28 | uint64(rightRotations[i])
		// apply PC2 permutation to 7 byte input
		subkeys[i] = unpack(permuteBlock(pc2Input, permutedChoice2[:]))
	}

	// decrypt
	left, right := uint32(c.plain>>32), uint32(c.plain)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, subkeys[2*i], subkeys[2*i+1])
	}

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	// switch left & right
	preOutput := (uint64(right) << 32) | uint64(left)
	return preOutput == c.cipher
}
