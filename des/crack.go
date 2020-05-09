// Copyright 2020 Andrew Archibald. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

// Cracker is an instance of DES encryption.
type Cracker struct {
	in  uint64
	out uint64
}

// NewCracker creates and returns a new Cracker.
func NewCracker(in, out uint64) *Cracker {
	c := new(Cracker)
	c.in = permuteInitialBlock(in)
	c.out = permuteInitialBlock(out)
	return c
}

// CheckKey checks whether the given permuted 56-biy key encrypts to the
// cipher text and returns the key in the format used by des.Cipher.
func (c *Cracker) CheckKey(permutedKey uint64) (key uint64, ok bool) {
	// rotate halves of key according to the rotation schedule
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
	left, right := uint32(c.in>>32), uint32(c.in)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, subkeys[2*i], subkeys[2*i+1])
	}

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	// switch left & right
	preOutput := (uint64(right) << 32) | uint64(left)

	if preOutput == c.out {
		// apply PC1 permutation to key in reverse
		key = permuteBlockInverse(permutedKey, permutedChoice1[:])
		return key, true
	}
	return 0, false
}

func (c *Cracker) SearchKey(min, max uint64) (key uint64, ok bool) {
	for i := min; i < max; i++ {
		if key, ok := c.CheckKey(i); ok {
			return key, true
		}
	}
	return 0, false
}

func searchKey(in, out, min, max uint64) (key uint64, ok bool) {
	for i := min; i < max; i++ {
		key := Intersperse56(i)
		c := NewCipher(key)
		out := c.EncryptBlock(in)
		if out == out {
			return key, true
		}
	}
	return 0, false
}
