// Copyright 2020 Andrew Archibald. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

import "testing"

func TestCheckKey(t *testing.T) {
	for i, tt := range encryptDESTests {
		c := NewCracker(tt.in, tt.out)
		permutedKey := permuteChoice1(tt.key)
		key, ok := c.CheckKey(permutedKey)
		if !ok {
			t.Errorf("#%d: key %x not ok", i, permutedKey)
		}

		out := NewCipher(key).EncryptBlock(tt.in)
		if out != tt.out {
			t.Errorf("#%d: key %x encrypt: %x want %x", i, key, out, tt.out)
		}

		badKey := permuteChoice1(tt.key + 127)
		if _, ok := c.CheckKey(badKey); ok {
			t.Errorf("#%d: key should not match: %x", i, badKey)
		}
	}
}

func TestSearchKey(t *testing.T) {
	for i, tt := range encryptDESTests {
		c := NewCracker(tt.in, tt.out)
		permutedKey := permuteChoice1(tt.key)
		min, max := uint64(0), permutedKey+10
		if permutedKey > 10 {
			min = permutedKey - 10
		}

		key, ok := c.SearchKey(min, max)
		if !ok {
			t.Errorf("#%d: key not found in range [%x, %x)", i, min, max)
		}
		if want := maskParity(tt.key); key != want {
			t.Errorf("#%d: found key not equal: %x want %x", i, key, want)
		}

		min, max = permutedKey+1, permutedKey+10
		if key, ok := c.SearchKey(min, max); ok {
			t.Errorf("#%d: key %x found in range [%x, %x)", i, key, min, max)
		}
	}
}

func BenchmarkCrackerSearchKey(b *testing.B) {
	tt := encryptDESTests[0]
	c := NewCracker(tt.in, tt.out)
	max := permuteChoice1(tt.key) + 100
	min := max - 100000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.SearchKey(min, max)
	}
}

func BenchmarkEncryptSearchKey(b *testing.B) {
	tt := encryptDESTests[0]
	max := tt.key + 100
	min := max - 100000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = searchKey(tt.in, tt.out, min, max)
	}
}

func searchKey(in, out, min, max uint64) (key uint64, ok bool) {
	for i := min; i < max; i++ {
		key := unpackParity(i)
		c := NewCipher(key)
		out := c.EncryptBlock(in)
		if out == out {
			return key, true
		}
	}
	return 0, false
}

// unpackParity expands a 56-bit key into 64 bits by interspersing zeros
// at every eighth bit.
func unpackParity(key56 uint64) (key64 uint64) {
	return (key56&0x7f)<<1 |
		(key56&(0x7f<<7))<<2 |
		(key56&(0x7f<<14))<<3 |
		(key56&(0x7f<<21))<<4 |
		(key56&(0x7f<<28))<<5 |
		(key56&(0x7f<<35))<<6 |
		(key56&(0x7f<<42))<<7 |
		(key56&(0x7f<<49))<<8
}

// packParity removes parity bits from a key. This is the inverse
// operation of unpackParity.
func packParity(key64 uint64) (key56 uint64) {
	return (key64>>1)&0x7f |
		(key64>>2)&(0x7f<<7) |
		(key64>>3)&(0x7f<<14) |
		(key64>>4)&(0x7f<<21) |
		(key64>>5)&(0x7f<<28) |
		(key64>>6)&(0x7f<<35) |
		(key64>>7)&(0x7f<<42) |
		(key64>>8)&(0x7f<<49)
}

// maskParity clears the parity bits in a key.
func maskParity(key64 uint64) uint64 {
	return key64 &^ 0x0101010101010101
}
