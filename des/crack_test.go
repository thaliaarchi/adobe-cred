// Copyright 2020 Andrew Archibald. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

import "testing"

func TestCheckKey(t *testing.T) {
	for i, tt := range encryptDESTests {
		c := NewCracker(tt.in, tt.out)
		key56 := permuteChoice1(tt.key)
		key64, ok := c.CheckKey(key56)
		if !ok {
			t.Errorf("#%d: key %x not ok", i, key56)
		}

		d := NewCipher(key64)
		out := d.EncryptBlock(tt.in)
		if out != tt.out {
			t.Errorf("#%d: key %x encrypt: %x want %x", i, key64, out, tt.out)
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
