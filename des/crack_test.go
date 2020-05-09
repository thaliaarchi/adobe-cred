// Copyright 2020 Andrew Archibald. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

import "testing"

func TestCheckKey(t *testing.T) {
	for i, tt := range encryptDESTests {
		c := NewCracker(tt.out, tt.in)
		key56 := permuteBlock(tt.key, permutedChoice1[:])
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
