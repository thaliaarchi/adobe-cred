// Copyright 2020 Andrew Archibald. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/des"
	"encoding/binary"
	"testing"
)

func BenchmarkNewCipher(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewCipher(0x736563523374243b) // "secR3t$;"
	}
}

func BenchmarkGoNewCipher(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = des.NewCipher([]byte("secR3t$;"))
	}
}

func BenchmarkEncryptBlock(b *testing.B) {
	c := NewCipher(0x736563523374243b) // "secR3t$;"
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.EncryptBlock(0x6120746573743132) // "a test12"
	}
}

func BenchmarkGoEncrypt(b *testing.B) {
	c, _ := des.NewCipher([]byte("secR3t$;"))
	var dst [8]byte
	src := [8]byte{'a', ' ', 't', 'e', 's', 't', '1', '2'}
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst[:], src[:])
	}
}

func BenchmarkEncryptSearch(b *testing.B) {
	c := NewCipher(0x736563523374243b) // "secR3t$;"
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for k := uint64(0); k < 0xff; k++ {
			_ = c.EncryptBlock(k)
		}
	}
}

func BenchmarkGoEncryptSearch(b *testing.B) {
	var key, dst [8]byte
	src := [8]byte{'a', ' ', 't', 'e', 's', 't', '1', '2'}
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for k := uint64(0); k < 0xff; k++ {
			binary.BigEndian.PutUint64(key[:], k)
			c, _ := des.NewCipher(key[:])
			c.Encrypt(dst[:], src[:])
		}
	}
}
