package main

import (
	"crypto/des"
	"fmt"
	"time"
)

// DES brute force. The key size should be 56 bits, but Go accepts 64
// bit keys. The credentials alternatively may have used triple DES, in
// which case this approach will not work.
func main() {
	cipher := []byte{0x2f, 0xca, 0x9b, 0x00, 0x3d, 0xe3, 0x97, 0x78}
	plain := [8]byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	var key [8]byte
	var out [8]byte
	start := time.Now()
	t := start
	for i := 0; i < 1<<63-1; i++ {
		key[0] = byte((i >> 56) & 0xff)
		key[1] = byte((i >> 48) & 0xff)
		key[2] = byte((i >> 40) & 0xff)
		key[3] = byte((i >> 32) & 0xff)
		key[4] = byte((i >> 24) & 0xff)
		key[5] = byte((i >> 16) & 0xff)
		key[6] = byte((i >> 8) & 0xff)
		key[7] = byte(i & 0xff)

		d, err := des.NewCipher(key[:])
		if err != nil {
			panic(err)
		}
		d.Decrypt(out[:], cipher)
		if out == plain {
			fmt.Printf("key %x matches\n", key)
			break
		}
		if i&0xffffff == 0 {
			now := time.Now()
			fmt.Printf("%d keys tried, %v %v\n", i, now.Sub(start), now.Sub(t))
			t = now
		}
	}
}
