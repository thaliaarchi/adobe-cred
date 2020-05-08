package main

import (
	"crypto/des"
	"encoding/binary"
	"fmt"
	"time"
)

// DES brute force of all 56-bit keys.
func main() {
	cipher := [8]byte{0x2f, 0xca, 0x9b, 0x00, 0x3d, 0xe3, 0x97, 0x78}
	plain := [8]byte{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	start := time.Now()
	t := start
	for i := uint64(0); i < 1<<56; i += 1 << 24 {
		key, ok, err := desWorker(i, i+1<<24, cipher, plain)
		if err != nil {
			panic(err)
		}
		if ok {
			fmt.Printf("Key found in %v: %x\n", time.Since(start), key)
			break
		}
		now := time.Now()
		fmt.Printf("%d keys tried, %v %v\n", i+1<<24, now.Sub(start), now.Sub(t))
		t = now
	}
}

func desWorker(min, max uint64, cipher, plain [8]byte) (uint64, bool, error) {
	var key [8]byte
	var out [8]byte
	for i := min; i < max; i++ {
		k := IntersperseKey(i)
		binary.BigEndian.PutUint64(key[:], k)
		d, err := des.NewCipher(key[:])
		if err != nil {
			return 0, false, err
		}
		d.Decrypt(out[:], cipher[:])
		if out == plain {
			return k, true, nil
		}
	}
	return 0, false, nil
}
