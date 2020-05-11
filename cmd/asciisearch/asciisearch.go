package main

import (
	"encoding/binary"
	"log"
	"time"

	"github.com/andrewarchi/adobe-cred/des"
)

var (
	cipher uint64 = 0x2fca9b003de39778
	plain  uint64 = binary.BigEndian.Uint64([]byte("password"))

	count = 0
	t0    = time.Now()
)

func main() {
	t0 := time.Now()
	c := des.NewCracker(plain, cipher)
	if key, ok := searchASCIIKey(c, 0, 0); ok {
		log.Printf("Key %d found in %v", key, time.Since(t0))
	}
	log.Printf("Key not found in %v", time.Since(t0))
}

func searchASCIIKey(c *des.Cracker, keyPrefix uint64, i uint8) (uint64, bool) {
	// Right shift skips parity bits
	for b := uint64(' ' >> 1); b <= '~'>>1; b++ {
		k := keyPrefix | (b << i)
		if i == 49 {
			if key, ok := c.CheckKey(k); ok {
				return key, true
			}
			count++
			if count&0xffffff == 0 {
				log.Printf("Tried %d keys in %v\n", count, time.Since(t0))
			}
			// var s [8]byte
			// binary.BigEndian.PutUint64(s[:], unpackParity(k))
			// log.Printf("Tried key %s\n", string(s[:]))
		} else if key, ok := searchASCIIKey(c, k, i+7); ok {
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
