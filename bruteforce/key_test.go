package main

import (
	"crypto/des"
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestIntersperse(t *testing.T) {
	for i := 0; i < 1000; i++ {
		key64a := rand.Uint64()
		key56a := CollapseKey(key64a)
		key64b := IntersperseKey(key56a)
		key56b := CollapseKey(key64b)
		if k := key64a &^ 0x0101010101010101; k != key64b {
			t.Errorf("key without parity bits not equal: %x and %x", k, key64b)
		}
		if key56a != key56b {
			t.Errorf("intersperse not two-way: %x and %x", key56a, key56b)
		}

		var keya, keyb [8]byte
		binary.BigEndian.PutUint64(keya[:], key64a)
		binary.BigEndian.PutUint64(keyb[:], key64b)
		da, err := des.NewCipher(keya[:])
		if err != nil {
			t.Error(err)
		}
		db, err := des.NewCipher(keyb[:])
		if err != nil {
			t.Error(err)
		}

		var outa, outb, plaina, plainb, plain [8]byte
		binary.BigEndian.PutUint64(plain[:], rand.Uint64())
		da.Encrypt(outa[:], plain[:])
		db.Encrypt(outb[:], plain[:])
		if outa != outb {
			t.Errorf("encrypt not equal: %x and %x", outa, outb)
		}
		da.Decrypt(plaina[:], outa[:])
		db.Decrypt(plainb[:], outb[:])
		if plaina != plainb || plaina != plain {
			t.Errorf("decrypt not equal to %x: %x and %x", plain, outa, outb)
		}
	}
}
