package main

import (
	"math/rand"
	"testing"

	"github.com/andrewarchi/adobe-cred/des"
)

func TestIntersperse(t *testing.T) {
	for i := 0; i < 1000; i++ {
		key64a := rand.Uint64()
		key56a := des.Collapse56(key64a)
		key64b := des.Intersperse56(key56a)
		key56b := des.Collapse56(key64b)
		if k := key64a &^ 0x0101010101010101; k != key64b {
			t.Errorf("key without parity bits not equal: %x and %x", k, key64b)
		}
		if key56a != key56b {
			t.Errorf("intersperse not two-way: %x and %x", key56a, key56b)
		}

		ca := des.NewCipher(key64a)
		cb := des.NewCipher(key64b)

		plain := rand.Uint64()
		outa := ca.EncryptBlock(plain)
		outb := cb.EncryptBlock(plain)
		if outa != outb {
			t.Errorf("encrypt not equal: %x and %x", outa, outb)
		}
		plaina := ca.DecryptBlock(outa)
		plainb := cb.DecryptBlock(outb)
		if plaina != plainb || plaina != plain {
			t.Errorf("decrypt not equal to %x: %x and %x", plain, outa, outb)
		}
	}
}
