package des

import (
	"math/rand"
	"testing"
)

func TestParityPack(t *testing.T) {
	for i := 0; i < 1000; i++ {
		key64a := rand.Uint64()
		key56a := PackParity(key64a)
		key64b := UnpackParity(key56a)
		key56b := PackParity(key64b)
		if k := key64a &^ 0x0101010101010101; k != key64b {
			t.Errorf("key without parity bits not equal: %x and %x", k, key64b)
		}
		if key56a != key56b {
			t.Errorf("intersperse not two-way: %x and %x", key56a, key56b)
		}

		ca := NewCipher(key64a)
		cb := NewCipher(key64b)

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
