package main

// IntersperseKey expands a 56-bit key into 64 bits by interspersing
// zeros at every eighth bit. Each byte has a parity bit that is
// discarded when permuting the key. Ignoring these reduces our key
// space to 2 ** 56 keys.
func IntersperseKey(key56 uint64) (key64 uint64) {
	return (key56&0x7f)<<1 |
		(key56&(0x7f<<7))<<2 |
		(key56&(0x7f<<14))<<3 |
		(key56&(0x7f<<21))<<4 |
		(key56&(0x7f<<28))<<5 |
		(key56&(0x7f<<35))<<6 |
		(key56&(0x7f<<42))<<7 |
		(key56&(0x7f<<49))<<8
}

// CollapseKey removes parity bits from a key. This is the inverse
// operation of IntersperseKey.
func CollapseKey(key64 uint64) (key56 uint64) {
	return (key64>>1)&0x7f |
		(key64>>2)&(0x7f<<7) |
		(key64>>3)&(0x7f<<14) |
		(key64>>4)&(0x7f<<21) |
		(key64>>5)&(0x7f<<28) |
		(key64>>6)&(0x7f<<35) |
		(key64>>7)&(0x7f<<42) |
		(key64>>8)&(0x7f<<49)
}
