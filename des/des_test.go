// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

import (
	"testing"
)

type DESTest struct {
	key uint64
	in  uint64
	out uint64
}

type TripleDESTest struct {
	key [3]uint64
	in  uint64
	out uint64
}

// some custom tests for DES
var encryptDESTests = []DESTest{
	{0x0000000000000000, 0x0000000000000000, 0x8ca64de9c1b123a7},
	{0x0000000000000000, 0xffffffffffffffff, 0x355550b2150e2451},
	{0x0000000000000000, 0x0123456789abcdef, 0x617b3a0ce8f07100},
	{0x0000000000000000, 0xfedcba9876543210, 0x9231f236ff9aa95c},
	{0xffffffffffffffff, 0x0000000000000000, 0xcaaaaf4deaf1dbae},
	{0xffffffffffffffff, 0xffffffffffffffff, 0x7359b2163e4edc58},
	{0xffffffffffffffff, 0x0123456789abcdef, 0x6dce0dc9006556a3},
	{0xffffffffffffffff, 0xfedcba9876543210, 0x9e84c5f3170f8eff},
	{0x0123456789abcdef, 0x0000000000000000, 0xd5d44ff720683d0d},
	{0x0123456789abcdef, 0xffffffffffffffff, 0x59732356f36fde06},
	{0x0123456789abcdef, 0x0123456789abcdef, 0x56cc09e7cfdc4cef},
	{0x0123456789abcdef, 0xfedcba9876543210, 0x12c626af058b433b},
	{0xfedcba9876543210, 0x0000000000000000, 0xa68cdca90c9021f9},
	{0xfedcba9876543210, 0xffffffffffffffff, 0x2a2bb008df97c2f2},
	{0xfedcba9876543210, 0x0123456789abcdef, 0xed39d950fa74bcc4},
	{0xfedcba9876543210, 0xfedcba9876543210, 0xa933f6183023b310},
	{0x0123456789abcdef, 0x1111111111111111, 0x17668dfc7292532d},
	{0x0123456789abcdef, 0x0101010101010101, 0xb4fd231647a5bec0},
	{0x0e329232ea6d0d73, 0x8787878787878787, 0x0000000000000000},
	{0x736563523374243b, 0x6120746573743132, 0x370dee2c1fb4f7a5}, // key "secR3t$;", in "a test12"
	{0x6162636465666768, 0x6162636465666768, 0x2a8d69de9d5fdff9}, // key "abcdefgh", in "abcdefgh"
	{0x6162636465666768, 0x3132333435363738, 0x21c60da534248bce}, // key "abcdefgh", in "12345678"
	{0x3132333435363738, 0x6162636465666768, 0x94d4436bc3b5b693}, // key "12345678", in "abcdefgh"
	{0x1f79905f8801c888, 0xc7461873af485fb3, 0xb0935088f992446a}, // key random, in random
	{0xe6f4f2db31425301, 0xff3d255012e34ac5, 0x8608d3d16c2fd255}, // key random, in random
	{0x69c19dc115c5fb2b, 0x1a225caf1f1da3f9, 0x64ba316756911ea7}, // key random, in random
	{0x6e5ee247c4bff651, 0x11c957ff66890ef0, 0x94c535b2c58b3972}, // key random, in random
}

var weakKeyTests = []DESTest{
	{0x0101010101010101, 0x5574c0bd7cdff739, 0}, // in random
	{0xfefefefefefefefe, 0xe8e1a7c1de1189aa, 0}, // in random
	{0xe0e0e0e0f1f1f1f1, 0x506a4b943bed7ddc, 0}, // in random
	{0x1f1f1f1f0e0e0e0e, 0x88815638ec3b1c97, 0}, // in random
	{0x0000000000000000, 0x17a0836232fe9a0b, 0}, // in random
	{0xffffffffffffffff, 0xca8fca1f50c57b49, 0}, // in random
	{0xe1e1e1e1f0f0f0f0, 0xb1eaad7de7c37a43, 0}, // in random
	{0x1e1e1e1e0f0f0f0f, 0xae747d6fef16bb81, 0}, // in random
}

var semiWeakKeyTests = []DESTest{
	// key and out contain the semi-weak key pair
	{0x011f011f010e010e, 0x12fa3116f9c50ae4, 0x1f011f010e010e01}, // in random
	{0x01e001e001f101f1, 0xb04c7aeed2e54db7, 0xe001e001f101f101}, // in random
	{0x01fe01fe01fe01fe, 0xa481cdb1646fd3bc, 0xfe01fe01fe01fe01}, // in random
	{0x1fe01fe00ef10ef1, 0xee27dd884c22cdce, 0xe01fe01ff10ef10e}, // in random
	{0x1ffe1ffe0efe0efe, 0x193dcf9770fbabe1, 0xfe1ffe1ffe0efe0e}, // in random
	{0xe0fee0fef1fef1fe, 0x7c8269e41e8699d7, 0xfee0fee0fef1fef1}, // in random
}

// some custom tests for TripleDES
var encryptTripleDESTests = []TripleDESTest{
	{
		[3]uint64{0x0000000000000000, 0xffffffffffffffff, 0x0000000000000000},
		0x0000000000000000,
		0x9295b59bb384736e},
	{
		[3]uint64{0x0000000000000000, 0xffffffffffffffff, 0x0000000000000000},
		0xffffffffffffffff,
		0xc197f558748a20e7},
	{
		[3]uint64{0xffffffffffffffff, 0x0000000000000000, 0xffffffffffffffff},
		0x0000000000000000,
		0x3e680aa78b75df18},
	{
		[3]uint64{0xffffffffffffffff, 0x0000000000000000, 0xffffffffffffffff},
		0xffffffffffffffff,
		0x6d6a4a644c7b8c91},
	{
		[3]uint64{0x6162636465666768, 0x3132333435363738, 0x4142434445464748}, // "abcdefgh12345678ABCDEFGH"
		0x3030303030303030, // "00000000"
		0xe461b759688bff66},
	{
		[3]uint64{0x6162636465666768, 0x3132333435363738, 0x4142434445464748}, // "abcdefgh12345678ABCDEFGH"
		0x3132333435363738, // "12345678"
		0xdbd092def834ff58},
	{
		[3]uint64{0x6162636465666768, 0x3132333435363738, 0x4142434445464748}, // "abcdefgh12345678ABCDEFGH"
		0xf0c58222d3e612d2, // random
		0xbae441b13c374df4},
	{
		[3]uint64{0xd37d45ee22e9cf52, 0xf465a24f70d1818a, 0x3dbe2f39c771d2e9}, // random
		0x4953c3e978df9faf, // random
		0x53405124d83cf988},
	{
		[3]uint64{0xcb107dda7e96570a, 0xe8ebe8078e87d357, 0xb26112b82a90b72f}, // random
		0xa3c260b10bb7286e, // random
		0x56737dfbb5a1c3de},
}

// NIST Special Publication 800-20, Appendix A
// Key for use with Table A.1 tests
var tableA1Key = [3]uint64{
	0x0101010101010101,
	0x0101010101010101,
	0x0101010101010101,
}

// Table A.1 Resulting Ciphertext from the Variable Plaintext Known Answer Test
var tableA1Tests = []DESTest{
	{0, 0x8000000000000000, 0x95f8a5e5dd31d900}, // 0
	{0, 0x4000000000000000, 0xdd7f121ca5015619}, // 1
	{0, 0x2000000000000000, 0x2e8653104f3834ea}, // 2
	{0, 0x1000000000000000, 0x4bd388ff6cd81d4f}, // 3
	{0, 0x0800000000000000, 0x20b9e767b2fb1456}, // 4
	{0, 0x0400000000000000, 0x55579380d77138ef}, // 5
	{0, 0x0200000000000000, 0x6cc5defaaf04512f}, // 6
	{0, 0x0100000000000000, 0x0d9f279ba5d87260}, // 7
	{0, 0x0080000000000000, 0xd9031b0271bd5a0a}, // 8
	{0, 0x0040000000000000, 0x424250b37c3dd951}, // 9
	{0, 0x0020000000000000, 0xb8061b7ecd9a21e5}, // 10
	{0, 0x0010000000000000, 0xf15d0f286b65bd28}, // 11
	{0, 0x0008000000000000, 0xadd0cc8d6e5deba1}, // 12
	{0, 0x0004000000000000, 0xe6d5f82752ad63d1}, // 13
	{0, 0x0002000000000000, 0xecbfe3bd3f591a5e}, // 14
	{0, 0x0001000000000000, 0xf356834379d165cd}, // 15
	{0, 0x0000800000000000, 0x2b9f982f20037fa9}, // 16
	{0, 0x0000400000000000, 0x889de068a16f0be6}, // 17
	{0, 0x0000200000000000, 0xe19e275d846a1298}, // 18
	{0, 0x0000100000000000, 0x329a8ed523d71aec}, // 19
	{0, 0x0000080000000000, 0xe7fce22557d23c97}, // 20
	{0, 0x0000040000000000, 0x12a9f5817ff2d65d}, // 21
	{0, 0x0000020000000000, 0xa484c3ad38dc9c19}, // 22
	{0, 0x0000010000000000, 0xfbe00a8a1ef8ad72}, // 23
	{0, 0x0000008000000000, 0x750d079407521363}, // 24
	{0, 0x0000004000000000, 0x64feed9c724c2faf}, // 25
	{0, 0x0000002000000000, 0xf02b263b328e2b60}, // 26
	{0, 0x0000001000000000, 0x9d64555a9a10b852}, // 27
	{0, 0x0000000800000000, 0xd106ff0bed5255d7}, // 28
	{0, 0x0000000400000000, 0xe1652c6b138c64a5}, // 29
	{0, 0x0000000200000000, 0xe428581186ec8f46}, // 30
	{0, 0x0000000100000000, 0xaeb5f5ede22d1a36}, // 31
	{0, 0x0000000080000000, 0xe943d7568aec0c5c}, // 32
	{0, 0x0000000040000000, 0xdf98c8276f54b04b}, // 33
	{0, 0x0000000020000000, 0xb160e4680f6c696f}, // 34
	{0, 0x0000000010000000, 0xfa0752b07d9c4ab8}, // 35
	{0, 0x0000000008000000, 0xca3a2b036dbc8502}, // 36
	{0, 0x0000000004000000, 0x5e0905517bb59bcf}, // 37
	{0, 0x0000000002000000, 0x814eeb3b91d90726}, // 38
	{0, 0x0000000001000000, 0x4d49db1532919c9f}, // 39
	{0, 0x0000000000800000, 0x25eb5fc3f8cf0621}, // 40
	{0, 0x0000000000400000, 0xab6a20c0620d1c6f}, // 41
	{0, 0x0000000000200000, 0x79e90dbc98f92cca}, // 42
	{0, 0x0000000000100000, 0x866ecedd8072bb0e}, // 43
	{0, 0x0000000000080000, 0x8b54536f2f3e64a8}, // 44
	{0, 0x0000000000040000, 0xea51d3975595b86b}, // 45
	{0, 0x0000000000020000, 0xcaffc6ac4542de31}, // 46
	{0, 0x0000000000010000, 0x8dd45a2ddf90796c}, // 47
	{0, 0x0000000000008000, 0x1029d55e880ec2d0}, // 48
	{0, 0x0000000000004000, 0x5d86cb23639dbea9}, // 49
	{0, 0x0000000000002000, 0x1d1ca853ae7c0c5f}, // 50
	{0, 0x0000000000001000, 0xce332329248f3228}, // 51
	{0, 0x0000000000000800, 0x8405d1abe24fb942}, // 52
	{0, 0x0000000000000400, 0xe643d78090ca4207}, // 53
	{0, 0x0000000000000200, 0x48221b9937748a23}, // 54
	{0, 0x0000000000000100, 0xdd7c0bbd61fafd54}, // 55
	{0, 0x0000000000000080, 0x2fbc291a570db5c4}, // 56
	{0, 0x0000000000000040, 0xe07c30d7e4e26e12}, // 57
	{0, 0x0000000000000020, 0x0953e2258e8e90a1}, // 58
	{0, 0x0000000000000010, 0x5b711bc4ceebf2ee}, // 59
	{0, 0x0000000000000008, 0xcc083f1e6d9e85f6}, // 60
	{0, 0x0000000000000004, 0xd2fd8867d50d2dfe}, // 61
	{0, 0x0000000000000002, 0x06e7ea22ce92708f}, // 62
	{0, 0x0000000000000001, 0x166b40b44aba4bd6}, // 63
}

// Plaintext for use with Table A.2 tests
var tableA2Plaintext uint64 = 0x0000000000000000

// Table A.2 Resulting Ciphertext from the Variable Key Known Answer Test
var tableA2Tests = []TripleDESTest{
	{ // 0
		[3]uint64{0x8001010101010101, 0x8001010101010101, 0x8001010101010101},
		0,
		0x95a8d72813daa94d},
	{ // 1
		[3]uint64{0x4001010101010101, 0x4001010101010101, 0x4001010101010101},
		0,
		0x0eec1487dd8c26d5},
	{ // 2
		[3]uint64{0x2001010101010101, 0x2001010101010101, 0x2001010101010101},
		0,
		0x7ad16ffb79c45926},
	{ // 3
		[3]uint64{0x1001010101010101, 0x1001010101010101, 0x1001010101010101},
		0,
		0xd3746294ca6a6cf3},
	{ // 4
		[3]uint64{0x0801010101010101, 0x0801010101010101, 0x0801010101010101},
		0,
		0x809f5f873c1fd761},
	{ // 5
		[3]uint64{0x0401010101010101, 0x0401010101010101, 0x0401010101010101},
		0,
		0xc02faffec989d1fc},
	{ // 6
		[3]uint64{0x0201010101010101, 0x0201010101010101, 0x0201010101010101},
		0,
		0x4615aa1d33e72f10},
	{ // 7
		[3]uint64{0x0180010101010101, 0x0180010101010101, 0x0180010101010101},
		0,
		0x2055123350c00858},
	{ // 8
		[3]uint64{0x0140010101010101, 0x0140010101010101, 0x0140010101010101},
		0,
		0xdf3b99d6577397c8},
	{ // 9
		[3]uint64{0x0120010101010101, 0x0120010101010101, 0x0120010101010101},
		0,
		0x31fe17369b5288c9},
	{ // 10
		[3]uint64{0x0110010101010101, 0x0110010101010101, 0x0110010101010101},
		0,
		0xdfdd3cc64dae1642},
	{ // 11
		[3]uint64{0x0108010101010101, 0x0108010101010101, 0x0108010101010101},
		0,
		0x178c83ce2b399d94},
	{ // 12
		[3]uint64{0x0104010101010101, 0x0104010101010101, 0x0104010101010101},
		0,
		0x50f636324a9b7f80},
	{ // 13
		[3]uint64{0x0102010101010101, 0x0102010101010101, 0x0102010101010101},
		0,
		0xa8468ee3bc18f06d},
	{ // 14
		[3]uint64{0x0101800101010101, 0x0101800101010101, 0x0101800101010101},
		0,
		0xa2dc9e92fd3cde92},
	{ // 15
		[3]uint64{0x0101400101010101, 0x0101400101010101, 0x0101400101010101},
		0,
		0xcac09f797d031287},
	{ // 16
		[3]uint64{0x0101200101010101, 0x0101200101010101, 0x0101200101010101},
		0,
		0x90ba680b22aeb525},
	{ // 17
		[3]uint64{0x0101100101010101, 0x0101100101010101, 0x0101100101010101},
		0,
		0xce7a24f350e280b6},
	{ // 18
		[3]uint64{0x0101080101010101, 0x0101080101010101, 0x0101080101010101},
		0,
		0x882bff0aa01a0b87},
	{ // 19
		[3]uint64{0x0101040101010101, 0x0101040101010101, 0x0101040101010101},
		0,
		0x25610288924511c2},
	{ // 20
		[3]uint64{0x0101020101010101, 0x0101020101010101, 0x0101020101010101},
		0,
		0xc71516c29c75d170},
	{ // 21
		[3]uint64{0x0101018001010101, 0x0101018001010101, 0x0101018001010101},
		0,
		0x5199c29a52c9f059},
	{ // 22
		[3]uint64{0x0101014001010101, 0x0101014001010101, 0x0101014001010101},
		0,
		0xc22f0a294a71f29f},
	{ // 23
		[3]uint64{0x0101012001010101, 0x0101012001010101, 0x0101012001010101},
		0,
		0xee371483714c02ea},
	{ // 24
		[3]uint64{0x0101011001010101, 0x0101011001010101, 0x0101011001010101},
		0,
		0xa81fbd448f9e522f},
	{ // 25
		[3]uint64{0x0101010801010101, 0x0101010801010101, 0x0101010801010101},
		0,
		0x4f644c92e192dfed},
	{ // 26
		[3]uint64{0x0101010401010101, 0x0101010401010101, 0x0101010401010101},
		0,
		0x1afa9a66a6df92ae},
	{ // 27
		[3]uint64{0x0101010201010101, 0x0101010201010101, 0x0101010201010101},
		0,
		0xb3c1cc715cb879d8},
	{ // 28
		[3]uint64{0x0101010180010101, 0x0101010180010101, 0x0101010180010101},
		0,
		0x19d032e64ab0bd8b},
	{ // 29
		[3]uint64{0x0101010140010101, 0x0101010140010101, 0x0101010140010101},
		0,
		0x3cfaa7a7dc8720dc},
	{ // 30
		[3]uint64{0x0101010120010101, 0x0101010120010101, 0x0101010120010101},
		0,
		0xb7265f7f447ac6f3},
	{ // 31
		[3]uint64{0x0101010110010101, 0x0101010110010101, 0x0101010110010101},
		0,
		0x9db73b3c0d163f54},
	{ // 32
		[3]uint64{0x0101010108010101, 0x0101010108010101, 0x0101010108010101},
		0,
		0x8181b65babf4a975},
	{ // 33
		[3]uint64{0x0101010104010101, 0x0101010104010101, 0x0101010104010101},
		0,
		0x93c9b64042eaa240},
	{ // 34
		[3]uint64{0x0101010102010101, 0x0101010102010101, 0x0101010102010101},
		0,
		0x5570530829705592},
	{ // 35
		[3]uint64{0x0101010101800101, 0x0101010101800101, 0x0101010101800101},
		0,
		0x8638809e878787a0},
	{ // 36
		[3]uint64{0x0101010101400101, 0x0101010101400101, 0x0101010101400101},
		0,
		0x41b9a79af79ac208},
	{ // 37
		[3]uint64{0x0101010101200101, 0x0101010101200101, 0x0101010101200101},
		0,
		0x7a9be42f2009a892},
	{ // 38
		[3]uint64{0x0101010101100101, 0x0101010101100101, 0x0101010101100101},
		0,
		0x29038d56ba6d2745},
	{ // 39
		[3]uint64{0x0101010101080101, 0x0101010101080101, 0x0101010101080101},
		0,
		0x5495c6abf1e5df51},
	{ // 40
		[3]uint64{0x0101010101040101, 0x0101010101040101, 0x0101010101040101},
		0,
		0xae13dbd561488933},
	{ // 41
		[3]uint64{0x0101010101020101, 0x0101010101020101, 0x0101010101020101},
		0,
		0x024d1ffa8904e389},
	{ // 42
		[3]uint64{0x0101010101018001, 0x0101010101018001, 0x0101010101018001},
		0,
		0xd1399712f99bf02e},
	{ // 43
		[3]uint64{0x0101010101014001, 0x0101010101014001, 0x0101010101014001},
		0,
		0x14c1d7c1cffec79e},
	{ // 44
		[3]uint64{0x0101010101012001, 0x0101010101012001, 0x0101010101012001},
		0,
		0x1de5279dae3bed6f},
	{ // 45
		[3]uint64{0x0101010101011001, 0x0101010101011001, 0x0101010101011001},
		0,
		0xe941a33f85501303},
	{ // 46
		[3]uint64{0x0101010101010801, 0x0101010101010801, 0x0101010101010801},
		0,
		0xda99dbbc9a03f379},
	{ // 47
		[3]uint64{0x0101010101010401, 0x0101010101010401, 0x0101010101010401},
		0,
		0xb7fc92f91d8e92e9},
	{ // 48
		[3]uint64{0x0101010101010201, 0x0101010101010201, 0x0101010101010201},
		0,
		0xae8e5caa3ca04e85},
	{ // 49
		[3]uint64{0x0101010101010180, 0x0101010101010180, 0x0101010101010180},
		0,
		0x9cc62df43b6eed74},
	{ // 50
		[3]uint64{0x0101010101010140, 0x0101010101010140, 0x0101010101010140},
		0,
		0xd863dbb5c59a91a0},
	{ // 50
		[3]uint64{0x0101010101010120, 0x0101010101010120, 0x0101010101010120},
		0,
		0xa1ab2190545b91d7},
	{ // 52
		[3]uint64{0x0101010101010110, 0x0101010101010110, 0x0101010101010110},
		0,
		0x0875041e64c570f7},
	{ // 53
		[3]uint64{0x0101010101010108, 0x0101010101010108, 0x0101010101010108},
		0,
		0x5a594528bebef1cc},
	{ // 54
		[3]uint64{0x0101010101010104, 0x0101010101010104, 0x0101010101010104},
		0,
		0xfcdb3291de21f0c0},
	{ // 55
		[3]uint64{0x0101010101010102, 0x0101010101010102, 0x0101010101010102},
		0,
		0x869efd7f9f265a09},
}

// Plaintext for use with Table A.3 tests
var tableA3Plaintext uint64 = 0x0000000000000000

// Table A.3 Values To Be Used for the Permutation Operation Known Answer Test
var tableA3Tests = []TripleDESTest{
	{ // 0
		[3]uint64{0x1046913489980131, 0x1046913489980131, 0x1046913489980131},
		0,
		0x88d55e54f54c97b4},
	{ // 1
		[3]uint64{0x1007103489988020, 0x1007103489988020, 0x1007103489988020},
		0,
		0x0c0cc00c83ea48fd},
	{ // 2
		[3]uint64{0x10071034c8980120, 0x10071034c8980120, 0x10071034c8980120},
		0,
		0x83bc8ef3a6570183},
	{ // 3
		[3]uint64{0x1046103489988020, 0x1046103489988020, 0x1046103489988020},
		0,
		0xdf725dcad94ea2e9},
	{ // 4
		[3]uint64{0x1086911519190101, 0x1086911519190101, 0x1086911519190101},
		0,
		0xe652b53b550be8b0},
	{ // 5
		[3]uint64{0x1086911519580101, 0x1086911519580101, 0x1086911519580101},
		0,
		0xaf527120c485cbb0},
	{ // 6
		[3]uint64{0x5107b01519580101, 0x5107b01519580101, 0x5107b01519580101},
		0,
		0x0f04ce393db926d5},
	{ // 7
		[3]uint64{0x1007b01519190101, 0x1007b01519190101, 0x1007b01519190101},
		0,
		0xc9f00ffc74079067},
	{ // 8
		[3]uint64{0x3107915498080101, 0x3107915498080101, 0x3107915498080101},
		0,
		0x7cfd82a593252b4e},
	{ // 9
		[3]uint64{0x3107919498080101, 0x3107919498080101, 0x3107919498080101},
		0,
		0xcb49a2f9e91363e3},
	{ // 10
		[3]uint64{0x10079115b9080140, 0x10079115b9080140, 0x10079115b9080140},
		0,
		0x00b588be70d23f56},
	{ // 11
		[3]uint64{0x3107911598080140, 0x3107911598080140, 0x3107911598080140},
		0,
		0x406a9a6ab43399ae},
	{ // 12
		[3]uint64{0x1007d01589980101, 0x1007d01589980101, 0x1007d01589980101},
		0,
		0x6cb773611dca9ada},
	{ // 13
		[3]uint64{0x9107911589980101, 0x9107911589980101, 0x9107911589980101},
		0,
		0x67fd21c17dbb5d70},
	{ // 14
		[3]uint64{0x9107d01589190101, 0x9107d01589190101, 0x9107d01589190101},
		0,
		0x9592cb4110430787},
	{ // 15
		[3]uint64{0x1007d01598980120, 0x1007d01598980120, 0x1007d01598980120},
		0,
		0xa6b7ff68a318ddd3},
	{ // 16
		[3]uint64{0x1007940498190101, 0x1007940498190101, 0x1007940498190101},
		0,
		0x4d102196c914ca16},
	{ // 17
		[3]uint64{0x0107910491190401, 0x0107910491190401, 0x0107910491190401},
		0,
		0x2dfa9f4573594965},
	{ // 18
		[3]uint64{0x0107910491190101, 0x0107910491190101, 0x0107910491190101},
		0,
		0xb46604816c0e0774},
	{ // 19
		[3]uint64{0x0107940491190401, 0x0107940491190401, 0x0107940491190401},
		0,
		0x6e7e6221a4f34e87},
	{ // 20
		[3]uint64{0x19079210981a0101, 0x19079210981a0101, 0x19079210981a0101},
		0,
		0xaa85e74643233199},
	{ // 21
		[3]uint64{0x1007911998190801, 0x1007911998190801, 0x1007911998190801},
		0,
		0x2e5a19db4d1962d6},
	{ // 22
		[3]uint64{0x10079119981a0801, 0x10079119981a0801, 0x10079119981a0801},
		0,
		0x23a866a809d30894},
	{ // 23
		[3]uint64{0x1007921098190101, 0x1007921098190101, 0x1007921098190101},
		0,
		0xd812d961f017d320},
	{ // 24
		[3]uint64{0x100791159819010b, 0x100791159819010b, 0x100791159819010b},
		0,
		0x055605816e58608f},
	{ // 25
		[3]uint64{0x1004801598190101, 0x1004801598190101, 0x1004801598190101},
		0,
		0xabd88e8b1b7716f1},
	{ // 26
		[3]uint64{0x1004801598190102, 0x1004801598190102, 0x1004801598190102},
		0,
		0x537ac95be69da1e1},
	{ // 27
		[3]uint64{0x1004801598190108, 0x1004801598190108, 0x1004801598190108},
		0,
		0xaed0f6ae3c25cdd8},
	{ // 28
		[3]uint64{0x1002911598100104, 0x1002911598100104, 0x1002911598100104},
		0,
		0xb3e35a5ee53e7b8d},
	{ // 29
		[3]uint64{0x1002911598190104, 0x1002911598190104, 0x1002911598190104},
		0,
		0x61c79c71921a2ef8},
	{ // 30
		[3]uint64{0x1002911598100201, 0x1002911598100201, 0x1002911598100201},
		0,
		0xe2f5728f0995013c},
	{ // 31
		[3]uint64{0x1002911698100101, 0x1002911698100101, 0x1002911698100101},
		0,
		0x1aeac39a61f0a464},
}

// Table A.4 Values To Be Used for the Substitution Table Known Answer Test
var tableA4Tests = []TripleDESTest{
	{ // 0
		[3]uint64{0x7ca110454a1a6e57, 0x7ca110454a1a6e57, 0x7ca110454a1a6e57},
		0x01a1d6d039776742,
		0x690f5b0d9a26939b},
	{ // 1
		[3]uint64{0x0131d9619dc1376e, 0x0131d9619dc1376e, 0x0131d9619dc1376e},
		0x5cd54ca83def57da,
		0x7a389d10354bd271},
	{ // 2
		[3]uint64{0x07a1133e4a0b2686, 0x07a1133e4a0b2686, 0x07a1133e4a0b2686},
		0x0248d43806f67172,
		0x868ebb51cab4599a},
	{ // 3
		[3]uint64{0x3849674c2602319e, 0x3849674c2602319e, 0x3849674c2602319e},
		0x51454b582ddf440a,
		0x7178876e01f19b2a},
	{ // 4
		[3]uint64{0x04b915ba43feb5b6, 0x04b915ba43feb5b6, 0x04b915ba43feb5b6},
		0x42fd443059577fa2,
		0xaf37fb421f8c4095},
	{ // 5
		[3]uint64{0x0113b970fd34f2ce, 0x0113b970fd34f2ce, 0x0113b970fd34f2ce},
		0x059b5e0851cf143a,
		0x86a560f10ec6d85b},
	{ // 6
		[3]uint64{0x0170f175468fb5e6, 0x0170f175468fb5e6, 0x0170f175468fb5e6},
		0x0756d8e0774761d2,
		0x0cd3da020021dc09},
	{ // 7
		[3]uint64{0x43297fad38e373fe, 0x43297fad38e373fe, 0x43297fad38e373fe},
		0x762514b829bf486a,
		0xea676b2cb7db2b7a},
	{ // 8
		[3]uint64{0x07a7137045da2a16, 0x07a7137045da2a16, 0x07a7137045da2a16},
		0x3bdd119049372802,
		0xdfd64a815caf1a0f},
	{ // 9
		[3]uint64{0x04689104c2fd3b2f, 0x04689104c2fd3b2f, 0x04689104c2fd3b2f},
		0x26955f6835af609a,
		0x5c513c9c4886c088},
	{ // 10
		[3]uint64{0x37d06bb516cb7546, 0x37d06bb516cb7546, 0x37d06bb516cb7546},
		0x164d5e404f275232,
		0x0a2aeeae3ff4ab77},
	{ // 11
		[3]uint64{0x1f08260d1ac2465e, 0x1f08260d1ac2465e, 0x1f08260d1ac2465e},
		0x6b056e18759f5cca,
		0xef1bf03e5dfa575a},
	{ // 12
		[3]uint64{0x584023641aba6176, 0x584023641aba6176, 0x584023641aba6176},
		0x004bd6ef09176062,
		0x88bf0db6d70dee56},
	{ // 13
		[3]uint64{0x025816164629b007, 0x025816164629b007, 0x025816164629b007},
		0x480d39006ee762f2,
		0xa1f9915541020b56},
	{ // 14
		[3]uint64{0x49793ebc79b3258f, 0x49793ebc79b3258f, 0x49793ebc79b3258f},
		0x437540c8698f3cfa,
		0x6fbf1cafcffd0556},
	{ // 15
		[3]uint64{0x4fb05e1515ab73a7, 0x4fb05e1515ab73a7, 0x4fb05e1515ab73a7},
		0x072d43a077075292,
		0x2f22e49bab7ca1ac},
	{ // 16
		[3]uint64{0x49e95d6d4ca229bf, 0x49e95d6d4ca229bf, 0x49e95d6d4ca229bf},
		0x02fe55778117f12a,
		0x5a6b612cc26cce4a},
	{ // 17
		[3]uint64{0x018310dc409b26d6, 0x018310dc409b26d6, 0x018310dc409b26d6},
		0x1d9d5c5018f728c2,
		0x5f4c038ed12b2e41},
	{ // 18
		[3]uint64{0x1c587f1c13924fef, 0x1c587f1c13924fef, 0x1c587f1c13924fef},
		0x305532286d6f295a,
		0x63fac0d034d9f793},
}

// Use the known weak keys to test DES implementation
func TestWeakKeys(t *testing.T) {
	for i, tt := range weakKeyTests {
		var encrypt = func(in uint64) (out uint64) {
			c := NewCipher(tt.key)
			out = encryptBlock(c.subkeys[:], in)
			return
		}

		// Encrypting twice with a DES weak
		// key should reproduce the original input
		result := encrypt(tt.in)
		result = encrypt(result)

		if result != tt.in {
			t.Errorf("#%d: result: %x want: %x", i, result, tt.in)
		}
	}
}

// Use the known semi-weak key pairs to test DES implementation
func TestSemiWeakKeyPairs(t *testing.T) {
	for i, tt := range semiWeakKeyTests {
		var encrypt = func(key, in uint64) (out uint64) {
			c := NewCipher(key)
			out = encryptBlock(c.subkeys[:], in)
			return
		}

		// Encrypting with one member of the semi-weak pair
		// and then encrypting the result with the other member
		// should reproduce the original input.
		result := encrypt(tt.key, tt.in)
		result = encrypt(tt.out, result)

		if result != tt.in {
			t.Errorf("#%d: result: %x want: %x", i, result, tt.in)
		}
	}
}

func TestDESEncryptBlock(t *testing.T) {
	for i, tt := range encryptDESTests {
		c := NewCipher(tt.key)
		out := encryptBlock(c.subkeys[:], tt.in)

		if out != tt.out {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.out)
		}
	}
}

func TestDESDecryptBlock(t *testing.T) {
	for i, tt := range encryptDESTests {
		c := NewCipher(tt.key)
		plain := decryptBlock(c.subkeys[:], tt.out)

		if plain != tt.in {
			t.Errorf("#%d: result: %x want: %x", i, plain, tt.in)
		}
	}
}

func TestEncryptTripleDES(t *testing.T) {
	for i, tt := range encryptTripleDESTests {
		c := NewTripleDESCipher(tt.key)
		out := c.EncryptBlock(tt.in)

		if out != tt.out {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.out)
		}
	}
}

func TestDecryptTripleDES(t *testing.T) {
	for i, tt := range encryptTripleDESTests {
		c := NewTripleDESCipher(tt.key)
		plain := c.DecryptBlock(tt.out)

		if plain != tt.in {
			t.Errorf("#%d: result: %x want: %x", i, plain, tt.in)
		}
	}
}

// Defined in Pub 800-20
func TestVariablePlaintextKnownAnswer(t *testing.T) {
	for i, tt := range tableA1Tests {
		c := NewTripleDESCipher(tableA1Key)
		out := c.EncryptBlock(tt.in)

		if out != tt.out {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.out)
		}
	}
}

// Defined in Pub 800-20
func TestVariableCiphertextKnownAnswer(t *testing.T) {
	for i, tt := range tableA1Tests {
		c := NewTripleDESCipher(tableA1Key)
		plain := c.DecryptBlock(tt.out)

		if plain != tt.in {
			t.Errorf("#%d: result: %x want: %x", i, plain, tt.in)
		}
	}
}

// Defined in Pub 800-20
// Encrypting the Table A.1 ciphertext with the
// 0x01... key produces the original plaintext
func TestInversePermutationKnownAnswer(t *testing.T) {
	for i, tt := range tableA1Tests {
		c := NewTripleDESCipher(tableA1Key)
		plain := c.EncryptBlock(tt.out)

		if plain != tt.in {
			t.Errorf("#%d: result: %x want: %x", i, plain, tt.in)
		}
	}
}

// Defined in Pub 800-20
// Decrypting the Table A.1 plaintext with the
// 0x01... key produces the corresponding ciphertext
func TestInitialPermutationKnownAnswer(t *testing.T) {
	for i, tt := range tableA1Tests {
		c := NewTripleDESCipher(tableA1Key)
		out := c.DecryptBlock(tt.in)

		if out != tt.out {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.out)
		}
	}
}

// Defined in Pub 800-20
func TestVariableKeyKnownAnswerEncrypt(t *testing.T) {
	for i, tt := range tableA2Tests {
		c := NewTripleDESCipher(tt.key)
		out := c.EncryptBlock(tableA2Plaintext)

		if out != tt.out {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.out)
		}
	}
}

// Defined in Pub 800-20
func TestVariableKeyKnownAnswerDecrypt(t *testing.T) {
	for i, tt := range tableA2Tests {
		c := NewTripleDESCipher(tt.key)
		out := c.DecryptBlock(tt.out)

		if out != tableA2Plaintext {
			t.Errorf("#%d: result: %x want: %x", i, out, tableA2Plaintext)
		}
	}
}

// Defined in Pub 800-20
func TestPermutationOperationKnownAnswerEncrypt(t *testing.T) {
	for i, tt := range tableA3Tests {
		c := NewTripleDESCipher(tt.key)
		out := c.EncryptBlock(tableA3Plaintext)

		if out != tt.out {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.out)
		}
	}
}

// Defined in Pub 800-20
func TestPermutationOperationKnownAnswerDecrypt(t *testing.T) {
	for i, tt := range tableA3Tests {
		c := NewTripleDESCipher(tt.key)
		out := c.DecryptBlock(tt.out)

		if out != tableA3Plaintext {
			t.Errorf("#%d: result: %x want: %x", i, out, tableA3Plaintext)
		}
	}
}

// Defined in Pub 800-20
func TestSubstitutionTableKnownAnswerEncrypt(t *testing.T) {
	for i, tt := range tableA4Tests {
		c := NewTripleDESCipher(tt.key)
		out := c.EncryptBlock(tt.in)

		if out != tt.out {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.out)
		}
	}
}

// Defined in Pub 800-20
func TestSubstitutionTableKnownAnswerDecrypt(t *testing.T) {
	for i, tt := range tableA4Tests {
		c := NewTripleDESCipher(tt.key)
		out := c.DecryptBlock(tt.out)

		if out != tt.in {
			t.Errorf("#%d: result: %x want: %x", i, out, tt.in)
		}
	}
}

func TestInitialPermute(t *testing.T) {
	for i := uint(0); i < 64; i++ {
		bit := uint64(1) << i
		got := permuteInitialBlock(bit)
		want := uint64(1) << finalPermutation[63-i]
		if got != want {
			t.Errorf("permute(%x) = %x, want %x", bit, got, want)
		}
	}
}

func TestFinalPermute(t *testing.T) {
	for i := uint(0); i < 64; i++ {
		bit := uint64(1) << i
		got := permuteFinalBlock(bit)
		want := uint64(1) << initialPermutation[63-i]
		if got != want {
			t.Errorf("permute(%x) = %x, want %x", bit, got, want)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	tt := encryptDESTests[0]
	c := NewCipher(tt.key)
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.EncryptBlock(tt.in)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	tt := encryptDESTests[0]
	c := NewCipher(tt.key)
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.DecryptBlock(tt.out)
	}
}

func BenchmarkTDESEncrypt(b *testing.B) {
	tt := encryptTripleDESTests[0]
	c := NewTripleDESCipher(tt.key)
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.EncryptBlock(tt.in)
	}
}

func BenchmarkTDESDecrypt(b *testing.B) {
	tt := encryptTripleDESTests[0]
	c := NewTripleDESCipher(tt.key)
	b.SetBytes(BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.DecryptBlock(tt.out)
	}
}
