package sm4

// [GM/T] SM4 GB/T 32907-2016

import (
	"encoding/binary"
	"math/bits"
)

/*
sm4/block.go sm4块加密与块解密
*/

type convert func(uint32) uint32

// sm4块加密
//  Encrypt one block from src into dst, using the expanded key xk.
func encryptBlockGo(xk []uint32, dst, src []byte) {
	_ = src[15] // early bounds check
	_ = dst[15] // early bounds check
	var b0, b1, b2, b3 uint32
	// 切分明文块，获取4个字
	b0 = binary.BigEndian.Uint32(src[0:4])
	b1 = binary.BigEndian.Uint32(src[4:8])
	b2 = binary.BigEndian.Uint32(src[8:12])
	b3 = binary.BigEndian.Uint32(src[12:16])
	// 1~4轮
	b0 ^= t(b1 ^ b2 ^ b3 ^ xk[0])
	b1 ^= t(b2 ^ b3 ^ b0 ^ xk[1])
	b2 ^= t(b3 ^ b0 ^ b1 ^ xk[2])
	b3 ^= t(b0 ^ b1 ^ b2 ^ xk[3])
	// 5~8轮
	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[4])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[5])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[6])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[7])
	// 9~12轮
	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[8])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[9])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[10])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[11])
	// 13~16轮
	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[12])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[13])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[14])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[15])
	// 17~20轮
	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[16])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[17])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[18])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[19])
	// 21~24轮
	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[20])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[21])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[22])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[23])
	// 24～28轮
	b0 ^= precompute_t(b1 ^ b2 ^ b3 ^ xk[24])
	b1 ^= precompute_t(b2 ^ b3 ^ b0 ^ xk[25])
	b2 ^= precompute_t(b3 ^ b0 ^ b1 ^ xk[26])
	b3 ^= precompute_t(b0 ^ b1 ^ b2 ^ xk[27])
	// 29~32轮
	b0 ^= t(b1 ^ b2 ^ b3 ^ xk[28])
	b1 ^= t(b2 ^ b3 ^ b0 ^ xk[29])
	b2 ^= t(b3 ^ b0 ^ b1 ^ xk[30])
	b3 ^= t(b0 ^ b1 ^ b2 ^ xk[31])
	// 反序拼接
	binary.BigEndian.PutUint32(dst[:], b3)
	binary.BigEndian.PutUint32(dst[4:], b2)
	binary.BigEndian.PutUint32(dst[8:], b1)
	binary.BigEndian.PutUint32(dst[12:], b0)
}

// sm4密钥扩展
//  Key expansion algorithm.
func expandKeyGo(key []byte, enc, dec []uint32) {
	// Encryption key setup.
	var i int
	var mk []uint32
	var k [rounds + 4]uint32
	nk := len(key) / 4
	mk = make([]uint32, nk)
	for i = 0; i < nk; i++ {
		mk[i] = binary.BigEndian.Uint32(key[4*i:])
		k[i] = mk[i] ^ fk[i]
	}

	for i = 0; i < rounds; i++ {
		// 合成置换再异或
		k[i+4] = k[i] ^ t2(k[i+1]^k[i+2]^k[i+3]^ck[i])
		enc[i] = k[i+4]
	}

	// Derive decryption key from encryption key.
	if dec == nil {
		return
	}
	for i = 0; i < rounds; i++ {
		dec[i] = enc[rounds-1-i]
	}
}

// sm4块解密
//  外部调用时需保证xk是逆序的轮密钥
//  Decrypt one block from src into dst, using the expanded key xk.
func decryptBlockGo(xk []uint32, dst, src []byte) {
	encryptBlockGo(xk, dst, src)
}

// 轮函数用线性变换函数
//  L(B)
func l(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^ bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

// 密钥扩展用线性变换函数
//  L'(B)
func l2(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

// 合成置换函数
func _t(in uint32, fn convert) uint32 {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], in)
	// 使用s盒映射实现非线性变换
	for i := 0; i < 4; i++ {
		bytes[i] = sbox[bytes[i]]
	}
	// 调用非线性变换函数
	return fn(binary.BigEndian.Uint32(bytes[:]))
}

// 轮函数用合成置换函数
//  T
func t(in uint32) uint32 {
	return _t(in, l)
}

// 密钥扩展用合成置换函数
//  T'
func t2(in uint32) uint32 {
	return _t(in, l2)
}

// 优化的轮函数用合成置换函数
//  5~28轮使用
func precompute_t(in uint32) uint32 {
	return sbox_t0[byte(in>>24)] ^
		sbox_t1[byte(in>>16)] ^
		sbox_t2[byte(in>>8)] ^
		sbox_t3[byte(in)]
}
