// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//go:build amd64 || arm64
// +build amd64 arm64

package sm4

import (
	"crypto/cipher"
	goSubtle "crypto/subtle"

	"gitee.com/zhaochuninhefei/gmgo/internal/subtle"
)

// sm4CipherGCM implements crypto/cipher.gcmAble so that crypto/cipher.NewGCM
// will use the optimised implementation in this file when possible. Instances
// of this type only exist when hasGCMAsm returns true.
type sm4CipherGCM struct {
	sm4CipherAsm
}

// Assert that sm4CipherGCM implements the gcmAble interface.
var _ gcmAble = (*sm4CipherGCM)(nil)

//go:noescape
func gcmSm4Init(productTable *[256]byte, rk []uint32)

//go:noescape
func gcmSm4Enc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)

//go:noescape
func gcmSm4Dec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)

//go:noescape
func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)

//go:noescape
func gcmSm4Finish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)

type gcmAsm struct {
	gcm
	bytesProductTable [256]byte
}

// NewGCM returns the SM4 cipher wrapped in Galois Counter Mode. This is only
// called by crypto/cipher.NewGCM via the gcmAble interface.
func (c *sm4CipherGCM) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	// fmt.Println("sm4.NewGCM in sm4/sm4_gcm_asm.go")
	g := &gcmAsm{}
	g.cipher = &c.sm4CipherAsm
	g.nonceSize = nonceSize
	g.tagSize = tagSize
	gcmSm4Init(&g.bytesProductTable, g.cipher.enc)
	return g, nil
}

func (g *gcmAsm) NonceSize() int {
	return g.nonceSize
}

func (g *gcmAsm) Overhead() int {
	return g.tagSize
}

// Seal encrypts and authenticates plaintext. See the cipher.AEAD interface for
// details.
func (g *gcmAsm) Seal(dst, nonce, plaintext, data []byte) []byte {
	// fmt.Println("sm4.Seal in sm4/sm4_gcm_asm.go")
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*BlockSize {
		panic("cipher: message too large for GCM")
	}

	var counter, tagMask [gcmBlockSize]byte

	if len(nonce) == gcmStandardNonceSize {
		// Init counter to nonce||1
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		// Otherwise counter = GHASH(nonce)
		gcmSm4Data(&g.bytesProductTable, nonce, &counter)
		gcmSm4Finish(&g.bytesProductTable, &tagMask, &counter, uint64(len(nonce)), uint64(0))
	}

	g.cipher.Encrypt(tagMask[:], counter[:])

	var tagOut [gcmTagSize]byte
	gcmSm4Data(&g.bytesProductTable, data, &tagOut)

	ret, out := subtle.SliceForAppend(dst, len(plaintext)+g.tagSize)
	if subtle.InexactOverlap(out[:len(plaintext)], plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	if len(plaintext) > 0 {
		gcmSm4Enc(&g.bytesProductTable, out, plaintext, &counter, &tagOut, g.cipher.enc)
	}
	gcmSm4Finish(&g.bytesProductTable, &tagMask, &tagOut, uint64(len(plaintext)), uint64(len(data)))
	copy(out[len(plaintext):], tagOut[:])

	return ret
}

// Open authenticates and decrypts ciphertext. See the cipher.AEAD interface
// for details.
func (g *gcmAsm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	// fmt.Println("sm4.Open in sm4/sm4_gcm_asm.go")
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	// Sanity check to prevent the authentication from always succeeding if an implementation
	// leaves tagSize uninitialized, for example.
	if g.tagSize < gcmMinimumTagSize {
		panic("cipher: incorrect GCM tag size")
	}

	if len(ciphertext) < g.tagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(BlockSize)+uint64(g.tagSize) {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-g.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-g.tagSize]

	// See GCM spec, section 7.1.
	var counter, tagMask [gcmBlockSize]byte

	if len(nonce) == gcmStandardNonceSize {
		// Init counter to nonce||1
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		// Otherwise counter = GHASH(nonce)
		gcmSm4Data(&g.bytesProductTable, nonce, &counter)
		gcmSm4Finish(&g.bytesProductTable, &tagMask, &counter, uint64(len(nonce)), uint64(0))
	}

	g.cipher.Encrypt(tagMask[:], counter[:])

	var expectedTag [gcmTagSize]byte
	gcmSm4Data(&g.bytesProductTable, data, &expectedTag)

	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}
	if len(ciphertext) > 0 {
		gcmSm4Dec(&g.bytesProductTable, out, ciphertext, &counter, &expectedTag, g.cipher.enc)
	}
	gcmSm4Finish(&g.bytesProductTable, &tagMask, &expectedTag, uint64(len(ciphertext)), uint64(len(data)))

	if goSubtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}
