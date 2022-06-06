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
// of this type only exist when hasGCMAsm and hasAES returns true.
type sm4CipherGCM struct {
	*sm4CipherAsm
}

// Assert that sm4CipherGCM implements the gcmAble interface.
var _ gcmAble = (*sm4CipherGCM)(nil)

//go:noescape
func gcmSm4Init(productTable *[256]byte, rk []uint32, inst int)

//go:noescape
func gcmSm4Enc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)

//go:noescape
func gcmSm4Dec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32)

//go:noescape
func gcmSm4Data(productTable *[256]byte, data []byte, T *[16]byte)

//go:noescape
func gcmSm4Finish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)

// gcmSm4InitInst is used for test
func gcmSm4InitInst(productTable *[256]byte, rk []uint32) {
	if supportSM4 {
		gcmSm4Init(productTable, rk, INST_SM4)
	} else {
		gcmSm4Init(productTable, rk, INST_AES)
	}
}

// gcmSm4EncInst is used for test
func gcmSm4EncInst(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32) {
	if supportSM4 {
		gcmSm4niEnc(productTable, dst, src, ctr, T, rk)
	} else {
		gcmSm4Enc(productTable, dst, src, ctr, T, rk)
	}
}

// gcmSm4DecInst is used for test
func gcmSm4DecInst(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, rk []uint32) {
	if supportSM4 {
		gcmSm4niDec(productTable, dst, src, ctr, T, rk)
	} else {
		gcmSm4Dec(productTable, dst, src, ctr, T, rk)
	}
}

type gcmAsm struct {
	gcm
	bytesProductTable [256]byte
}

// NewGCM returns the SM4 cipher wrapped in Galois Counter Mode. This is only
// called by crypto/cipher.NewGCM via the gcmAble interface.
func (c *sm4CipherGCM) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	// zclog.Debug("sm4.NewGCM in sm4/sm4_gcm_asm.go")
	g := &gcmAsm{}
	g.cipher = c.sm4CipherAsm
	g.nonceSize = nonceSize
	g.tagSize = tagSize
	gcmSm4Init(&g.bytesProductTable, g.cipher.enc, INST_AES)
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
	// zclog.Debug("sm4.Seal in sm4/sm4_gcm_asm.go")
	// zclog.Debugf("dst: %v, nonce: %v, plaintext: %v, data: %v", dst, nonce, plaintext, data)
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
	// zclog.Debugf("tagOut 1 : %v", tagOut)
	ret, out := subtle.SliceForAppend(dst, len(plaintext)+g.tagSize)
	if subtle.InexactOverlap(out[:len(plaintext)], plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	if len(plaintext) > 0 {
		gcmSm4Enc(&g.bytesProductTable, out, plaintext, &counter, &tagOut, g.cipher.enc)
		// zclog.Debugf("tagOut 2 : %v", tagOut)
	}
	gcmSm4Finish(&g.bytesProductTable, &tagMask, &tagOut, uint64(len(plaintext)), uint64(len(data)))
	// zclog.Debugf("tagOut 3 : %v", tagOut)
	copy(out[len(plaintext):], tagOut[:])
	// zclog.Debugf("ret: %v", ret)
	return ret
}

// Open authenticates and decrypts ciphertext. See the cipher.AEAD interface
// for details.
func (g *gcmAsm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	// zclog.Debug("sm4.Open in sm4/sm4_gcm_asm.go")
	// zclog.Debugf("dst: %v, nonce: %v, ciphertext: %v, data: %v", dst, nonce, ciphertext, data)
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
	// zclog.Debugf("expectedTag 1 : %v", expectedTag)
	// 目前gcmSm4Dec函数的入参dst与src在内存上必须各自独立，因此这里不能直接调用`subtle.SliceForAppend`函数，而是强制另外申请内存来生成ret和out两个切片。
	ret, out := subtle.SliceForAppend(dst, len(ciphertext))
	// total := len(dst) + len(ciphertext)
	// ret := make([]byte, total)
	// copy(ret, dst)
	// out := ret[len(dst):]
	if subtle.InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}
	if len(ciphertext) > 0 {
		// zclog.Debugf("ProductTable: %v, out: %v, ciphertext: %v, counter: %v, expectedTag: %v, g.cipher.enc: %v", g.bytesProductTable, out, ciphertext, &counter, expectedTag, g.cipher.enc)
		gcmSm4Dec(&g.bytesProductTable, out, ciphertext, &counter, &expectedTag, g.cipher.enc)
		// zclog.Debugf("expectedTag 2 : %v", expectedTag)
	}
	gcmSm4Finish(&g.bytesProductTable, &tagMask, &expectedTag, uint64(len(ciphertext)), uint64(len(data)))
	// zclog.Debugf("expectedTag 3 : %v", expectedTag)
	// zclog.Debugf("ret: %v", ret)
	if goSubtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}
