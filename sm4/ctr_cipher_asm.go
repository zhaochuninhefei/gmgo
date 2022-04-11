// Copyright (c) 2022 zhaochun
// gmingo is licensed under Mulan PSL v2.
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

	"gitee.com/zhaochuninhefei/gmgo/internal/subtle"
	"gitee.com/zhaochuninhefei/gmgo/internal/xor"
)

// Assert that sm4CipherAsm implements the ctrAble interface.
var _ ctrAble = (*sm4CipherAsm)(nil)

type ctr struct {
	b       *sm4CipherAsm
	ctr     []byte
	out     []byte
	outUsed int
}

const streamBufferSize = 512

// NewCTR returns a Stream which encrypts/decrypts using the SM4 block
// cipher in counter mode. The length of iv must be the same as BlockSize.
func (c *sm4CipherAsm) NewCTR(iv []byte) cipher.Stream {
	if len(iv) != BlockSize {
		panic("cipher.NewCTR: IV length must equal block size")
	}
	bufSize := streamBufferSize
	if bufSize < BlockSize {
		bufSize = BlockSize
	}
	s := &ctr{
		b:       c,
		ctr:     make([]byte, c.batchBlocks*len(iv)),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}
	copy(s.ctr, iv)
	for i := 1; i < c.batchBlocks; i++ {
		s.genCtr(i * BlockSize)
	}
	return s

}

func (x *ctr) genCtr(start int) {
	if start > 0 {
		copy(x.ctr[start:], x.ctr[start-BlockSize:start])
	} else {
		copy(x.ctr[start:], x.ctr[len(x.ctr)-BlockSize:])
	}
	// Increment counter
	end := start + BlockSize
	for i := end - 1; i >= 0; i-- {
		x.ctr[i]++
		if x.ctr[i] != 0 {
			break
		}
	}
}

func (x *ctr) refill() {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)]
	for remain <= len(x.out)-x.b.blocksSize {
		x.b.EncryptBlocks(x.out[remain:], x.ctr)
		remain += x.b.blocksSize

		// Increment counter
		for i := 0; i < x.b.batchBlocks; i++ {
			x.genCtr(i * BlockSize)
		}
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

func (x *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if subtle.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-BlockSize {
			x.refill()
		}
		n := xor.XorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}
