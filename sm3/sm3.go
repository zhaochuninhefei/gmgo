// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm3

/*
sm3/sm3.go SM3实现
[GM/T] SM3 GB/T 32905-2016
*/

import (
	"encoding/binary"
	"errors"
	"hash"
)

// SM3校验和字节数，即散列结果的字节长度
const Size int = 32

// SM3散列块字节数
const BlockSize int = 64

// 编译运行本模块代码的平台的CPU架构
var cpuType string = "unknown"

const (
	chunk = 64
	init0 = 0x7380166f
	init1 = 0x4914b2b9
	init2 = 0x172442d7
	init3 = 0xda8a0600
	init4 = 0xa96f30bc
	init5 = 0x163138aa
	init6 = 0xe38dee4d
	init7 = 0xb0fb0e4e
)

// 摘要digest结构体，是对校验和的部分描述
type digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

const (
	magic256      = "sm3\x03"
	marshaledSize = len(magic256) + 8*4 + chunk + 8
)

// 将摘要digest序列化为字节数组
func (d *digest) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSize)
	b = append(b, magic256...)
	b = appendUint32(b, d.h[0])
	b = appendUint32(b, d.h[1])
	b = appendUint32(b, d.h[2])
	b = appendUint32(b, d.h[3])
	b = appendUint32(b, d.h[4])
	b = appendUint32(b, d.h[5])
	b = appendUint32(b, d.h[6])
	b = appendUint32(b, d.h[7])
	b = append(b, d.x[:d.nx]...)
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	b = appendUint64(b, d.len)
	return b, nil
}

// 将字节数组反序列化为摘要digest
func (d *digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic256) || (string(b[:len(magic256)]) != magic256) {
		return errors.New("sm3: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("sm3: invalid hash state size")
	}
	b = b[len(magic256):]
	b, d.h[0] = consumeUint32(b)
	b, d.h[1] = consumeUint32(b)
	b, d.h[2] = consumeUint32(b)
	b, d.h[3] = consumeUint32(b)
	b, d.h[4] = consumeUint32(b)
	b, d.h[5] = consumeUint32(b)
	b, d.h[6] = consumeUint32(b)
	b, d.h[7] = consumeUint32(b)
	b = b[copy(d.x[:], b):]
	_, d.len = consumeUint64(b)
	d.nx = int(d.len % chunk)
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

// New生成一个新的hash.Hash，用来计算SM3校验和。
// New returns a new hash.Hash computing the SM3 checksum. The Hash
// also implements encoding.BinaryMarshaler and
// encoding.BinaryUnmarshaler to marshal and unmarshal the internal
// state of the hash.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Sum 将当前哈希附加到 b 并返回结果切片。
// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() []byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}
	// Length in bits.
	len <<= 3
	binary.BigEndian.PutUint64(tmp[:], len)
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])

	return digest[:]
}

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int { return BlockSize }

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

// Sm3Sum returns the SM3 checksum of the data.
func Sm3Sum(data []byte) []byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

func Sm3SumArr(data []byte) (sum_sm3 [Size]byte) {
	sum := Sm3Sum(data)
	copy(sum_sm3[:], sum[:Size])
	return
}
