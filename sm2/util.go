// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

var zero = big.NewInt(0)

// 将大整数转为字节数组，并根据曲线位数计算出的字节数组长度对左侧补0
func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	// 大整数的字节数组
	bytes := value.Bytes()
	// 需要的长度: (256 + 7) / 8 = 32
	byteLen := (curve.Params().BitSize + 7) >> 3
	if byteLen == len(bytes) {
		return bytes
	}
	// 左侧补0
	result := make([]byte, byteLen)
	copy(result[byteLen-len(bytes):], bytes)
	return result
}

// 将曲线上的点座标(x,y)转为未压缩字节数组
//  参考: GB/T 32918.1-2016 4.2.9
func point2UncompressedBytes(curve elliptic.Curve, x, y *big.Int) []byte {
	return elliptic.Marshal(curve, x, y)
}

// 将曲线上的点座标(x,y)转为压缩字节数组
//  返回的字节数组长度33, 第一位是C1压缩标识, 2代表y是偶数, 3代表y是奇数
//  参考: GB/T 32918.1-2016 4.2.9
func point2CompressedBytes(curve elliptic.Curve, x, y *big.Int) []byte {
	// buffer长度: (曲线位数(256) + 7) / 8 + 1 = 33
	buffer := make([]byte, (curve.Params().BitSize+7)>>3+1)
	// 将x的字节数组填入右侧32个字节
	copy(buffer[1:], toBytes(curve, x))
	// 首位字节是C1压缩标识
	// 因为椭圆曲线取模后的点是沿 y=p/2 这条线对称的，即一个x可能对应着两个y，这两个y关于 p/2 对称，因此 y1 = p - y2。
	// 又因为p是奇素数，所以两个y必然一奇一偶
	if getLastBitOfY(x, y) > 0 {
		// y最右侧一位为1，即奇数，压缩标识为 3
		buffer[0] = compressed03
	} else {
		// y最右侧一位为0，即偶数，压缩标识为 2
		buffer[0] = compressed02
	}
	return buffer
}

// 将曲线上的点座标(x,y)转为混合字节数组
//  参考: GB/T 32918.1-2016 4.2.9
func point2MixedBytes(curve elliptic.Curve, x, y *big.Int) []byte {
	// buffer是未做压缩的序列化字节数组, 长度65, 4 + x字节数组(32个) + y字节数组(32个)
	buffer := elliptic.Marshal(curve, x, y)
	// 修改首位的压缩标识
	// TODO: 混合模式有何意义? C1实际并未压缩，把首位标识改为混合标识有啥用?
	if getLastBitOfY(x, y) > 0 {
		// y最右侧一位为1，即奇数，压缩标识为 7
		buffer[0] = mixed07
	} else {
		// y最右侧一位为0，即偶数，压缩标识为 6
		buffer[0] = mixed06
	}
	return buffer
}

// 获取y最后一位的值
//  x坐标为0时，直接返回0
//  参考: GB/T 32918.1-2016 A.5.2
func getLastBitOfY(x, y *big.Int) uint {
	// x坐标为0时，直接返回0
	if x.Cmp(zero) == 0 {
		return 0
	}
	// 返回y最右侧一位的值
	return y.Bit(0)
}

func toPointXY(bytes []byte) *big.Int {
	return new(big.Int).SetBytes(bytes)
}

// 根据x坐标计算y坐标
//  参考: GB/T 32918.1-2016 A.5.2 B.1.4
func calculatePrimeCurveY(curve elliptic.Curve, x *big.Int) (*big.Int, error) {
	// x3 : x^3
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	// threeX : 3x
	threeX := new(big.Int).Lsh(x, 1) // x*2
	threeX.Add(threeX, x)            // x*2 + x = 3x

	x3.Sub(x3, threeX)           // x^3 - 3x
	x3.Add(x3, curve.Params().B) // x^3 - 3x + b
	x3.Mod(x3, curve.Params().P) // (x^3 - 3x + b) mod p
	// y² ≡ x³ - 3x + b (mod p) 的意思: y^2 和 (x^3 - 3x + b) 同余于p
	// 但是上一步已经对x3做了一次模运算，所以下面的计算实际上是 y² ≡ ((x³ - 3x + b) mod p) (mod p)
	// 两次模运算和一次模运算的结果其实是一样的: 23对10取余是3，3再对10取余还是3，大概用更小的x3可以加快计算速度?
	y := x3.ModSqrt(x3, curve.Params().P)

	if y == nil {
		return nil, errors.New("can't calculate y based on x")
	}
	return y, nil
}

// 字节数组转为曲线上的点坐标
//  返回x,y数值，以及字节数组长度(未压缩/混合:65, 压缩:33)
//  参考: GB/T 32918.1-2016 4.2.10 A.5.2
func bytes2Point(curve elliptic.Curve, bytes []byte) (*big.Int, *big.Int, int, error) {
	if len(bytes) < 1+(curve.Params().BitSize/8) {
		return nil, nil, 0, fmt.Errorf("invalid bytes length %d", len(bytes))
	}
	// 获取压缩标识
	format := bytes[0]
	byteLen := (curve.Params().BitSize + 7) >> 3
	switch format {
	case uncompressed, mixed06, mixed07: // what's the mixed format purpose?
		// 未压缩，或混合模式下，直接将x,y分别取出转换
		if len(bytes) < 1+byteLen*2 {
			return nil, nil, 0, fmt.Errorf("invalid uncompressed bytes length %d", len(bytes))
		}
		x := toPointXY(bytes[1 : 1+byteLen])
		y := toPointXY(bytes[1+byteLen : 1+byteLen*2])
		if !curve.IsOnCurve(x, y) {
			return nil, nil, 0, fmt.Errorf("point c1 is not on curve %s", curve.Params().Name)
		}
		return x, y, 1 + byteLen*2, nil
	case compressed02, compressed03:
		// 压缩模式下
		if len(bytes) < 1+byteLen {
			return nil, nil, 0, fmt.Errorf("invalid compressed bytes length %d", len(bytes))
		}
		if strings.HasPrefix(curve.Params().Name, "P-") || strings.EqualFold(curve.Params().Name, p256.CurveParams.Name) {
			// y² = x³ - 3x + b, prime curves
			x := toPointXY(bytes[1 : 1+byteLen])
			// 根据x推算y数值
			y, err := calculatePrimeCurveY(curve, x)
			if err != nil {
				return nil, nil, 0, err
			}
			// 计算出的y的值与压缩标识冲突的话，则 y = p - y
			// 因为椭圆曲线取模后的点是沿 y=p/2 这条线对称的，即一个x可能对应着两个y，这两个y关于 p/2 对称，因此 y1 = p - y2。
			// 又因为p是奇素数，所以两个y必然一奇一偶
			if (getLastBitOfY(x, y) > 0 && format == compressed02) || (getLastBitOfY(x, y) == 0 && format == compressed03) {
				y.Sub(curve.Params().P, y)
			}
			return x, y, 1 + byteLen, nil
		}
		return nil, nil, 0, fmt.Errorf("unsupport bytes format %d, curve %s", format, curve.Params().Name)
	}
	return nil, nil, 0, fmt.Errorf("unknown bytes format %d", format)
}

var (
	closedChanOnce sync.Once
	closedChan     chan struct{}
)

// maybeReadByte reads a single byte from r with ~50% probability. This is used
// to ensure that callers do not depend on non-guaranteed behaviour, e.g.
// assuming that rsa.GenerateKey is deterministic w.r.t. a given random stream.
//
// This does not affect tests that pass a stream of fixed bytes as the random
// source (e.g. a zeroReader).
func maybeReadByte(r io.Reader) {
	closedChanOnce.Do(func() {
		closedChan = make(chan struct{})
		close(closedChan)
	})

	select {
	case <-closedChan:
		return
	case <-closedChan:
		var buf [1]byte
		r.Read(buf[:])
	}
}

func ConvertSM2Priv2ECPriv(sm2Priv *PrivateKey) (*ecdsa.PrivateKey, error) {
	ecPriv := &ecdsa.PrivateKey{}
	ecPriv.Curve = sm2Priv.Curve
	ecPriv.D = sm2Priv.D
	ecPriv.X = sm2Priv.X
	ecPriv.Y = sm2Priv.Y
	return ecPriv, nil
}

func ConvertECPriv2SM2Priv(ecPriv *ecdsa.PrivateKey) (*PrivateKey, error) {
	sm2Priv := &PrivateKey{}
	sm2Priv.Curve = ecPriv.Curve
	if sm2Priv.Curve != P256Sm2() {
		return nil, errors.New("sm2.ConvertECPriv2SM2Priv: 源私钥并未使用SM2曲线,无法转换")
	}
	sm2Priv.D = ecPriv.D
	sm2Priv.X = ecPriv.X
	sm2Priv.Y = ecPriv.Y
	return sm2Priv, nil
}
