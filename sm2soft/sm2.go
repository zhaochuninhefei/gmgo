// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/*
sm2soft 是sm2的纯软实现，基于tjfoc国密算法库`tjfoc/gmsm`做了少量修改。
对应版权声明: thrid_licenses/github.com/tjfoc/gmsm/版权声明
*/

package sm2soft

// reference to ecdsa
import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"gitee.com/zhaochuninhefei/gmgo/sm3"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	defaultUid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
	C1C3C2     = 0
	C1C2C3     = 1
)

// PublicKey SM2公钥结构体
type PublicKey struct {
	elliptic.Curve          // 椭圆曲线
	X, Y           *big.Int // 公钥座标
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.X.Cmp(xx.X) == 0 && pub.Y.Cmp(xx.Y) == 0 &&
		// Standard library Curve implementations are singletons, so this check
		// will work for those. Other Curves might be equivalent even if not
		// singletons, but there is no definitive way to check for that, and
		// better to err on the side of safety.
		pub.Curve == xx.Curve
}

// PrivateKey SM2私钥结构体
type PrivateKey struct {
	PublicKey          // 公钥
	D         *big.Int // 私钥，[1,n-1]区间的随机数
}

type sm2Cipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

// Public The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && priv.D.Cmp(xx.D) == 0
}

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s

// Sign 使用priv私钥对签名内容摘要做SM2签名，参数signer目前没有使用，但仍要求传入外部对明文消息做摘要的散列算法。
// 返回的签名为DER字节数组，对(r,s)做了asn1编码。
//   - random : 随机数获取用, 如 rand.Reader
//   - signContentDigest : 签名内容摘要(散列值)
//   - signer : 外部对签名内容进行摘要计算使用的散列函数
//
//goland:noinspection GoUnusedParameter
func (priv *PrivateKey) Sign(random io.Reader, signContentDigest []byte, signer crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sm2Sign(priv, signContentDigest, nil, random)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

// SignASN1 使用私钥priv对一个hash值进行签名。
// 返回的签名为DER字节数组，对(r,s)做了asn1编码。
//
//goland:noinspection GoUnusedExportedFunction
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
	return priv.Sign(rand, hash, nil)
}

// Verify 使用pub公钥对签名sig做验签。
//   - signContentDigest : 签名内容摘要(散列值)
//   - sig : 签名DER字节数组(对(r,s)做了asn1编码，因此会先做asn1解码)
func (pub *PublicKey) Verify(signContentDigest []byte, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return Sm2Verify(pub, signContentDigest, defaultUid, r, s)
}

// VerifyASN1 使用公钥pub对hash和sig进行验签。
//   - pub 公钥
//   - hash 签名内容摘要(散列值)
//   - sig 签名DER字节数组(对(r,s)做了asn1编码，因此会先做asn1解码)
//
//goland:noinspection GoUnusedExportedFunction
func VerifyASN1(pub *PublicKey, hash, sig []byte) bool {
	return pub.Verify(hash, sig)
}

// Sm3Digest 对签名内容进行SM3摘要计算，摘要计算前混入sm2椭圆曲线部分参数与公钥并预散列一次。
func (pub *PublicKey) Sm3Digest(msg, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUid
	}

	za, err := ZA(pub, uid)
	if err != nil {
		return nil, err
	}

	e, err := msgHash(za, msg)
	if err != nil {
		return nil, err
	}

	return e.Bytes(), nil
}

//****************************Encryption algorithm****************************//

// EncryptAsn1 sm2加密，C1C3C2，asn1编码
func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

// DecryptAsn1 sm2解密，C1C3C2，asn1解码
func (priv *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(priv, data)
}

//**************************Key agreement algorithm**************************//

// KeyExchangeB 协商第二部，用户B调用， 返回共享密钥k
func KeyExchangeB(klen int, ida, idb []byte, priB *PrivateKey, pubA *PublicKey, rpri *PrivateKey, rpubA *PublicKey) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priB, pubA, rpri, rpubA, false)
}

// KeyExchangeA 协商第二部，用户A调用，返回共享密钥k
func KeyExchangeA(klen int, ida, idb []byte, priA *PrivateKey, pubB *PublicKey, rpri *PrivateKey, rpubB *PublicKey) (k, s1, s2 []byte, err error) {
	return keyExchange(klen, ida, idb, priA, pubB, rpri, rpubB, true)
}

//****************************************************************************//

// Sm2Sign SM2签名
//   - priv : 签名私钥 *sm2.PrivateKey
//   - signContentDigest : 签名内容摘要(散列值)
//   - uid : 内部混合摘要计算用uid, 长度16的字节数组，可以传 nil
//   - random : 随机数获取用
func Sm2Sign(priv *PrivateKey, signContentDigest, uid []byte, random io.Reader) (r, s *big.Int, err error) {
	// 对签名内容进行摘要计算
	digest, err := priv.PublicKey.Sm3Digest(signContentDigest, uid)
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	// SM2签名实现
	for {
		for {
			// 生成随机数k
			k, err = randFieldElement(c, random)
			if err != nil {
				r = nil
				return
			}
			// 计算P = k*G，返回值的x赋予了r
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			// 计算 r = (e + P(x)) mod n
			// e + P(x)
			r.Add(r, e)
			// (e + P(x)) mod n
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		// 计算 s = (((1 + d)^-1) (k-rd)) mod n
		// rd
		rD := new(big.Int).Mul(priv.D, r)
		// k - rd
		s = new(big.Int).Sub(k, rD)
		// 1 + d
		d1 := new(big.Int).Add(priv.D, one)
		// (1 + d)^-1
		d1Inv := new(big.Int).ModInverse(d1, N)
		// ((1 + d)^-1) × (k-rd)
		s.Mul(s, d1Inv)
		// (((1 + d)^-1) (k-rd)) mod n
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}

// Sm2Verify SM2验签
//   - pub : 验签公钥, *sm2.PublicKey
//   - signContentDigest : 签名内容摘要(散列值)
//   - uid : 内部混合摘要计算用uid, 长度16的字节数组，可以传 nil
//   - r, s : 签名
func Sm2Verify(pub *PublicKey, signContentDigest, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = defaultUid
	}
	// 获取za: sm3(ENTLA || IDA || a || b || xG || yG || xA || yA)
	za, err := ZA(pub, uid)
	if err != nil {
		return false
	}
	// 混合za与签名内容明文，并做sm3摘要
	e, err := msgHash(za, signContentDigest)
	if err != nil {
		return false
	}
	// 计算 t = (r + s) mod n
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}
	var x *big.Int
	// 计算 s*G
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	// 计算 t*pub
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	// 计算 s*G + t*pub 结果只要x轴座标
	x, _ = c.Add(x1, y1, x2, y2)
	// 计算 e + x
	x.Add(x, e)
	// 计算 R = (e + x) mod n
	x.Mod(x, N)
	// 判断 R == r
	return x.Cmp(r) == 0
}

// Verify SM2验签
//   - pub : 验签公钥, *sm2.PublicKey
//   - hash : 签名内容摘要(散列值)
//   - r, s : 签名
//
//goland:noinspection GoUnusedExportedFunction
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	return Sm2Verify(pub, hash, nil, r, s)
}

/*
    za, err := ZA(pub, uid)
	if err != nil {
		return
	}
	e, err := msgHash(za, msg)
	hash=e.getBytes()
*/
// 并非sm2验签
// func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
// 	c := pub.Curve
// 	N := c.Params().N

// 	if r.Sign() <= 0 || s.Sign() <= 0 {
// 		return false
// 	}
// 	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
// 		return false
// 	}

// 	// 调整算法细节以实现SM2
// 	t := new(big.Int).Add(r, s)
// 	t.Mod(t, N)
// 	if t.Sign() == 0 {
// 		return false
// 	}

// 	var x *big.Int
// 	x1, y1 := c.ScalarBaseMult(s.Bytes())
// 	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
// 	x, _ = c.Add(x1, y1, x2, y2)

// 	e := new(big.Int).SetBytes(hash)
// 	x.Add(x, e)
// 	x.Mod(x, N)
// 	return x.Cmp(r) == 0
// }

// Encrypt sm2非对称加密，支持C1C3C2(mode = 0)与C1C2C3(mode = 1)两种模式，默认使用C1C3C2模式。
// 不同的模式表示不同的密文结构，其中C1C2C3的意义：
// C1 : sm2椭圆曲线上的某个点，每次加密得到的点不一样
// C2 : 密文
// C3 : 明文加盐后的摘要
func Encrypt(pub *PublicKey, data []byte, random io.Reader, mode int) ([]byte, error) {
	length := len(data)
	for {
		var c []byte
		curve := pub.Curve
		// 获取随机数k
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}
		// 计算点C1 = k*G ，因为k是随机数，所以C1每次加密都是随机的
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		// 计算点(x2,y2) = k*pub，利用公钥计算出一个随机的点P
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		// 填充满32个字节长度
		if n := len(x1Buf); n < 32 {
			x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
		}
		if n := len(y1Buf); n < 32 {
			y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
		}
		if n := len(x2Buf); n < 32 {
			x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
		}
		if n := len(y2Buf); n < 32 {
			y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
		}
		// 填入C1(x)
		c = append(c, x1Buf...)
		// 填入C1(y)
		c = append(c, y1Buf...)

		// 计算C3 : 按 x2 data y2 的顺序混合数据并做sm3摘要
		var tm []byte
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)
		h := sm3.Sm3Sum(tm)
		// 填入C3
		c = append(c, h...)

		// 使用密钥派生函数kdf，基于P计算长度等于data长度的派生密钥 ct
		ct, ok := kdf(length, x2Buf, y2Buf)
		if !ok {
			continue
		}
		// 填入ct
		c = append(c, ct...)
		// 利用ct对data进行异或加密，并覆盖c中对应内容
		for i := 0; i < length; i++ {
			c[96+i] ^= data[i]
		}

		// 此时c的内容是 c1c3c2，需要根据传入的参数mode判断是否需要重新排列。
		switch mode {
		case C1C3C2:
			return append([]byte{0x04}, c...), nil
		case C1C2C3:
			// 如果是 C1C2C3 模式，那么需要将c切分后重新组装
			c1 := make([]byte, 64)
			c2 := make([]byte, len(c)-96)
			c3 := make([]byte, 32)
			// C1，即 x1Buf+y1Buf
			copy(c1, c[:64])
			// C3，即 x2+data+y2混合后的SM3摘要
			copy(c3, c[64:96])
			// C2，即 使用kdf派生出的密钥对data进行加密后的密文
			copy(c2, c[96:])
			// 按C1C2C3的顺序组装结果
			var ciphertext []byte
			ciphertext = append(ciphertext, c1...)
			ciphertext = append(ciphertext, c2...)
			ciphertext = append(ciphertext, c3...)
			return append([]byte{0x04}, ciphertext...), nil
		default:
			return append([]byte{0x04}, c...), nil
		}
	}
}

// Decrypt sm2非对称解密
func Decrypt(priv *PrivateKey, data []byte, mode int) ([]byte, error) {
	switch mode {
	case C1C3C2:
		data = data[1:]
	case C1C2C3:
		// C1C2C3重新组装为 C1C3C2
		data = data[1:]
		c1 := make([]byte, 64)
		c2 := make([]byte, len(data)-96)
		c3 := make([]byte, 32)
		copy(c1, data[:64])             //x1,y1
		copy(c2, data[64:len(data)-32]) //密文
		copy(c3, data[len(data)-32:])   //hash
		var c []byte
		c = append(c, c1...)
		c = append(c, c3...)
		c = append(c, c2...)
		data = c
	default:
		data = data[1:]
	}
	length := len(data) - 96
	curve := priv.Curve
	// 取出C1的x和y
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	// 根据C1计算 P = d*C1
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 32 {
		x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
	}
	if n := len(y2Buf); n < 32 {
		y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
	}
	// 使用密钥派生函数kdf，基于P计算派生密钥 c
	c, ok := kdf(length, x2Buf, y2Buf)
	if !ok {
		return nil, errors.New("decrypt: failed to decrypt")
	}
	// 使用派生密钥c对C2部分做异或计算解密
	// 解密结果覆盖到c中，此时c即明文
	for i := 0; i < length; i++ {
		c[i] ^= data[i+96]
	}
	// 重新混合明文并计算摘要，与C3进行比较
	var tm []byte
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)
	h := sm3.Sm3Sum(tm)
	if !bytes.Equal(h, data[64:96]) {
		return c, errors.New("decrypt: failed to decrypt")
	}
	return c, nil
}

// keyExchange 为SM2密钥交换算法的第二部和第三步复用部分，协商的双方均调用此函数计算共同的字节串
// klen: 密钥长度
// ida, idb: 协商双方的标识，ida为密钥协商算法发起方标识，idb为响应方标识
// pri: 函数调用者的密钥
// pub: 对方的公钥
// rpri: 函数调用者生成的临时SM2密钥
// rpub: 对方发来的临时SM2公钥
// thisIsA: 如果是A调用，文档中的协商第三步，设置为true，否则设置为false
// 返回 k 为klen长度的字节串
func keyExchange(klen int, ida, idb []byte, pri *PrivateKey, pub *PublicKey, rpri *PrivateKey, rpub *PublicKey, thisISA bool) (k, s1, s2 []byte, err error) {
	curve := P256Sm2()
	N := curve.Params().N
	x2hat := keXHat(rpri.PublicKey.X)
	x2rb := new(big.Int).Mul(x2hat, rpri.D)
	tbt := new(big.Int).Add(pri.D, x2rb)
	tb := new(big.Int).Mod(tbt, N)
	if !curve.IsOnCurve(rpub.X, rpub.Y) {
		err = errors.New("ra not on curve")
		return
	}
	x1hat := keXHat(rpub.X)
	ramx1, ramy1 := curve.ScalarMult(rpub.X, rpub.Y, x1hat.Bytes())
	vxt, vyt := curve.Add(pub.X, pub.Y, ramx1, ramy1)

	vx, vy := curve.ScalarMult(vxt, vyt, tb.Bytes())
	pza := pub
	if thisISA {
		pza = &pri.PublicKey
	}
	za, err := ZA(pza, ida)
	if err != nil {
		return
	}
	zero := new(big.Int)
	if vx.Cmp(zero) == 0 || vy.Cmp(zero) == 0 {
		err = errors.New("v is infinite")
		return
	}
	pzb := pub
	if !thisISA {
		pzb = &pri.PublicKey
	}
	zb, _ := ZA(pzb, idb)
	k, ok := kdf(klen, vx.Bytes(), vy.Bytes(), za, zb)
	if !ok {
		err = errors.New("kdf: zero key")
		return
	}
	h1 := BytesCombine(vx.Bytes(), za, zb, rpub.X.Bytes(), rpub.Y.Bytes(), rpri.X.Bytes(), rpri.Y.Bytes())
	if !thisISA {
		h1 = BytesCombine(vx.Bytes(), za, zb, rpri.X.Bytes(), rpri.Y.Bytes(), rpub.X.Bytes(), rpub.Y.Bytes())
	}
	hash := sm3.Sm3Sum(h1)
	h2 := BytesCombine([]byte{0x02}, vy.Bytes(), hash)
	S1 := sm3.Sm3Sum(h2)
	h3 := BytesCombine([]byte{0x03}, vy.Bytes(), hash)
	S2 := sm3.Sm3Sum(h3)
	return k, S1, S2, nil
}

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	uidLen := len(uid)
	if uidLen >= 8192 {
		return []byte{}, errors.New("SM2: uid too large")
	}
	Entla := uint16(8 * uidLen)
	za.Write([]byte{byte((Entla >> 8) & 0xFF)})
	za.Write([]byte{byte(Entla & 0xFF)})
	if uidLen > 0 {
		za.Write(uid)
	}
	za.Write(sm2P256ToBig(&sm2P256.a).Bytes())
	za.Write(sm2P256.B.Bytes())
	za.Write(sm2P256.Gx.Bytes())
	za.Write(sm2P256.Gy.Bytes())

	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()
	if n := len(xBuf); n < 32 {
		xBuf = append(zeroByteSlice()[:32-n], xBuf...)
	}
	if n := len(yBuf); n < 32 {
		yBuf = append(zeroByteSlice()[:32-n], yBuf...)
	}
	za.Write(xBuf)
	za.Write(yBuf)
	return za.Sum(nil)[:32], nil
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

// EncryptAsn1 sm2加密，返回asn.1编码格式的密文内容
func EncryptAsn1(pub *PublicKey, data []byte, rand io.Reader) ([]byte, error) {
	cipher, err := Encrypt(pub, data, rand, C1C3C2)
	if err != nil {
		return nil, err
	}
	return CipherMarshal(cipher)
}

// DecryptAsn1 sm2解密，解析asn.1编码格式的密文内容
func DecryptAsn1(pub *PrivateKey, data []byte) ([]byte, error) {
	cipher, err := CipherUnmarshal(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(pub, cipher, C1C3C2)
}

// CipherMarshal sm2密文转asn.1编码格式
//
//	sm2密文结构如下:
//	- x
//	- y
//	- hash
//	- CipherText
func CipherMarshal(data []byte) ([]byte, error) {
	data = data[1:]
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	hash := data[64:96]
	cipherText := data[96:]
	return asn1.Marshal(sm2Cipher{x, y, hash, cipherText})
}

// CipherUnmarshal sm2密文asn.1编码格式转C1|C3|C2拼接格式
func CipherUnmarshal(data []byte) ([]byte, error) {
	var cipher sm2Cipher
	_, err := asn1.Unmarshal(data, &cipher)
	if err != nil {
		return nil, err
	}
	x := cipher.XCoordinate.Bytes()
	y := cipher.YCoordinate.Bytes()
	hash := cipher.HASH
	//if err != nil {
	//	return nil, err
	//}
	cipherText := cipher.CipherText
	//if err != nil {
	//	return nil, err
	//}
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	var c []byte
	c = append(c, x...)          // x分量
	c = append(c, y...)          // y分
	c = append(c, hash...)       // x分量
	c = append(c, cipherText...) // y分
	return append([]byte{0x04}, c...), nil
}

// keXHat 计算 x = 2^w + (x & (2^w-1))
// 密钥协商算法辅助函数
func keXHat(x *big.Int) (xul *big.Int) {
	buf := x.Bytes()
	for i := 0; i < len(buf)-16; i++ {
		buf[i] = 0
	}
	if len(buf) >= 16 {
		c := buf[len(buf)-16]
		buf[len(buf)-16] = c & 0x7f
	}

	r := new(big.Int).SetBytes(buf)
	_2w := new(big.Int).SetBytes([]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return r.Add(r, _2w)
}

func BytesCombine(pBytes ...[]byte) []byte {
	length := len(pBytes)
	s := make([][]byte, length)
	for index := 0; index < length; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

// 选取一个位于[1~n-1]之间的随机数k，n是椭圆曲线的参数N
func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey 基于P256Sm2曲线生成sm2的公私钥
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}
	// 生成随机数k
	k := new(big.Int).SetBytes(b)
	// n = N - 2
	n := new(big.Int).Sub(params.N, two)
	// k = k mod n
	k.Mod(k, n)
	// k = k + 1
	k.Add(k, one)
	priv := new(PrivateKey)
	// 设置曲线
	priv.PublicKey.Curve = c
	// 设置私钥
	priv.D = k
	// 公钥 = k * G
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

	return priv, nil
}

// ecdsa的实现中，使用zeroReader辅助生成一个cipher.StreamReader用作随机数生成的 rand io.Reader。
// sm2目前没有采用这种方式，所以这里将相关代码注释掉了。

// type zr struct {
// 	io.Reader
// }

// func (z *zr) Read(dst []byte) (n int, err error) {
// 	for i := range dst {
// 		dst[i] = 0
// 	}
// 	return len(dst), nil
// }

// var zeroReader = &zr{}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}

// Decrypt crypto.Decrypter
func (priv *PrivateKey) Decrypt(_ io.Reader, msg []byte, _ crypto.DecrypterOpts) (plaintext []byte, err error) {
	return Decrypt(priv, msg, C1C3C2)
}
