// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm2

/*
sm2/sm2.go sm2国密算法实现,包括签名验签与非对称加解密

为*sm2.PrivateKey绑定方法:
Public
Equal
SignWithZA
Sign
DecryptAsn1
Decrypt

为*sm2.PublicKey绑定方法:
Equal
Verify
EncryptAsn1
Encrypt

提供函数:
P256Sm2
GenerateKey
IsSM2PublicKey
NewSM2SignerOption
DefaultSM2SignerOption
SignASN1WithOpts
SignASN1
Sign
Sm2Sign
SignWithZA
SignAfterZA
VerifyASN1
VerifyASN1WithoutZA
Verify
Sm2Verify
VerifyWithZA
CalculateZA
Encrypt
Decrypt
EncryptDefault
EncryptAsn1
DecryptDefault
DecryptAsn1
ASN1Ciphertext2Plain
PlainCiphertext2ASN1
AdjustCiphertextSplicingOrder
NewPlainEncrypterOpts
NewPlainDecrypterOpts

*/

// Further references:
//   [NSA]: Suite B implementer's guide to FIPS 186-3
//     http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.182.4503&rep=rep1&type=pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf
//   [GM/T]: SM2 GB/T 32918.2-2016, GB/T 32918.4-2016
//

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"gitee.com/zhaochuninhefei/gmgo/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// SM2公钥结构体
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

// SM2私钥结构体
type PrivateKey struct {
	PublicKey          // 公钥
	D         *big.Int // 私钥，[1,n-1]区间的随机数
}

// The SM2's private key contains the public key
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

var (
	one      = new(big.Int).SetInt64(1)
	initonce sync.Once
)

// 获取sm2p256曲线
// P256Sm2 init and return the singleton.
func P256Sm2() elliptic.Curve {
	initonce.Do(initP256)
	return p256
}

// 选取一个位于[1~n-1]之间的随机数k，n是椭圆曲线的参数N
// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8) // (N + 64) / 8 = （256 + 64） / 8
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b) // 5.Convert returned_bits to the (non-negtive) integrer c
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one) // 6. k = (c mod (n-1)) + 1, here n = params.N
	return
}

// 生成sm2的公私钥对
// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	// 生成随机数k
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	// 设置曲线为sm2p256
	priv.PublicKey.Curve = c
	// 设置私钥为随机数k
	priv.D = k
	// 计算公钥座标 k*G
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

var errZeroParam = errors.New("zero parameter")

// IsSM2PublicKey check if given public key is a SM2 public key or not
func IsSM2PublicKey(publicKey interface{}) bool {
	pub, ok := publicKey.(*PublicKey)
	return ok && strings.EqualFold(P256Sm2().Params().Name, pub.Curve.Params().Name)
}

// ↓↓↓↓↓↓↓↓↓↓ 签名与验签 ↓↓↓↓↓↓↓↓↓↓

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed.
var directSigning crypto.Hash = 0

// sm2签名参数
// SM2SignerOption implements crypto.SignerOpts interface.
// It is specific for SM2, used in private key's Sign method.
type SM2SignerOption struct {
	// ZA计算用唯一标识符，只在ForceZA为true时使用。
	UID []byte
	// 是否强制使用国密签名标准，即对签名内容进行ZA混合散列后再签名。
	// 该值为true则代表进行ZA混合散列。
	ForceZA bool
}

// 生成一个新的sm2签名参数
//  forceZA为true而uid为空时，使用defaultUID
func NewSM2SignerOption(forceZA bool, uid []byte) *SM2SignerOption {
	opt := &SM2SignerOption{
		UID:     uid,
		ForceZA: forceZA,
	}
	if forceZA && len(uid) == 0 {
		// ForceGMSign为true而uid为空时，使用defaultUID
		opt.UID = defaultUID
	}
	return opt
}

// 生成一个默认的sm2签名参数
func DefaultSM2SignerOption() *SM2SignerOption {
	return &SM2SignerOption{
		UID:     defaultUID,
		ForceZA: true,
	}
}

// 为sm2.SM2SignerOption实现crypto.SignerOpts接口
func (*SM2SignerOption) HashFunc() crypto.Hash {
	return directSigning
}

// Signer SM2 special signer
type Signer interface {
	SignWithZA(rand io.Reader, uid, msg []byte) ([]byte, error)
}

// 为sm2.PrivateKey实现SignWithZA方法。
//  该方法强制对msg做ZA混合散列
// SignWithZA signs uid, msg with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// Deprecated: please use Sign method directly.
func (priv *PrivateKey) SignWithZA(rand io.Reader, uid, msg []byte) ([]byte, error) {
	return priv.Sign(rand, msg, NewSM2SignerOption(true, uid))
}

// SignASN1使用私钥priv对签名摘要hash进行签名，并将签名转为asn1格式字节数组。
//  是否对hash做ZA混合散列取决于opts类型是否*sm2.SM2SignerOption且opts.ForceGMSign为true。
//  如果opts传nil，则对hash做ZA混合散列。
func SignASN1WithOpts(rand io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.Sign(rand, hash, opts)
}

// SignASN1使用私钥priv对签名摘要hash进行签名，并将签名转为asn1格式字节数组。
//  会对hash做ZA混合散列。
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
	return priv.Sign(rand, hash, nil)
}

// 为sm2.PrivateKey实现Sign方法。
//  如果opts类型是*sm2.SM2SignerOption且opts.ForceGMSign为true，或opts传nil，
// 则将对digest进行ZA混合散列后再对其进行签名。
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var r, s *big.Int
	var err error
	if opts == nil {
		opts = DefaultSM2SignerOption()
	}
	if sm2Opts, ok := opts.(*SM2SignerOption); ok {
		// 传入的opts是SM2SignerOption类型时，根据设置决定是否进行ZA混合散列
		if sm2Opts.ForceZA {
			// 执行ZA混合散列
			r, s, err = SignWithZA(rand, priv, sm2Opts.UID, digest)
		} else {
			// 不执行ZA混合散列
			r, s, err = SignAfterZA(rand, priv, digest)
		}
	} else {
		// 传入的opts不是SM2SignerOption类型时，执行ZA混合散列
		r, s, err = SignWithZA(rand, priv, defaultUID, digest)
	}
	if err != nil {
		return nil, err
	}
	// 将签名结果(r,s)转为asn1格式字节数组
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

// Sign使用私钥priv对签名摘要hash进行签名，并将签名转为asn1格式字节数组。
//  会对hash做ZA混合散列。
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	r, s, err = SignWithZA(rand, priv, defaultUID, hash)
	return
}

// Sm2Sign使用私钥priv对签名摘要hash进行签名，并将签名转为asn1格式字节数组。
//  会对hash做ZA混合散列。
func Sm2Sign(priv *PrivateKey, msg, uid []byte, random io.Reader) (r, s *big.Int, err error) {
	r, s, err = SignWithZA(random, priv, defaultUID, msg)
	return
}

// SignWithZA对msg做ZA混合散列后再对得到的校验和进行签名。
//  混合散列使用sm3
// SignWithZA follow sm2 dsa standards for hash part, compliance with GB/T 32918.2-2016.
func SignWithZA(rand io.Reader, priv *PrivateKey, uid, msg []byte) (r, s *big.Int, err error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	// 计算ZA
	za, err := calculateZA(&priv.PublicKey, uid)
	if err != nil {
		return nil, nil, err
	}
	// 混入ZA
	md := sm3.New()
	md.Write(za)
	md.Write(msg)
	// 对混入了ZA的签名内容做散列，对得到的校验和进行签名
	return SignAfterZA(rand, priv, md.Sum(nil))
}

// sm2签名函数
//   1.内部不对签名内容hash进行混入ZA的散列处理。
//   2.内部会根据rand与hash使用aes生成一个后续签名生成随机数用的csprng，即本函数在签名时获取随机数时不是直接使用rand。
func SignAfterZA(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	// 为避免获取相同的随机数?
	maybeReadByte(rand)

	// ↓↓↓↓↓ 计算 csprng 用于签名时的随机数获取 begin ↓↓↓↓↓
	// We use SDK's nouce generation implementation here.
	// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
	//    SHA2-512(priv.D || entropy || hash)[:32]
	// The CSPRNG key is indifferentiable from a random oracle as shown in
	// [Coron], the AES-CTR stream is indifferentiable from a random oracle
	// under standard cryptographic assumptions (see [Larsson] for examples).
	// [Coron]: https://cs.nyu.edu/~dodis/ps/merkle.pdf
	// [Larsson]: https://web.archive.org/web/20040719170906/https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf
	// Get 256 bits of entropy from rand.
	entropy := make([]byte, 32)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}
	// Initialize an SHA-512 hash context; digest ...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.
	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}
	// ↑↑↑↑↑ 计算 csprng 用于签名时的随机数获取 end ↑↑↑↑↑

	return signGeneric(priv, &csprng, hash)
}

// sm2签名的具体实现
func signGeneric(priv *PrivateKey, csprng *cipher.StreamReader, hash []byte) (r, s *big.Int, err error) {
	// 获取私钥对应曲线
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	e := hashToInt(hash, c)
	for {
		for {
			// 1.生成随机数k，注意这里使用的不是random而是前面计算出来的csprng
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}
			// 2.计算P = k*G，即(x, y) = k*G，返回值的x座标赋予r
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			// 3.计算 r = (e + P(x)) mod n
			r.Add(r, e) // e + P(x)
			r.Mod(r, N) //  (e + P(x)) mod n
			if r.Sign() != 0 {
				t := new(big.Int).Add(r, k)
				// 步骤1,2,3得到的 r 与 k 满足条件才能跳出循环
				if t.Cmp(N) != 0 { // if r != 0 && (r + k) != N then ok
					break
				}
			}
		}
		// 4. 计算 s = (((1 + d)^-1) (k-rd)) mod n
		s = new(big.Int).Mul(priv.D, r)      // r×d
		s = new(big.Int).Sub(k, s)           // k - rd
		dp1 := new(big.Int).Add(priv.D, one) // 1 + d
		var dp1Inv *big.Int                  // (1 + d)^-1
		if in, ok := priv.Curve.(invertible); ok {
			fmt.Println("sm2hard/sm2.go signGeneric 利用硬件加速")
			// 如果平台cpu是amd64或arm64架构，则利用cpu硬件实现快速的 (1 + d)^-1 运算
			dp1Inv = in.Inverse(dp1)
		} else {
			fmt.Println("sm2hard/sm2.go signGeneric 没有利用硬件加速")
			// 纯软实现的 (1 + d)^-1 运算
			dp1Inv = fermatInverse(dp1, N) // N != 0
		}
		s.Mul(s, dp1Inv) // ((1 + d)^-1) × (k-rd)
		s.Mod(s, N)      // (((1 + d)^-1) (k-rd)) mod n
		if s.Sign() != 0 {
			break
		}
	}

	return
}

// sm2公钥验签
//  对msg做ZA混合散列
func (pub *PublicKey) Verify(msg []byte, sig []byte) bool {
	return VerifyASN1(pub, msg, sig)
}

// VerifyASN1将asn1格式字节数组的签名转为(r,s)在调用sm2的验签函数。
//  对msg做ZA混合散列
func VerifyASN1(pub *PublicKey, msg, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return VerifyWithZA(pub, nil, msg, r, s)
}

// VerifyASN1WithoutZA将asn1格式字节数组的签名转为(r,s)，再做验签。
// 不对hash再做ZA混合散列。
func VerifyASN1WithoutZA(pub *PublicKey, hash, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return verifyGeneric(pub, hash, r, s)
}

// sm2验签
//  对msg做ZA混合散列
func Verify(pub *PublicKey, msg []byte, r, s *big.Int) bool {
	return VerifyWithZA(pub, nil, msg, r, s)
}

// sm2验签
//  对msg做ZA混合散列
func Sm2Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	return VerifyWithZA(pub, uid, msg, r, s)
}

// VerifyWithZA将对msg进行ZA混合散列后再进行验签。
func VerifyWithZA(pub *PublicKey, uid, msg []byte, r, s *big.Int) bool {
	if len(uid) == 0 {
		uid = defaultUID
	}
	// 对消息进行ZA混合散列
	za, err := calculateZA(pub, uid)
	if err != nil {
		return false
	}
	md := sm3.New()
	md.Write(za)
	md.Write(msg)
	return verifyGeneric(pub, md.Sum(nil), r, s)
}

// sm2验签的具体实现。
//  如果有ZA混合散列，则在调用该函数之前处理。
func verifyGeneric(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	// 获取公钥对应曲线及其参数N
	c := pub.Curve
	N := c.Params().N
	// 检查签名(r,s)是否在(0, N)区间
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	e := hashToInt(hash, c)
	// 1.计算 t = (r + s) mod n
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}
	var x *big.Int
	if opt, ok := c.(combinedMult); ok {
		fmt.Println("sm2hard/sm2.go verifyGeneric 利用硬件加速")
		// 如果cpu是amd64或arm64架构，则使用快速计算实现步骤2~4
		x, _ = opt.CombinedMult(pub.X, pub.Y, s.Bytes(), t.Bytes())
	} else {
		fmt.Println("sm2hard/sm2.go verifyGeneric 没有利用硬件加速")
		// 2.计算 s*G
		x1, y1 := c.ScalarBaseMult(s.Bytes())
		// 3.计算 t*pub
		x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		// 4.计算 s*G + t*pub 结果只要x轴座标
		x, _ = c.Add(x1, y1, x2, y2)
	}
	// 计算 e + x
	x.Add(x, e)
	// 计算 R = (e + x) mod n
	x.Mod(x, N)
	// 判断 R == r
	return x.Cmp(r) == 0
}

// ZA计算。
//  SM2签名与验签之前，先对签名内容做一次混入ZA的散列。
//  ZA的值是根据公钥与uid计算出来的。
//  CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
//  Compliance with GB/T 32918.2-2016 5.5
func CalculateZA(pub *PublicKey, uid []byte) ([]byte, error) {
	return calculateZA(pub, uid)
}

// ZA计算。
//  SM2签名与验签之前，先对签名内容做一次混入ZA的散列。
//  ZA的值是根据公钥与uid计算出来的。
//  calculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
//  Compliance with GB/T 32918.2-2016 5.5
func calculateZA(pub *PublicKey, uid []byte) ([]byte, error) {
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("the uid is too long")
	}
	entla := uint16(uidLen) << 3
	md := sm3.New()
	md.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		md.Write(uid)
	}
	a := new(big.Int).Sub(pub.Params().P, big.NewInt(3))
	md.Write(toBytes(pub.Curve, a))
	md.Write(toBytes(pub.Curve, pub.Params().B))
	md.Write(toBytes(pub.Curve, pub.Params().Gx))
	md.Write(toBytes(pub.Curve, pub.Params().Gy))
	md.Write(toBytes(pub.Curve, pub.X))
	md.Write(toBytes(pub.Curve, pub.Y))
	return md.Sum(nil), nil
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

// A invertible implements fast inverse in GF(N).
type invertible interface {
	// mod Params().N 的倒数运算
	// Inverse returns the inverse of k mod Params().N.
	Inverse(k *big.Int) *big.Int
}

// fermatInverse 使用费马方法（取幂模 P - 2，根据欧拉定理）计算 GF(P) 中 k 的倒数。
//
// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

// combineMult 实现了快速组合乘法以进行验证。需要平台对应架构CPU的硬件支持。
// A combinedMult implements fast combined multiplication for verification.
type combinedMult interface {
	// CombinedMult 返回 [s1]G + [s2]P，其中 G 是生成器。
	//  需要平台对应架构CPU的硬件支持。
	// CombinedMult returns [s1]G + [s2]P where G is the generator.
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

const (
	aesIV = "IV for ECDSA CTR"
)

// ↑↑↑↑↑↑↑↑↑↑ 签名与验签 ↑↑↑↑↑↑↑↑↑↑

// ↓↓↓↓↓↓↓↓↓↓ 非对称加解密 ↓↓↓↓↓↓↓↓↓↓

// sm2公钥加密, C1C3C2, C1不压缩, C3C2做ASN1转码
func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

// sm2私钥解密, C1C3C2, C1不压缩, C3C2做ASN1转码
func (priv *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(priv, data)
}

// sm2公钥加密
//  opts传nil代表默认模式: C1C3C2, C1不压缩, C3C2不做ASN1转码
func (pub *PublicKey) Encrypt(rand io.Reader, msg []byte, opts *EncrypterOpts) (ciphertext []byte, err error) {
	return encryptGeneric(rand, pub, msg, opts)
}

// sm2私钥解密
//  opts传nil代表C1C3C2模式
func (priv *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts *DecrypterOpts) (plaintext []byte, err error) {
	return decryptGeneric(priv, msg, opts)
}

// sm2公钥加密
//  opts传nil代表默认模式: C1C3C2, C1不压缩, C3C2不做ASN1转码
func Encrypt(pub *PublicKey, data []byte, random io.Reader, opts *EncrypterOpts) ([]byte, error) {
	return encryptGeneric(random, pub, data, opts)
}

// sm2私钥解密
//  opts传nil代表C1C3C2模式
func Decrypt(priv *PrivateKey, data []byte, opts *DecrypterOpts) ([]byte, error) {
	return decryptGeneric(priv, data, opts)
}

// sm2公钥加密
//  默认模式: C1C3C2, C1不压缩, C3C2不做ASN1转码
func EncryptDefault(pub *PublicKey, data []byte, random io.Reader) ([]byte, error) {
	return encryptGeneric(random, pub, data, nil)
}

// sm2公钥加密
//  默认模式: C1C3C2, C1不压缩, C3C2做ASN1转码
func EncryptAsn1(pub *PublicKey, data []byte, random io.Reader) ([]byte, error) {
	return encryptGeneric(random, pub, data, ASN1EncrypterOpts)
}

// sm2私钥解密, C1C3C2模式
func DecryptDefault(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decryptGeneric(priv, ciphertext, nil)
}

// sm2私钥解密, C1C3C2, C3C2做ASN1转码
func DecryptAsn1(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decryptGeneric(priv, ciphertext, ASN1DecrypterOpts)
}

// sm2公钥加密实现
//  opts传nil代表默认模式: C1C3C2, C1不压缩, C3C2不做ASN1转码
//  参考: GB/T 32918.4-2016 chapter 6
func encryptGeneric(random io.Reader, pub *PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	// 获取公钥对应曲线
	curve := pub.Curve
	msgLen := len(msg)
	if msgLen == 0 {
		return nil, nil
	}
	if opts == nil {
		// 默认C1C3C2, C1不压缩, C3C2不做ASN1转码
		opts = defaultEncrypterOpts
	}
	// 检查公钥坐标
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("SM2: invalid public key")
	}
	for {
		// 1.获取随机数k
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}
		// 2.计算C1 = k*G ，C1是曲线上的一个点，坐标为(x1, y1)。
		// 因为k是随机数，所以C1每次加密都是随机的
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		// 3.计算点(x2,y2) = k*pub，利用公钥计算出一个随机点(x2,y2)
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		var kdfCount int = 0
		// 4.使用密钥派生函数kdf，基于P计算长度等于data长度的派生密钥 t=KDF(x2||y2, klen)
		t, success := kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
		if !success {
			kdfCount++
			if kdfCount > maxRetryLimit {
				return nil, fmt.Errorf("SM2: A5, failed to calculate valid t, tried %v times", kdfCount)
			}
			continue
		}
		// 5.计算C2, 利用派生密钥t对data进行异或加密
		c2 := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			c2[i] = msg[i] ^ t[i]
		}
		// 6.计算C3, 按照 (x2||msg||y2) 的顺序混合数据并做sm3摘要
		c3 := calculateC3(curve, x2, y2, msg)
		// 7.根据参数将C1,C2,C3拼接成加密结果
		// c1字节数组 : 根据加密参数中的座标序列化模式，对c1进行序列化转为字节数组
		c1 := opts.PointMarshalMode.mashal(curve, x1, y1)
		// 如果C2C3不做ASN1转码，则直接在这里拼接加密结果
		// TODO: 在 GB/T 32918.4-2016 中只看到直接拼接C2C3的，并没有对C3C2做ASN1转码的描述
		if opts.CiphertextEncoding == ENCODING_PLAIN {
			switch opts.CiphertextSplicingOrder {
			case C1C3C2:
				return append(append(c1, c3...), c2...), nil
			case C1C2C3:
				return append(append(c1, c2...), c3...), nil
			}
		}
		// C2C3做ASN1转码时，只支持C1C3C2模式且C1不压缩
		return mashalASN1Ciphertext(x1, y1, c2, c3)
	}
}

// sm2私钥解密
//  参考: GB/T 32918.4-2016 chapter 7.
func decryptGeneric(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	// 默认拼接顺序C1C3C2
	splicingOrder := C1C3C2
	if opts != nil {
		// C3C2做了ASN1转码时，按照对应规则读取C1C3C2并做sm2私钥解密
		if opts.CiphertextEncoding == ENCODING_ASN1 {
			return decryptASN1(priv, ciphertext)
		}
		// 不是固定的ASN1模式时，设置传入的拼接模式
		splicingOrder = opts.CipherTextSplicingOrder
	}
	// 判断密文是否做过ASN1转码
	if ciphertext[0] == 0x30 {
		return decryptASN1(priv, ciphertext)
	}
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("SM2: invalid ciphertext length")
	}
	curve := priv.Curve
	// 获取C1坐标，以及C1结束位置
	x1, y1, c1End, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	// 根据拼接顺序取出C2C3
	var c2, c3 []byte
	if splicingOrder == C1C3C2 {
		c2 = ciphertext[c1End+sm3.Size:]
		c3 = ciphertext[c1End : c1End+sm3.Size]
	} else {
		c2 = ciphertext[c1End : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}
	// 执行sm2私钥解密逻辑
	return rawDecrypt(priv, x1, y1, c2, c3)
}

// 按照C1C3C2顺序, C1未压缩, C3C2做了ASN1转码的规则进行sm2私钥解密
func decryptASN1(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	return rawDecrypt(priv, x1, y1, c2, c3)
}

// 按照C1C3C2顺序, C1未压缩, C3C2做了ASN1转码的规则读取C1,C2,C3
func unmarshalASN1Ciphertext(ciphertext []byte) (*big.Int, *big.Int, []byte, []byte, error) {
	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  cryptobyte.String
	)
	input := cryptobyte.String(ciphertext)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, asn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, nil, nil, nil, errors.New("SM2: invalid asn1 format ciphertext")
	}
	return x1, y1, c2, c3, nil
}

// sm2私钥解密实现逻辑
func rawDecrypt(priv *PrivateKey, x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	// 获取私钥对应曲线
	curve := priv.Curve
	// 根据C1计算随机点 (x2,y2) = c1 * D
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())
	msgLen := len(c2)
	// 派生密钥
	t, success := kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
	if !success {
		return nil, errors.New("SM2: invalid cipher text")
	}
	// 再对c2做异或运算，恢复msg
	msg := make([]byte, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = c2[i] ^ t[i]
	}
	// 重新计算C3并比较
	u := calculateC3(curve, x2, y2, msg)
	for i := 0; i < sm3.Size; i++ {
		if c3[i] != u[i] {
			return nil, errors.New("SM2: invalid hash value")
		}
	}
	return msg, nil
}

// sm2加密结果去除ASN1转码
// ASN1Ciphertext2Plain utility method to convert ASN.1 encoding ciphertext to plain encoding format
func ASN1Ciphertext2Plain(ciphertext []byte, opts *EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext((ciphertext))
	if err != nil {
		return nil, err
	}
	curve := P256Sm2()
	c1 := opts.PointMarshalMode.mashal(curve, x1, y1)
	if opts.CiphertextSplicingOrder == C1C3C2 {
		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
	// c1 || c2 || c3
	return append(append(c1, c2...), c3...), nil
}

// sm2加密结果改为ASN1转码
// PlainCiphertext2ASN1 utility method to convert plain encoding ciphertext to ASN.1 encoding format
func PlainCiphertext2ASN1(ciphertext []byte, from ciphertextSplicingOrder) ([]byte, error) {
	if ciphertext[0] == 0x30 {
		return nil, errors.New("SM2: invalid plain encoding ciphertext")
	}
	curve := P256Sm2()
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("SM2: invalid ciphertext length")
	}
	// get C1, and check C1
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	var c2, c3 []byte

	if from == C1C3C2 {
		c2 = ciphertext[c3Start+sm3.Size:]
		c3 = ciphertext[c3Start : c3Start+sm3.Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}
	return mashalASN1Ciphertext(x1, y1, c2, c3)
}

// 修改sm2加密结果的C2C3拼接顺序
// AdjustCiphertextSplicingOrder utility method to change c2 c3 order
func AdjustCiphertextSplicingOrder(ciphertext []byte, from, to ciphertextSplicingOrder) ([]byte, error) {
	curve := P256Sm2()
	if from == to {
		return ciphertext, nil
	}
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("SM2: invalid ciphertext length")
	}
	// 检查C1并获取C1结束位置
	_, _, c1End, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}
	var c1, c2, c3 []byte
	c1 = ciphertext[:c1End]
	if from == C1C3C2 {
		c2 = ciphertext[c1End+sm3.Size:]
		c3 = ciphertext[c1End : c1End+sm3.Size]
	} else {
		c2 = ciphertext[c1End : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}
	result := make([]byte, ciphertextLen)
	copy(result, c1)
	if to == C1C3C2 {
		// c1 || c3 || c2
		copy(result[c1End:], c3)
		copy(result[c1End+sm3.Size:], c2)
	} else {
		// c1 || c2 || c3
		copy(result[c1End:], c2)
		copy(result[ciphertextLen-sm3.Size:], c3)
	}
	return result, nil
}

// 计算C3 : sm3hash(x2||msg||y2)
func calculateC3(curve elliptic.Curve, x2, y2 *big.Int, msg []byte) []byte {
	md := sm3.New()
	md.Write(toBytes(curve, x2))
	md.Write(msg)
	md.Write(toBytes(curve, y2))
	return md.Sum(nil)
}

// 对C3C2做ASN1格式转码，并将加密啊结果拼接为C1C3C2模式，且C1不压缩
func mashalASN1Ciphertext(x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(x1)
		b.AddASN1BigInt(y1)
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

// // EncryptASN1 sm2 encrypt and output ASN.1 result, compliance with GB/T 32918.4-2016.
// func EncryptASN1(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
// 	return Encrypt(random, pub, msg, ASN1EncrypterOpts)
// }

const maxRetryLimit = 100

// 密钥派生函数
// kdf key derivation function, compliance with GB/T 32918.4-2016 5.4.3.
func kdf(z []byte, len int) ([]byte, bool) {
	// limit := (len + sm3.Size - 1) >> sm3.SizeBitSize
	limit := (len + sm3.Size - 1) >> 5
	hasher := sm3.New()
	var countBytes [4]byte
	var ct uint32 = 1
	k := make([]byte, len+sm3.Size-1)
	for i := 0; i < limit; i++ {
		binary.BigEndian.PutUint32(countBytes[:], ct)
		hasher.Write(z)
		hasher.Write(countBytes[:])
		copy(k[i*sm3.Size:], hasher.Sum(nil))
		ct++
		hasher.Reset()
	}
	for i := 0; i < len; i++ {
		if k[i] != 0 {
			return k[:len], true
		}
	}
	return k, false
}

const (
	uncompressed byte = 0x04
	compressed02 byte = 0x02
	compressed03 byte = 0x03
	mixed06      byte = 0x06
	mixed07      byte = 0x07
)

// C1序列化模式
type pointMarshalMode byte

const (
	// C1不压缩序列化
	//MarshalUncompressed uncompressed mashal mode
	MarshalUncompressed pointMarshalMode = iota
	// C1压缩序列化
	//MarshalCompressed compressed mashal mode
	MarshalCompressed
	// C1混合序列化
	//MarshalMixed mixed mashal mode
	MarshalMixed
)

// sm2 C1C2C3拼接顺序
type ciphertextSplicingOrder byte

const (
	// 默认使用 C1C3C2
	C1C3C2 ciphertextSplicingOrder = iota
	C1C2C3
)

// sm2 C2C3转码规则
type ciphertextEncoding byte

const (
	// 平文，即不对C2C3做ASN1转码
	ENCODING_PLAIN ciphertextEncoding = iota
	// ASN1，即对C2C3做ASN1转码
	ENCODING_ASN1
)

// 加密参数
// EncrypterOpts encryption options
type EncrypterOpts struct {
	// C2C3转码规则
	CiphertextEncoding ciphertextEncoding
	// C1序列化模式
	PointMarshalMode pointMarshalMode
	// C1C2C3拼接模式
	CiphertextSplicingOrder ciphertextSplicingOrder
}

// 解密参数
// DecrypterOpts decryption options
type DecrypterOpts struct {
	// 转码规则
	CiphertextEncoding ciphertextEncoding
	// 拼接模式
	CipherTextSplicingOrder ciphertextSplicingOrder
}

// 生成不做ASN1转码的sm2加密参数
func NewPlainEncrypterOpts(marhsalMode pointMarshalMode, splicingOrder ciphertextSplicingOrder) *EncrypterOpts {
	return &EncrypterOpts{ENCODING_PLAIN, marhsalMode, splicingOrder}
}

// 生成不做ASN1转码的sm2解密参数
func NewPlainDecrypterOpts(splicingOrder ciphertextSplicingOrder) *DecrypterOpts {
	return &DecrypterOpts{ENCODING_PLAIN, splicingOrder}
}

// 曲线座标序列化, 用于C1的序列化计算
func (mode pointMarshalMode) mashal(curve elliptic.Curve, x, y *big.Int) []byte {
	switch mode {
	case MarshalCompressed:
		// C1压缩序列化
		return point2CompressedBytes(curve, x, y)
	case MarshalMixed:
		// C1混合序列化
		return point2MixedBytes(curve, x, y)
	default:
		// C1完整序列化
		return point2UncompressedBytes(curve, x, y)
	}
}

// 默认加密参数: C1C3C2, C1不压缩, C3C2不做ASN1转码
var defaultEncrypterOpts = &EncrypterOpts{ENCODING_PLAIN, MarshalUncompressed, C1C3C2}

// ASN1转码加密参数: C1C3C2, C1不压缩, C3C2做ASN1转码
var ASN1EncrypterOpts = &EncrypterOpts{ENCODING_ASN1, MarshalUncompressed, C1C3C2}

// ASN1转码解密参数: C1C3C2, C3C2做ASN1转码
var ASN1DecrypterOpts = &DecrypterOpts{ENCODING_ASN1, C1C3C2}

// ↑↑↑↑↑↑↑↑↑↑ 非对称加解密 ↑↑↑↑↑↑↑↑↑↑
