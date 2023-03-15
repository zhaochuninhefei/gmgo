// Copyright (c) 2023 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

// Package ecdsa_ext ecdsa扩展包
package ecdsa_ext

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecbase"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"io"
	"math/big"
)

// PublicKey ecdsa_ext扩展公钥
//  注意, 该结构体指针上绑定了Verify方法从而实现了`ecbase.EcVerifier`接口
type PublicKey struct {
	ecdsa.PublicKey
}

// EcVerify 为ecdsa_ext扩展公钥绑定Verify方法, 用于实现`ecbase.EcVerifier`接口
//  默认需要low-s检查
func (pub *PublicKey) EcVerify(digest []byte, sig []byte, opts ecbase.EcSignerOpts) (bool, error) {
	if opts == nil {
		opts = ecbase.CreateDefaultEcSignerOpts()
	}
	// 如果有low-s要求，则检查签名s值是否low-s
	if opts.NeedLowS() {
		zclog.Debugf("在ecdsa_ext验签时执行IsSigLowS检查")
		lowS, err := IsSigLowS(&pub.PublicKey, sig)
		if err != nil {
			return false, err
		}
		if !lowS {
			return false, errors.New("ecdsa_ext签名的s值不是low-s值")
		}
		zclog.Debugf("在ecdsa_ext验签时执行IsSigLowS检查OK")
	}
	valid := ecdsa.VerifyASN1(&pub.PublicKey, digest, sig)
	if !valid {
		zclog.ErrorStack("ecdsa_ext验签失败")
		return false, errors.New("ecdsa_ext验签失败")
	}
	zclog.Debugf("ecdsa_ext验签成功")
	return true, nil
}

// ConvPubKeyFromOrigin 将`*ecdsa.PublicKey`封装为ecdsa_ext扩展公钥
//goland:noinspection GoUnusedExportedFunction
func ConvPubKeyFromOrigin(oriKey *ecdsa.PublicKey) *PublicKey {
	pubKey := &PublicKey{
		PublicKey: *oriKey,
	}
	return pubKey
}

// PrivateKey ecdsa_ext扩展私钥
//  注意，该结构体指针上绑定了Public与Sign方法从而实现了`crypto.Signer`接口
type PrivateKey struct {
	ecdsa.PrivateKey
}

// Public 为ecdsa_ext扩展私钥绑定Public方法, 用于实现`crypto.Signer`接口
func (priv *PrivateKey) Public() crypto.PublicKey {
	oriPub := priv.PublicKey
	return &PublicKey{
		PublicKey: oriPub,
	}
}

// Sign 为ecdsa_ext扩展私钥绑定Sign方法, 用于实现`crypto.Signer`接口
//  注意，这里实现的Sign方法可以通过使用`ecbase.CreateEcSignerOpts()`生成opts参数，并通过其参数needLowS来指定是否需要对签名做lows处理。
//  ecdsa签名是(r,s),其中s值有一个反s值(n-s), s与n-s是沿n/2对称的，一个是高值，一个是低值。而在ecdsa的验签逻辑里,如果取反s值也可以创建一个有效的签名(r, n-s)。
//  这种特性可能会导致ECDSA签名被重放攻击和双花攻击利用，因为攻击者可以使用同一个r值和反s值来伪造不同的消息。
//  而low-s处理则在签名后判断s值是否是高值，是则替换为低值，然后在验签时需要额外检查签名s值是不是low-s值，这样就避免了攻击者使用反s值伪造消息。
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, &priv.PrivateKey, digest)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		opts = ecbase.CreateDefaultEcSignerOpts()
	}
	// 判断是否需要low-s处理
	if ecOpts, ok := opts.(ecbase.EcSignerOpts); ok {
		if ecOpts.NeedLowS() {
			zclog.Debugln("在sign时尝试ToLowS处理")
			doLow := false
			doLow, s, err = ToLowS(&priv.PublicKey, s)
			if err != nil {
				return nil, err
			}
			if doLow {
				zclog.Debugf("在sign时完成ToLowS处理")
			}

		}
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

func ConvPrivKeyFromOrigin(oriKey *ecdsa.PrivateKey) *PrivateKey {
	privKey := &PrivateKey{
		PrivateKey: *oriKey,
	}
	return privKey
}

func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	oriKey, err := ecdsa.GenerateKey(c, rand)
	if err != nil {
		return nil, err
	}
	return ConvPrivKeyFromOrigin(oriKey), nil
}

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

//goland:noinspection GoUnusedExportedFunction
func AddCurveHalfOrders(curve elliptic.Curve, halfOrder *big.Int) {
	curveHalfOrders[curve] = halfOrder
}

//goland:noinspection GoUnusedExportedFunction
func GetCurveHalfOrdersAt(c elliptic.Curve) *big.Int {
	return big.NewInt(0).Set(curveHalfOrders[c])
}

// IsSigLowS 检查ecdsa签名的s值是否是low-s值
func IsSigLowS(k *ecdsa.PublicKey, signature []byte) (bool, error) {
	_, s, err := ecbase.UnmarshalECSignature(signature)
	if err != nil {
		return false, err
	}
	return IsLowS(k, s)
}

// SignatureToLowS 检查ecdsa签名的s值是否是lower-s值，如果不是，则将s转为对应的lower-s值并重新序列化为ecdsa签名
//goland:noinspection GoUnusedExportedFunction
func SignatureToLowS(k *ecdsa.PublicKey, signature []byte) (bool, []byte, error) {
	r, s, err := ecbase.UnmarshalECSignature(signature)
	if err != nil {
		return false, nil, err
	}
	hasToLow := false
	hasToLow, s, err = ToLowS(k, s)
	if err != nil {
		return hasToLow, nil, err
	}

	ecSignature, err := ecbase.MarshalECSignature(r, s)
	if err != nil {
		return hasToLow, nil, err
	}

	return hasToLow, ecSignature, nil
}

// IsLowS checks that s is a low-S
func IsLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}
	return s.Cmp(halfOrder) != 1, nil

}

func ToLowS(k *ecdsa.PublicKey, s *big.Int) (bool, *big.Int, error) {
	lowS, err := IsLowS(k, s)
	if err != nil {
		return false, nil, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		//fmt.Println("执行lows处理")
		s.Sub(k.Params().N, s)
		return true, s, nil
	}

	return false, s, nil
}
