// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

/*
x509/sec1.go 椭圆曲线公私钥与其SEC 1, ASN.1 DER字节数组之间的相互转换
目前支持sm2, ecdsa

ParseECPrivateKey : 将SEC 1, ASN.1 DER格式字节数组转为EC(椭圆曲线)私钥
MarshalECPrivateKey : 将EC(椭圆曲线)私钥转为SEC 1, ASN.1 DER格式字节数组
*/

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"gitee.com/zhaochuninhefei/gmgo/ecdsa_ext"

	gmelliptic "gitee.com/zhaochuninhefei/gmgo/gmcrypto/elliptic"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

const ecPrivKeyVersion = 1

// ecPrivateKey 椭圆曲线私钥结构体, 添加用于识别私钥类型的字段(目前支持sm2/ecdsa/ecdsa_ext)
//
//	ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
//
// References:
//
//	RFC 5915
//	SEC1 - http://www.secg.org/sec1-v2.pdf
//
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`

	// 用于识别私钥类型的字段
	PrivType string `asn1:"optional,explicit,tag:2"`
}

// ParseECPrivateKey 将SEC 1, ASN.1 DER格式字节数组转为EC(椭圆曲线)私钥
// 私钥目前支持: *sm2.PrivateKey, *ecdsa.PrivateKey, *ecdsa_ext.PrivateKey
//
// ParseECPrivateKey parses an EC private key in SEC 1, ASN.1 DER form.
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
func ParseECPrivateKey(der []byte) (interface{}, error) {
	return parseECPrivateKey(nil, der)
}

// MarshalECPrivateKey 将EC(椭圆曲线)私钥转为SEC 1, ASN.1 DER格式字节数组
// 私钥目前支持: *sm2.PrivateKey, *ecdsa.PrivateKey, *ecdsa_ext.PrivateKey
//
// MarshalECPrivateKey converts an EC private key to SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
// For a more flexible key format which is not EC specific, use
// MarshalPKCS8PrivateKey.
func MarshalECPrivateKey(key interface{}) ([]byte, error) {
	switch priv := key.(type) {
	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(priv.Curve)
		if !ok {
			return nil, errors.New("gmx509.MarshalECPrivateKey: unknown elliptic curve")
		}
		if oid.Equal(oidNamedCurveP256SM2) {
			return nil, errors.New("gmx509.MarshalECPrivateKey: not ecdsa curves")
		}
		privateKey := make([]byte, (priv.Curve.Params().N.BitLen()+7)/8)
		return asn1.Marshal(ecPrivateKey{
			Version:       ecPrivKeyVersion,
			PrivateKey:    priv.D.FillBytes(privateKey),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: gmelliptic.StdMarshal(priv.Curve, priv.X, priv.Y)},
			PrivType:      "ecdsa",
		})
	case *ecdsa_ext.PrivateKey:
		oid, ok := oidFromNamedCurve(priv.Curve)
		if !ok {
			return nil, errors.New("gmx509.MarshalECPrivateKey: unknown elliptic curve")
		}
		if oid.Equal(oidNamedCurveP256SM2) {
			return nil, errors.New("gmx509.MarshalECPrivateKey: not ecdsa curves")
		}
		privateKey := make([]byte, (priv.Curve.Params().N.BitLen()+7)/8)
		return asn1.Marshal(ecPrivateKey{
			Version:       ecPrivKeyVersion,
			PrivateKey:    priv.D.FillBytes(privateKey),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: gmelliptic.StdMarshal(priv.Curve, priv.X, priv.Y)},
			PrivType:      "ecdsa_ext",
		})
	case *sm2.PrivateKey:
		oid, ok := oidFromNamedCurve(priv.Curve)
		if !ok {
			return nil, errors.New("gmx509.MarshalECPrivateKey: unknown elliptic curve")
		}
		if !oid.Equal(oidNamedCurveP256SM2) {
			return nil, errors.New("gmx509.MarshalECPrivateKey: not sm2 curve")
		}
		privateKey := make([]byte, (priv.Curve.Params().N.BitLen()+7)/8)
		return asn1.Marshal(ecPrivateKey{
			Version:       ecPrivKeyVersion,
			PrivateKey:    priv.D.FillBytes(privateKey),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: gmelliptic.StdMarshal(priv.Curve, priv.X, priv.Y)},
			PrivType:      "sm2",
		})
		// var ecPriv ecPrivateKey
		// ecPriv.Version = ecPrivKeyVersion
		// ecPriv.NamedCurveOID = oidNamedCurveP256SM2
		// ecPriv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(priv.Curve, priv.X, priv.Y)}
		// ecPriv.PrivateKey = priv.D.Bytes()
		// return asn1.Marshal(ecPriv)
	}
	return nil, errors.New("x509: failed to marshalECPrivateKeyWithOID: Unknown PrivateKey")
}

// parseECPrivateKey根据namedCurveOID获取对应的椭圆曲线，并将SEC 1, ASN.1 DER格式字节数组转为EC(椭圆曲线)私钥
// 私钥目前支持: *sm2.PrivateKey, *ecdsa.PrivateKey, *ecdsa_ext.PrivateKey
//
// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key interface{}, err error) {
	var privKey ecPrivateKey
	// 尝试将 der 反序列化到 privKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &pkcs8{}); err == nil {
			return nil, errors.New("gmx509.parseECPrivateKey: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("gmx509.parseECPrivateKey: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, fmt.Errorf("gmx509.parseECPrivateKey: failed to parse EC private key: %s", err.Error())
	}
	// 检查版本
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("gmx509.parseECPrivateKey: unknown EC private key version %d", privKey.Version)
	}
	var curve elliptic.Curve
	// namedCurveOID有可能为nil，因为ecdsa在其序列化(pkcs8.go的MarshalPKCS8PrivateKey)分支里并没有传入oid到序列化结构中去。
	if namedCurveOID != nil {
		// 根据namedCurveOID获取曲线
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		// namedCurveOID为空则使用私钥的NamedCurveOID
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("gmx509.parseECPrivateKey: unknown elliptic curve")
	}
	// 检查私钥数值是否小于曲线参数N
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("gmx509.parseECPrivateKey: invalid elliptic curve private key value")
	}
	// 根据曲线选择生成对应完整私钥
	switch curve {
	case sm2.P256Sm2():
		priv := new(sm2.PrivateKey)
		priv.Curve = curve
		priv.D = k
		privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
		// Some private keys have leading zero padding. This is invalid
		// according to [SEC1], but this code will ignore it.
		for len(privKey.PrivateKey) > len(privateKey) {
			if privKey.PrivateKey[0] != 0 {
				return nil, errors.New("gmx509.parseECPrivateKey: invalid private key length")
			}
			privKey.PrivateKey = privKey.PrivateKey[1:]
		}
		// Some private keys remove all leading zeros, this is also invalid
		// according to [SEC1] but since OpenSSL used to do this, we ignore
		// this too.
		copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
		priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
		return priv, nil
	case elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521():
		switch privKey.PrivType {
		case "ecdsa", "":
			priv := new(ecdsa.PrivateKey)
			priv.Curve = curve
			priv.D = k
			privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
			// Some private keys have leading zero padding. This is invalid
			// according to [SEC1], but this code will ignore it.
			for len(privKey.PrivateKey) > len(privateKey) {
				if privKey.PrivateKey[0] != 0 {
					return nil, errors.New("gmx509.parseECPrivateKey: invalid private key length")
				}
				privKey.PrivateKey = privKey.PrivateKey[1:]
			}
			// Some private keys remove all leading zeros, this is also invalid
			// according to [SEC1] but since OpenSSL used to do this, we ignore
			// this too.
			copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
			priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
			return priv, nil
		case "ecdsa_ext":
			priv := new(ecdsa_ext.PrivateKey)
			priv.Curve = curve
			priv.D = k
			privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
			// Some private keys have leading zero padding. This is invalid
			// according to [SEC1], but this code will ignore it.
			for len(privKey.PrivateKey) > len(privateKey) {
				if privKey.PrivateKey[0] != 0 {
					return nil, errors.New("gmx509.parseECPrivateKey: invalid private key length")
				}
				privKey.PrivateKey = privKey.PrivateKey[1:]
			}
			// Some private keys remove all leading zeros, this is also invalid
			// according to [SEC1] but since OpenSSL used to do this, we ignore
			// this too.
			copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
			priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
			return priv, nil
		}
	}
	return nil, errors.New("gmx509.parseECPrivateKey: failed to parseECPrivateKey: Unknown curve")
}

// marshalECPrivateKeyWithOID根据oid将EC(椭圆曲线)私钥转为SEC 1, ASN.1 DER格式字节数组
// 私钥目前支持: *sm2.PrivateKey, *ecdsa.PrivateKey, *ecdsa_ext.PrivateKey
//
// marshalECPrivateKey marshals an EC private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key interface{}, oid asn1.ObjectIdentifier) ([]byte, error) {
	switch priv := key.(type) {
	case *ecdsa.PrivateKey:
		if oid.Equal(oidNamedCurveP256SM2) {
			return nil, errors.New("gmx509.marshalECPrivateKeyWithOID: not ecdsa curves")
		}
		privateKey := make([]byte, (priv.Curve.Params().N.BitLen()+7)/8)
		return asn1.Marshal(ecPrivateKey{
			Version:       ecPrivKeyVersion,
			PrivateKey:    priv.D.FillBytes(privateKey),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: gmelliptic.StdMarshal(priv.Curve, priv.X, priv.Y)},
			PrivType:      "ecdsa",
		})
	case *ecdsa_ext.PrivateKey:
		if oid.Equal(oidNamedCurveP256SM2) {
			return nil, errors.New("gmx509.marshalECPrivateKeyWithOID: not ecdsa curves")
		}
		privateKey := make([]byte, (priv.Curve.Params().N.BitLen()+7)/8)
		return asn1.Marshal(ecPrivateKey{
			Version:       ecPrivKeyVersion,
			PrivateKey:    priv.D.FillBytes(privateKey),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: gmelliptic.StdMarshal(priv.Curve, priv.X, priv.Y)},
			PrivType:      "ecdsa_ext",
		})
	case *sm2.PrivateKey:
		if !oid.Equal(oidNamedCurveP256SM2) {
			return nil, errors.New("gmx509.marshalECPrivateKeyWithOID: not sm2 curve")
		}
		privateKey := make([]byte, (priv.Curve.Params().N.BitLen()+7)/8)
		return asn1.Marshal(ecPrivateKey{
			Version:       ecPrivKeyVersion,
			PrivateKey:    priv.D.FillBytes(privateKey),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: gmelliptic.StdMarshal(priv.Curve, priv.X, priv.Y)},
			PrivType:      "sm2",
		})
		// var ecPriv ecPrivateKey
		// ecPriv.Version = ecPrivKeyVersion
		// ecPriv.NamedCurveOID = oidNamedCurveP256SM2
		// ecPriv.PublicKey = asn1.BitString{Bytes: elliptic.Marshal(priv.Curve, priv.X, priv.Y)}
		// ecPriv.PrivateKey = priv.D.Bytes()
		// return asn1.Marshal(ecPriv)
	}
	return nil, errors.New("gmx509.marshalECPrivateKeyWithOID: failed to marshalECPrivateKeyWithOID: Unknown PrivateKey")
}
