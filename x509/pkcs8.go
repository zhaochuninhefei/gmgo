// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

/*
x509/pkcs8.go PKCS#8标准DER字节数组与对应私钥之间的相互转换。
私钥支持: sm2, ecdsa, ed25519, rsa

ParsePKCS8PrivateKey : 将未加密的PKCS #8, ASN.1 DER格式字节数组转为对应的私钥
MarshalPKCS8PrivateKey : 将私钥转为PKCS #8, ASN.1 DER字节数组

PKCS#8 是私钥消息表示标准（Private-Key Information Syntax Standard）.
reference to RFC5959 and RFC2898
*/

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecdsa_ext"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

const (
	ErrMsgUseParseECPrivateKey    = "gmx509.ParsePKCS8PrivateKey: failed to parse private key (use ParseECPrivateKey instead for this key format)"
	ErrMsgUseParsePKCS1PrivateKey = "gmx509.ParsePKCS8PrivateKey: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)"
)

// ParsePKCS8PrivateKey 将未加密的PKCS #8, ASN.1 DER格式字节数组转为对应的私钥。
//  - 私钥支持: sm2, ecdsa, ed25519, rsa
//
// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, or a ed25519.PrivateKey.
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	// 尝试将 der 反序列化到 privKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New(ErrMsgUseParseECPrivateKey)
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New(ErrMsgUseParsePKCS1PrivateKey)
		}
		return nil, err
	}
	// 根据反序列化后的公钥算法标识生成对应的私钥
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeySM2):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		// 尝试获取曲线oid
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		// 根据曲线oid获取对应曲线并生成对应私钥
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("gmx509.ParsePKCS8PrivateKey: failed to parse EC private key embedded in PKCS#8: %s", err.Error())
		}
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("gmx509.ParsePKCS8PrivateKey: failed to parse RSA private key embedded in PKCS#8: %s", err.Error())
		}
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("gmx509.ParsePKCS8PrivateKey: failed to parse EC private key embedded in PKCS#8: %s", err.Error())
		}
		return key, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("gmx509.ParsePKCS8PrivateKey: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("gmx509.ParsePKCS8PrivateKey: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("gmx509.ParsePKCS8PrivateKey: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil
	default:
		return nil, fmt.Errorf("gmx509.ParsePKCS8PrivateKey: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey 将私钥转为PKCS #8, ASN.1 DER字节数组
//  - 私钥支持: sm2, ecdsa, ed25519, rsa
//
// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey, *ecdsa.PrivateKey
// and ed25519.PrivateKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *sm2.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, fmt.Errorf("gmx509.MarshalPKCS8PrivateKey: unknown curve: [%s]", k.Curve.Params().Name)
		}
		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, fmt.Errorf("gmx509.MarshalPKCS8PrivateKey: failed to marshal curve OID: [%s]", err.Error())
		}
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeySM2,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, oid); err != nil {
			return nil, fmt.Errorf("gmx509.MarshalPKCS8PrivateKey: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("gmx509.MarshalPKCS8PrivateKey: unknown curve while marshaling to PKCS#8")
		}
		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("gmx509.MarshalPKCS8PrivateKey: failed to marshal curve OID: " + err.Error())
		}
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		// 注意, ecdsa并没有将曲线oid传入序列化结构中
		// 大约是为了与openssl的结果对应
		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("gmx509.MarshalPKCS8PrivateKey: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}
	case *ecdsa_ext.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("gmx509.MarshalPKCS8PrivateKey: unknown curve while marshaling to PKCS#8")
		}
		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("gmx509.MarshalPKCS8PrivateKey: failed to marshal curve OID: " + err.Error())
		}
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		// 注意, ecdsa并没有将曲线oid传入序列化结构中
		// 大约是为了与openssl的结果对应
		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("gmx509.MarshalPKCS8PrivateKey: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}
	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("gmx509.MarshalPKCS8PrivateKey: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey
	default:
		return nil, fmt.Errorf("gmx509.MarshalPKCS8PrivateKey: unknown key type while marshaling PKCS#8: %T", key)
	}
	return asn1.Marshal(privKey)
}
