// Copyright (c) 2022 zhaochun
// gmingo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package x509

/*
x509/utils.go 提供gmx509常用操作的公开函数:
ReadPrivateKeyFromPem : 将pem字节数组转为对应私钥
ReadPrivateKeyFromPemFile : 将pem文件转为对应私钥
WritePrivateKeyToPem : 将私钥转为pem字节数组
WritePrivateKeytoPemFile : 将私钥转为pem文件
ReadPublicKeyFromPem :  将pem字节数组转为对应公钥
ReadPublicKeyFromPemFile : 将pem文件转为对应公钥
WritePublicKeyToPem : 将公钥转为pem字节数组
WritePublicKeytoPemFile : 将公钥转为pem文件
ReadSm2PrivFromHex : 将hex字符串转为sm2私钥
WriteSm2PrivToHex : 将sm2私钥D转为hex字符串
ReadSm2PubFromHex : 将hex字符串转为sm2公钥
WriteSm2PubToHex : 将sm2公钥转为hex字符串
ReadCertificateRequestFromPem : 将pem字节数组转为证书申请
ReadCertificateRequestFromPemFile : 将pem文件转为证书申请
CreateCertificateRequestToPem : 创建证书申请并转为pem字节数组
CreateCertificateRequestToPemFile : 创建证书申请并转为pem文件
ReadCertificateFromPem : 将pem字节数组转为gmx509证书
ReadCertificateFromPemFile : 将pem文件转为gmx509证书
CreateCertificateToPem : 创建gmx509证书并转为pem字节数组
CreateCertificateToPemFile : 创建gmx509证书并转为pem文件
ParseGmx509DerToX509 : 将gmx509证书DER字节数组转为x509证书
CreateEllipticSKI : 根据椭圆曲线公钥参数生成其SKI值
GetRandBigInt : 随机生成序列号
*/

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/sm3"
)

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// 私钥与pem相互转换

// 将pem字节数组转为对应私钥
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (interface{}, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParsePKCS8PrivateKey(block.Bytes)
	return priv, err
}

// 将pem文件转为对应私钥
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
func ReadPrivateKeyFromPemFile(FileName string, pwd []byte) (interface{}, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKeyFromPem(data, pwd)
}

// 将私钥转为pem字节数组
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
func WritePrivateKeyToPem(key interface{}, pwd []byte) ([]byte, error) {
	var block *pem.Block
	der, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	// if pwd != nil {
	// 	block = &pem.Block{
	// 		Type:  "ENCRYPTED PRIVATE KEY",
	// 		Bytes: der,
	// 	}
	// } else {
	// 	block = &pem.Block{
	// 		Type:  "PRIVATE KEY",
	// 		Bytes: der,
	// 	}
	// }
	var pemType string
	switch key.(type) {
	case *sm2.PrivateKey:
		pemType = "SM2 PRIVATE KEY"
	case *ecdsa.PrivateKey:
		pemType = "ECDSA PRIVATE KEY"
	case ed25519.PrivateKey:
		pemType = "ED25519 PRIVATE KEY"
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
	default:
		return nil, fmt.Errorf("gmx509.WritePrivateKeyToPem : unsupported key: [%T]", key)
	}
	block = &pem.Block{
		Type:  pemType,
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

// 将私钥转为pem文件
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
func WritePrivateKeytoPemFile(FileName string, key interface{}, pwd []byte) (bool, error) {
	var block *pem.Block
	der, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	// if pwd != nil {
	// 	block = &pem.Block{
	// 		Type:  "ENCRYPTED PRIVATE KEY",
	// 		Bytes: der,
	// 	}
	// } else {
	// 	block = &pem.Block{
	// 		Type:  "PRIVATE KEY",
	// 		Bytes: der,
	// 	}
	// }
	var pemType string
	switch key.(type) {
	case *sm2.PrivateKey:
		pemType = "SM2 PRIVATE KEY"
	case *ecdsa.PrivateKey:
		pemType = "ECDSA PRIVATE KEY"
	case ed25519.PrivateKey:
		pemType = "ED25519 PRIVATE KEY"
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
	default:
		return false, fmt.Errorf("gmx509.WritePrivateKeytoPemFile : unsupported key: [%T]", key)
	}
	block = &pem.Block{
		Type:  pemType,
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

// 私钥与pem相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// 公钥与pem相互转换

// 将pem字节数组转为对应公钥
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
func ReadPublicKeyFromPem(publicKeyPem []byte) (interface{}, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil || !strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return nil, errors.New("failed to decode public key")
	}
	return ParsePKIXPublicKey(block.Bytes)
}

// 将pem文件转为对应公钥
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
func ReadPublicKeyFromPemFile(FileName string) (interface{}, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPublicKeyFromPem(data)
}

// 将公钥转为pem字节数组
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
func WritePublicKeyToPem(key interface{}) ([]byte, error) {
	der, err := MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	var pemType string
	switch key.(type) {
	case *sm2.PublicKey:
		pemType = "SM2 PUBLIC KEY"
	case *ecdsa.PublicKey:
		pemType = "ECDSA PUBLIC KEY"
	case ed25519.PublicKey:
		pemType = "ED25519 PUBLIC KEY"
	case *rsa.PublicKey:
		pemType = "RSA PUBLIC KEY"
	default:
		return nil, fmt.Errorf("gmx509.WritePublicKeyToPem : unsupported key: [%T]", key)
	}
	block := &pem.Block{
		Type:  pemType,
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

// 将公钥转为pem文件
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
func WritePublicKeytoPemFile(FileName string, key interface{}) (bool, error) {
	der, err := MarshalPKIXPublicKey(key)
	if err != nil {
		return false, err
	}
	var pemType string
	switch key.(type) {
	case *sm2.PublicKey:
		pemType = "SM2 PUBLIC KEY"
	case *ecdsa.PublicKey:
		pemType = "ECDSA PUBLIC KEY"
	case ed25519.PublicKey:
		pemType = "ED25519 PUBLIC KEY"
	case *rsa.PublicKey:
		pemType = "RSA PUBLIC KEY"
	default:
		return false, fmt.Errorf("gmx509.WritePublicKeytoPemFile : unsupported key: [%T]", key)
	}
	block := &pem.Block{
		Type:  pemType,
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

// 公钥与pem相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// SM2公私钥与hex相互转换

// 将hex字符串转为sm2私钥
// Dhex是16进制字符串，对应sm2.PrivateKey.D
func ReadSm2PrivFromHex(Dhex string) (*sm2.PrivateKey, error) {
	c := sm2.P256Sm2()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow")
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// 将sm2私钥D转为hex字符串
func WriteSm2PrivToHex(key *sm2.PrivateKey) string {
	return key.D.Text(16)
}

// 将hex字符串转为sm2公钥
// Qhex是sm2公钥座标x,y的字节数组拼接后的hex转码字符串
func ReadSm2PubFromHex(Qhex string) (*sm2.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 65 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 64 {
		return nil, errors.New("publicKey is not uncompressed")
	}
	pub := new(sm2.PublicKey)
	pub.Curve = sm2.P256Sm2()
	pub.X = new(big.Int).SetBytes(q[:32])
	pub.Y = new(big.Int).SetBytes(q[32:])
	return pub, nil
}

// 将sm2公钥转为hex字符串
func WriteSm2PubToHex(key *sm2.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	c = append([]byte{0x04}, c...)
	return hex.EncodeToString(c)
}

// SM2公私钥与hex相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// 证书申请与pem相互转换

// 将pem字节数组转为证书申请
func ReadCertificateRequestFromPem(certPem []byte) (*CertificateRequest, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificateRequest(block.Bytes)
}

// 将pem文件转为证书申请
func ReadCertificateRequestFromPemFile(FileName string) (*CertificateRequest, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateRequestFromPem(data)
}

// 创建证书申请并转为pem字节数组
func CreateCertificateRequestToPem(template *CertificateRequest, signer interface{}) ([]byte, error) {
	der, err := CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

// 创建证书申请并转为pem文件
func CreateCertificateRequestToPemFile(FileName string, template *CertificateRequest, signer interface{}) (bool, error) {
	der, err := CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

// 证书申请与pem相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// gmx509证书与pem相互转换

// 将pem字节数组转为gmx509证书
func ReadCertificateFromPem(certPem []byte) (*Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificate(block.Bytes)
}

// 将pem文件转为gmx509证书
func ReadCertificateFromPemFile(FileName string) (*Certificate, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateFromPem(data)
}

// 创建gmx509证书并转为pem字节数组
func CreateCertificateToPem(template, parent *Certificate, pubKey, signer interface{}) ([]byte, error) {
	der, err := CreateCertificate(rand.Reader, template, parent, pubKey, signer)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

// 创建gmx509证书并转为pem文件
func CreateCertificateToPemFile(FileName string, template, parent *Certificate, pubKey, privKey interface{}) (bool, error) {
	der, err := CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

// gmx509证书与pem相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

// 将gmx509证书DER字节数组转为x509证书
func ParseGmx509DerToX509(asn1data []byte) (*x509.Certificate, error) {
	sm2Cert, err := ParseCertificate(asn1data)
	if err != nil {
		return nil, err
	}
	return sm2Cert.ToX509Certificate(), nil
}

// 根据椭圆曲线公钥参数生成其SKI值
func CreateEllipticSKI(curve elliptic.Curve, x, y *big.Int) []byte {
	if curve == nil {
		return nil
	}
	//Marshall the public key
	raw := elliptic.Marshal(curve, x, y)
	// Hash it 国密改造后改为sm3
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// 随机生成序列号
func GetRandBigInt() *big.Int {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return sn
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
