// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
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
ReadKeyFromPem : 从pem读取对称加密密钥
ReadKeyFromPemFile : 从pem文件读取对称加密密钥
WriteKeyToPem : 将对称加密密钥写入pem
WriteKeyToPemFile : 将对称加密密钥写入pem文件
*/

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecdsa_ext"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/sm3"
)

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// 私钥与pem相互转换

// ReadPrivateKeyFromPem 将pem字节数组转为对应私钥
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
//  @param privateKeyPem 私钥pem字节数组
//  @param pwd pem解密口令
//  @return interface{} 返回私钥
//  @return error
func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (interface{}, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("failed to decode private key")
	}
	var der []byte
	var err error
	if pwd != nil {
		der, err = DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}
	privKey, err := ParsePKCS8PrivateKey(der)
	if err != nil {
		if err.Error() == ErrMsgUseParseECPrivateKey {
			privKey, err = ParseECPrivateKey(der)
		} else if err.Error() == ErrMsgUseParsePKCS1PrivateKey {
			privKey, err = ParsePKCS1PrivateKey(der)
		} else {
			return nil, err
		}
	}
	// 对于ECDSA_EXT，需要封装为`ecdsa_ext.PrivateKey`
	if block.Type == "ECDSA_EXT PRIVATE KEY" {
		if priv, ok := privKey.(*ecdsa.PrivateKey); ok {
			return &ecdsa_ext.PrivateKey{
				PrivateKey: *priv,
			}, nil
		}
	}
	return privKey, err
}

// ReadPrivateKeyFromPemFile 将pem文件转为对应私钥
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
//  @param FileName pem文件路径
//  @param pwd pem解密口令
//  @return interface{} 返回私钥
//  @return error
func ReadPrivateKeyFromPemFile(FileName string, pwd []byte) (interface{}, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKeyFromPem(data, pwd)
}

// WritePrivateKeyToPem 将私钥转为pem字节数组
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
//  @param key 私钥
//  @param pwd pem加密口令
//  @return []byte 私钥pem字节数组
//  @return error
func WritePrivateKeyToPem(key interface{}, pwd []byte) ([]byte, error) {
	var block *pem.Block
	der, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var pemType string
	switch key.(type) {
	case *sm2.PrivateKey:
		pemType = "SM2 PRIVATE KEY"
	case *ecdsa.PrivateKey:
		pemType = "ECDSA PRIVATE KEY"
	case *ecdsa_ext.PrivateKey:
		pemType = "ECDSA_EXT PRIVATE KEY"
	case ed25519.PrivateKey:
		pemType = "ED25519 PRIVATE KEY"
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
	default:
		return nil, fmt.Errorf("gmx509.WritePrivateKeyToPem : unsupported key: [%T]", key)
	}
	if pwd != nil {
		block, err = EncryptPEMBlock(rand.Reader, "ENCRYPTED "+pemType, der, pwd, PEMCipherSM4)
		if err != nil {
			return nil, err
		}
	} else {
		block = &pem.Block{
			Type:  pemType,
			Bytes: der,
		}
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

// WritePrivateKeytoPemFile 将私钥转为pem文件
//  - 私钥类型: *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
//  @param FileName pem文件路径
//  @param key 私钥
//  @param pwd pem加密口令
//  @return bool 成功与否
//  @return error
func WritePrivateKeytoPemFile(FileName string, key interface{}, pwd []byte) (bool, error) {
	var block *pem.Block
	der, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	var pemType string
	switch key.(type) {
	case *sm2.PrivateKey:
		pemType = "SM2 PRIVATE KEY"
	case *ecdsa.PrivateKey:
		pemType = "ECDSA PRIVATE KEY"
	case *ecdsa_ext.PrivateKey:
		pemType = "ECDSA_EXT PRIVATE KEY"
	case ed25519.PrivateKey:
		pemType = "ED25519 PRIVATE KEY"
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
	default:
		return false, fmt.Errorf("gmx509.WritePrivateKeytoPemFile : unsupported key: [%T]", key)
	}
	if pwd != nil {
		block, err = EncryptPEMBlock(rand.Reader, "ENCRYPTED "+pemType, der, pwd, PEMCipherSM4)
		if err != nil {
			return false, err
		}
	} else {
		block = &pem.Block{
			Type:  pemType,
			Bytes: der,
		}
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			zclog.Errorln(err)
		}
	}(file)
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

// ReadPublicKeyFromPem 将pem字节数组转为对应公钥
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
//  @param publicKeyPem
//  @return interface{}
//  @return error
func ReadPublicKeyFromPem(publicKeyPem []byte) (interface{}, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil || !strings.HasSuffix(block.Type, "PUBLIC KEY") {
		return nil, errors.New("failed to decode public key")
	}
	key, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 对于ECDSA_EXT需要包装为`ecdsa_ext.PublicKey`
	if block.Type == "ECDSA_EXT PUBLIC KEY" {
		if pub, ok := key.(*ecdsa.PublicKey); ok {
			return &ecdsa_ext.PublicKey{
				PublicKey: *pub,
			}, nil
		}
	}
	return key, nil
}

// ReadPublicKeyFromPemFile 将pem文件转为对应公钥
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
//  @param FileName
//  @return interface{}
//  @return error
func ReadPublicKeyFromPemFile(FileName string) (interface{}, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadPublicKeyFromPem(data)
}

// WritePublicKeyToPem 将公钥转为pem字节数组
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
//
//  @param key
//  @return []byte
//  @return error
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
	case *ecdsa_ext.PublicKey:
		pemType = "ECDSA_EXT PUBLIC KEY"
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

// WritePublicKeytoPemFile 将公钥转为pem文件
//  - 公钥类型: *sm2.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
//
//  @param FileName
//  @param key
//  @return bool
//  @return error
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
	case *ecdsa_ext.PublicKey:
		pemType = "ECDSA_EXT PUBLIC KEY"
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
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			zclog.Errorln(err)
		}
	}(file)
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

// 公钥与pem相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// 证书申请与pem相互转换

// ReadCertificateRequestFromPem 将pem字节数组转为证书申请
//
//  @param certPem
//  @return *CertificateRequest
//  @return error
func ReadCertificateRequestFromPem(certPem []byte) (*CertificateRequest, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificateRequest(block.Bytes)
}

// ReadCertificateRequestFromPemFile 将pem文件转为证书申请
//
//  @param FileName
//  @return *CertificateRequest
//  @return error
func ReadCertificateRequestFromPemFile(FileName string) (*CertificateRequest, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateRequestFromPem(data)
}

// CreateCertificateRequestToPem 创建证书申请并转为pem字节数组
//
//  @param template
//  @param signer
//  @return []byte
//  @return error
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

// CreateCertificateRequestToPemFile 创建证书申请并转为pem文件
//
//  @param FileName
//  @param template
//  @param signer
//  @return bool
//  @return error
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
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			zclog.Errorln(err)
		}
	}(file)
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

// ReadCertificateFromPem 将pem字节数组转为gmx509证书
//
//  @param certPem
//  @return *Certificate
//  @return error
func ReadCertificateFromPem(certPem []byte) (*Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificate(block.Bytes)
}

// ReadCertificateFromPemFile 将pem文件转为gmx509证书
//
//  @param FileName
//  @return *Certificate
//  @return error
func ReadCertificateFromPemFile(FileName string) (*Certificate, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadCertificateFromPem(data)
}

// CreateCertificateToPem 创建gmx509证书并转为pem字节数组
//
//  @param template
//  @param parent
//  @param pubKey
//  @param signer
//  @return []byte
//  @return error
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

// CreateCertificateToPemFile 创建gmx509证书并转为pem文件
//
//  @param FileName
//  @param template
//  @param parent
//  @param pubKey
//  @param privKey
//  @return bool
//  @return error
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
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			zclog.Errorln(err)
		}
	}(file)
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}

// gmx509证书与pem相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

// ParseGmx509DerToX509 将gmx509证书DER字节数组转为x509证书
//
//  @param asn1data
//  @return *x509.Certificate
//  @return error
//goland:noinspection GoUnusedExportedFunction
func ParseGmx509DerToX509(asn1data []byte) (*x509.Certificate, error) {
	sm2Cert, err := ParseCertificate(asn1data)
	if err != nil {
		return nil, err
	}
	return sm2Cert.ToX509Certificate(), nil
}

// CreateEllipticSKI 根据椭圆曲线公钥参数生成其SKI值
//
//  @param curve
//  @param x
//  @param y
//  @return []byte
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

// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
// 对称加密密钥与pem相互转换

// ReadKeyFromPem 从pem读取对称加密密钥
func ReadKeyFromPem(data []byte, pwd []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ReadKeyFromPem: pem decode failed")
	}
	blockType := strings.ToUpper(strings.TrimSpace(block.Type))
	if IsEncryptedPEMBlock(block) {
		if !strings.HasSuffix(blockType, "ENCRYPTED KEY") {
			return nil, errors.New("ReadKeyFromPem: unknown type")
		}
		if len(pwd) == 0 {
			return nil, errors.New("ReadKeyFromPem: need passwd")
		}
		data, err := DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	switch blockType {
	case "KEY", "SM4 KEY", "AES KEY", "SYMMETRIC KEY":
		return block.Bytes, nil
	default:
		return nil, errors.New("ReadKeyFromPem: unknown type")
	}
}

// ReadKeyFromPemFile 从pem文件读取对称加密密钥
func ReadKeyFromPemFile(FileName string, pwd []byte) ([]byte, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadKeyFromPem(data, pwd)
}

// WriteKeyToPem 将对称加密密钥写入pem
func WriteKeyToPem(key []byte, pwd []byte) ([]byte, error) {
	var block *pem.Block
	var err error
	if pwd != nil {
		block, err = EncryptPEMBlock(rand.Reader,
			"SYMMETRIC ENCRYPTED KEY", key, pwd, PEMCipherAES256)
	} else {
		block = &pem.Block{
			Type:  "SYMMETRIC KEY",
			Bytes: key,
		}
	}
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// WriteKeyToPemFile 将对称加密密钥写入pem文件
func WriteKeyToPemFile(FileName string, key []byte, pwd []byte) error {
	pemBytes, err := WriteKeyToPem(key, pwd)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(FileName, pemBytes, 0666)
	if err != nil {
		return err
	}
	return nil
}

// 对称加密密钥与pem相互转换
// ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
