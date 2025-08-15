// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
package x509

/*
x509/x509.go 实现gmx509证书的相关操作:
ParsePKIXPublicKey : 将一个PKIX, ASN.1 DER格式字节数组转为对应的公钥
MarshalPKIXPublicKey : 将公钥转为PKIX, ASN.1 DER格式字节数组
Certificate : gmx509证书结构体
 c.CheckSignatureFrom : 检查对c做的签名是否是父证书拥有者的有效签名(使用父证书中的公钥验签)
 c.CheckSignature : 使用c的公钥检查签名是否有效
 c.ToX509Certificate : gmx509转x509
 c.FromX509Certificate : x509转gmx509
 c.CheckCRLSignature : 检查证书撤销列表CRL是否由c签名
 c.CreateCRL : 创建一个CRL
CreateCertificate : 根据证书模板生成gmx509证书(v3)的DER字节数组
ParseCRL : 将给定的字节数组(PEM/DER)转为CRL
ParseDERCRL : 将DER字节数组转为CRL
CertificateRequest : 证书申请结构体
CreateCertificateRequest : 基于证书申请模板生成一个新的证书申请
ParseCertificateRequest : 将DER字节数组转为单个证书申请
 csr.CheckSignature : 检查证书申请c的签名是否有效
*/

//goland:noinspection GoVulnerablePackageImport
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"time"
	"unicode"

	"gitee.com/zhaochuninhefei/gmgo/ecbase"
	"gitee.com/zhaochuninhefei/gmgo/ecdsa_ext"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"

	//gmelliptic "gitee.com/zhaochuninhefei/gmgo/gmcrypto/elliptic"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/sm3"

	// Explicitly import these for their crypto.RegisterHash init side-effects.
	// Keep these as blank imports, even if they're imported above.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/sha3"
)

// PKIX格式公钥结构体，用于x509证书中的公钥部分。
// pkixPublicKey reflects a PKIX public key structure.
// See SubjectPublicKeyInfo in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// ParsePKIXPublicKey 将一个PKIX, ASN.1 DER格式字节数组转为对应的公钥。
// 公钥支持 *sm2.PublicKey, *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey ，
// 这些公钥的pem类型是"PUBLIC KEY"。
//
// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
//
// It returns a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or
// ed25519.PublicKey. More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &pkcs1PublicKey{}); err == nil {
			return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	// 根据pki中的算法oid获取对应的算法
	algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if algo == UnknownPublicKeyAlgorithm {
		return nil, errors.New("x509: unknown public key algorithm")
	}
	return parsePublicKey(algo, &pki)
}

// 将公钥转为字节数组，同时返回对应的pkix算法标识符
func marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *sm2.PublicKey:
		// 将椭圆曲线、公钥座标转换为字节数组
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		// 获取椭圆曲线oid，注意，国标目前没有给出sm2椭圆曲线的oid，这里使用SM2算法的oid代替
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported SM2 curve")
		}
		// 设定公钥算法的oid为sm2算法oid
		publicKeyAlgorithm.Algorithm = oidPublicKeySM2
		var paramBytes []byte
		// 将椭圆曲线oid转为字节数组
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// RFC 3279, Section 2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case *ecdsa_ext.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSAEXT
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case ed25519.PublicKey:
		publicKeyBytes = pub
		publicKeyAlgorithm.Algorithm = oidPublicKeyEd25519
	default:
		return nil, pkix.AlgorithmIdentifier{}, fmt.Errorf("x509: unsupported public key type: %T", pub)
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// MarshalPKIXPublicKey 将公钥转为PKIX, ASN.1 DER格式字节数组。
// 公钥支持 *sm2.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey ，
// 这些公钥的pem类型是"PUBLIC KEY"。
//
// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure
// (see RFC 5280, Section 4.1).
//
// The following key types are currently supported: *rsa.PublicKey, *ecdsa.PublicKey
// and ed25519.PublicKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}
	// 生成PKIX公钥
	pkixPk := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}
	// PKIX公钥字节数组，用于x509证书的公钥部分。
	ret, _ := asn1.Marshal(pkixPk)
	return ret, nil
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// 证书主体，签名内容
// tbs即"To be signed"
type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

//goland:noinspection GoUnusedType
type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

// 初始化加载所有支持的散列组件
func init() {
	RegisterHash(MD4, nil)
	RegisterHash(MD5, md5.New)
	RegisterHash(SHA1, sha1.New)
	RegisterHash(SHA224, sha256.New224)
	RegisterHash(SHA256, sha256.New)
	RegisterHash(SHA384, sha512.New384)
	RegisterHash(SHA512, sha512.New)
	RegisterHash(MD5SHA1, nil)
	// RegisterHash(RIPEMD160, ripemd160.New)
	RegisterHash(SHA3_224, sha3.New224)
	RegisterHash(SHA3_256, sha3.New256)
	RegisterHash(SHA3_384, sha3.New384)
	RegisterHash(SHA3_512, sha3.New512)
	RegisterHash(SHA512_224, sha512.New512_224)
	RegisterHash(SHA512_256, sha512.New512_256)
	RegisterHash(SM3, sm3.New)
}

// SignatureAlgorithm 签名算法
type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota

	MD2WithRSA // Unsupported.
	MD5WithRSA // Only supported for signing, not verification.
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1   // Unsupported.
	DSAWithSHA256 // Unsupported.
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	PureEd25519
	SM2WithSM3         // 签名算法添加国密算法: SM2WithSM3
	ECDSAEXTWithSHA256 // ecdsa_ext 扩展的ECDSA签名算法(支持low-s处理)
	ECDSAEXTWithSHA384 // ecdsa_ext 扩展的ECDSA签名算法(支持low-s处理)
	ECDSAEXTWithSHA512 // ecdsa_ext 扩展的ECDSA签名算法(支持low-s处理)
)

func (algo SignatureAlgorithm) IsECDSAEXT() bool {
	switch algo {
	case ECDSAEXTWithSHA256, ECDSAEXTWithSHA384, ECDSAEXTWithSHA512:
		return true
	default:
		return false
	}
}

func (algo SignatureAlgorithm) isRSAPSS() bool {
	switch algo {
	case SHA256WithRSAPSS, SHA384WithRSAPSS, SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

func (algo SignatureAlgorithm) String() string {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return details.name
		}
	}
	return strconv.Itoa(int(algo))
}

// PublicKeyAlgorithm 公钥算法
type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA // Unsupported.
	ECDSA
	Ed25519
	SM2      // 公钥算法添加SM2
	ECDSAEXT // ecdsa_ext 扩展的ecdsa公钥算法
)

var publicKeyAlgoName = [...]string{
	RSA:      "RSA",
	DSA:      "DSA",
	ECDSA:    "ECDSA",
	Ed25519:  "Ed25519",
	SM2:      "SM2",      // 公钥算法名称定义添加SM2
	ECDSAEXT: "ECDSAEXT", // ecdsa_ext 扩展的ecdsa公钥算法
}

func (algo PublicKeyAlgorithm) String() string {
	if 0 < algo && int(algo) < len(publicKeyAlgoName) {
		return publicKeyAlgoName[algo]
	}
	return strconv.Itoa(int(algo))
}

// OIDs for signature algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
// md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
//
// md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
// sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
// dsaWithSha1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
// ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
// 	  iso(1) member-body(2) us(840) ansi-x962(10045)
//    signatures(4) ecdsa-with-SHA1(1)}
//
//
// RFC 4055 5 PKCS #1 Version 1.5
//
// sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
// sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
// sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
//
// RFC 5758 3.1 DSA Signature Algorithms
//
// dsaWithSha256 OBJECT IDENTIFIER ::= {
//    joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//    csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
//
//
// RFC 8410 3 Curve25519 and Curve448 Algorithm Identifiers
//
// id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }

//goland:noinspection GoUnusedGlobalVariable
var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}

	// 国密相关算法标识定义，参考国密标准`GMT 0006-2012 密码应用标识规范.pdf`
	oidSignatureSM2WithSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	// oidSM3                 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 1}
	oidSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}

	//oidSignatureECDSAEXTWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 5, 3, 2}
	//oidSignatureECDSAEXTWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 5, 3, 3}
	//oidSignatureECDSAEXTWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 5, 3, 4}
)

// 定义支持的签名算法细节
var signatureAlgorithmDetails = []struct {
	algo       SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo PublicKeyAlgorithm
	hash       Hash
	opts       crypto.SignerOpts
}{
	{MD2WithRSA, "MD2-RSA", oidSignatureMD2WithRSA, RSA, Hash(0), Hash(0) /* no value for MD2 */},
	{MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA, RSA, MD5, MD5},
	{SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, RSA, SHA1, SHA1},
	{SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA, RSA, SHA1, SHA1},
	{SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, RSA, SHA256, SHA256},
	{SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, RSA, SHA384, SHA384},
	{SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, RSA, SHA512, SHA512},
	{SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, RSA, SHA256, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       SHA256.HashFunc(),
	}},
	{SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, RSA, SHA384, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       SHA384.HashFunc(),
	}},
	{SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, RSA, SHA512, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       SHA512.HashFunc(),
	}},
	{DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, DSA, SHA1, SHA1},
	{DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, DSA, SHA256, SHA256},
	{ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, ECDSA, SHA1, ecbase.CreateEcSignerOpts(SHA1.HashFunc(), false)},
	{ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, ECDSA, SHA256, ecbase.CreateEcSignerOpts(SHA256.HashFunc(), false)},
	{ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, ECDSA, SHA384, ecbase.CreateEcSignerOpts(SHA384.HashFunc(), false)},
	{ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, ECDSA, SHA512, ecbase.CreateEcSignerOpts(SHA512.HashFunc(), false)},
	{PureEd25519, "Ed25519", oidSignatureEd25519, Ed25519, Hash(0), Hash(0) /* no pre-hashing */},
	// 添加SM2相关签名算法定义, sm2签名算法既可以在内部做散列，也可以在外部做散列，但gmx509固定为在sm2签名算法内部做ZA散列计算,这里的散列算法设置为Hash(0)。
	{SM2WithSM3, "SM2-with-SM3", oidSignatureSM2WithSM3, SM2, Hash(0), sm2.DefaultSM2SignerOption()},
	// 添加ecdsa_ext扩展的ecdsa签名算法定义, 支持low-s处理
	{ECDSAEXTWithSHA256, "ECDSA-EXT-SHA256", oidSignatureECDSAWithSHA256, ECDSAEXT, SHA256, ecbase.CreateEcSignerOpts(SHA256.HashFunc(), true)},
	{ECDSAEXTWithSHA384, "ECDSA-EXT-SHA384", oidSignatureECDSAWithSHA384, ECDSAEXT, SHA384, ecbase.CreateEcSignerOpts(SHA384.HashFunc(), true)},
	{ECDSAEXTWithSHA512, "ECDSA-EXT-SHA512", oidSignatureECDSAWithSHA512, ECDSAEXT, SHA512, ecbase.CreateEcSignerOpts(SHA512.HashFunc(), true)},
}

// hashToPSSParameters contains the DER encoded RSA PSS parameters for the
// SHA256, SHA384, and SHA512 hashes as defined in RFC 3447, Appendix A.2.3.
// The parameters contain the following values:
//   - hashAlgorithm contains the associated hash identifier with NULL parameters
//   - maskGenAlgorithm always contains the default mgf1SHA1 identifier
//   - saltLength contains the length of the associated hash
//   - trailerField always contains the default trailerFieldBC value
var hashToPSSParameters = map[Hash]asn1.RawValue{
	SHA256: {FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 162, 3, 2, 1, 32}},
	SHA384: {FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2, 5, 0, 162, 3, 2, 1, 48}},
	SHA512: {FullBytes: []byte{48, 52, 160, 15, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 161, 28, 48, 26, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 8, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 162, 3, 2, 1, 64}},
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// 根据pkix.AlgorithmIdentifier获取签名算法
func getSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) SignatureAlgorithm {
	if ai.Algorithm.Equal(oidSignatureEd25519) {
		// RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
		if len(ai.Parameters.FullBytes) != 0 {
			return UnknownSignatureAlgorithm
		}
	}

	if !ai.Algorithm.Equal(oidSignatureRSAPSS) {
		// 国密签名算法走该分支
		for _, details := range signatureAlgorithmDetails {
			// TODO ecdsa与ecdsa+ext共用相同的oid，这里取哪一个?
			if ai.Algorithm.Equal(details.oid) {
				return details.algo
			}
		}
		return UnknownSignatureAlgorithm
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return UnknownSignatureAlgorithm
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.
	if (len(params.Hash.Parameters.FullBytes) != 0 && !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes)) ||
		!params.MGF.Algorithm.Equal(oidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		(len(mgf1HashFunc.Parameters.FullBytes) != 0 && !bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes)) ||
		params.TrailerField != 1 {
		return UnknownSignatureAlgorithm
	}

	switch {
	case params.Hash.Algorithm.Equal(oidSHA256) && params.SaltLength == 32:
		return SHA256WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA384) && params.SaltLength == 48:
		return SHA384WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA512) && params.SaltLength == 64:
		return SHA512WithRSAPSS
	}

	return UnknownSignatureAlgorithm
}

// RFC 3279, 2.3 Public Key Algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//
//	rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
// id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//
//	x9-57(10040) x9cm(4) 1 }
//
// # RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
//	id-ecPublicKey OBJECT IDENTIFIER ::= {
//	      iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	// 自定义ecdsa_ext算法标识，`1.3.6.1.4.1`是ISO分配给私人企业的节点，`60387`是向IANA申请到的企业ID(zhaochuninhefei)，`1`是该企业在该节点下的子节点,`2`是该子节点下的ecdsa_ext算法标识
	oidPublicKeyECDSAEXT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 60387, 1, 2}
	oidPublicKeyEd25519  = oidSignatureEd25519
	// SM2算法标识 参考`GMT 0006-2012 密码应用标识规范.pdf`的`附录A 商用密码领域中的相关oID定义`
	oidPublicKeySM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	// // 通过asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})计算得出
	// sm2OidFullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
)

// 根据OID获取公钥算法
func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeySM2):
		return SM2
	case oid.Equal(oidPublicKeyRSA):
		return RSA
	case oid.Equal(oidPublicKeyDSA):
		return DSA
	case oid.Equal(oidPublicKeyECDSA):
		return ECDSA
	case oid.Equal(oidPublicKeyECDSAEXT):
		return ECDSAEXT
	case oid.Equal(oidPublicKeyEd25519):
		return Ed25519
	}
	return UnknownPublicKeyAlgorithm
}

// RFC 5480, 2.1.1.1. Named Curve
//
//	secp224r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
//	secp256r1 OBJECT IDENTIFIER ::= {
//	  iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//	  prime(1) 7 }
//
//	secp384r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
//	secp521r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	// SM2椭圆曲线参数标识 没有查到，用SM2算法标识代替
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// 根据oid获取对应的椭圆曲线参数
func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP256SM2):
		return sm2.P256Sm2()
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

// 根据椭圆曲线参数获取对应的oid
func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case sm2.P256Sm2():
		return oidNamedCurveP256SM2, true
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

// KeyUsage 公钥用途，即证书用途。
// KeyUsage represents the set of actions that are valid for a given key. It's
// a bitmap of the KeyUsage* constants.
type KeyUsage int

const (
	KeyUsageDigitalSignature  KeyUsage = 1 << iota // Digital Signature
	KeyUsageContentCommitment                      // Non Repudiation
	KeyUsageKeyEncipherment                        // Key Encipherment
	KeyUsageDataEncipherment                       // Data Encipherment
	KeyUsageKeyAgreement                           // Key Agreement
	KeyUsageCertSign                               // Certificate Sign
	KeyUsageCRLSign                                // CRL Sign
	KeyUsageEncipherOnly                           // Encipher Only
	KeyUsageDecipherOnly                           // Decipher Only
)

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// ExtKeyUsage 公钥(证书)扩展用途
// ExtKeyUsage represents an extended set of actions that are valid for a given key.
// Each of the ExtKeyUsage* constants define a unique action.
type ExtKeyUsage int

const (
	ExtKeyUsageAny                        ExtKeyUsage = iota // Any Extended Key Usage
	ExtKeyUsageServerAuth                                    // TLS Web Server Authentication
	ExtKeyUsageClientAuth                                    // TLS Web Client Authentication
	ExtKeyUsageCodeSigning                                   // Code Signing
	ExtKeyUsageEmailProtection                               // E-mail Protection
	ExtKeyUsageIPSECEndSystem                                // IPSec End System
	ExtKeyUsageIPSECTunnel                                   // IPSec Tunnel
	ExtKeyUsageIPSECUser                                     // IPSec User
	ExtKeyUsageTimeStamping                                  // Time Stamping
	ExtKeyUsageOCSPSigning                                   // OCSP Signing
	ExtKeyUsageMicrosoftServerGatedCrypto                    // Microsoft Server Gated Crypto
	ExtKeyUsageNetscapeServerGatedCrypto                     // Netscape Server Gated Crypto
	ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}

func oidFromExtKeyUsage(eku ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// Certificate gmx509证书结构体
//
//	A Certificate represents an X.509 certificate.
type Certificate struct {
	// 完整的 ASN1 DER 证书字节数组(证书+签名算法+签名)
	// Complete ASN.1 DER content (certificate, signature algorithm and signature).
	Raw []byte
	// 签名内容的原始 ASN.1 DER字节数组
	// Certificate part of raw ASN.1 DER content.
	RawTBSCertificate []byte
	// SubjectPublicKeyInfo的DER字节数组
	// DER encoded SubjectPublicKeyInfo.
	RawSubjectPublicKeyInfo []byte
	// 证书拥有者的DER字节数组
	// DER encoded Subject
	RawSubject []byte
	// 证书签署者的DER字节数组
	// DER encoded Issuer
	RawIssuer []byte

	// 签名DER字节数组
	Signature []byte
	// 签名算法
	SignatureAlgorithm SignatureAlgorithm

	// 证书拥有者的公钥算法
	PublicKeyAlgorithm PublicKeyAlgorithm
	// 证书拥有者的公钥(证书的核心内容)
	PublicKey interface{}

	// 证书版本
	Version int
	// 证书序列号
	SerialNumber *big.Int
	// 证书签署者(提供私钥对RawTBSCertificate进行签名)
	Issuer pkix.Name
	// 证书拥有者(该证书的核心公钥的拥有者)
	Subject pkix.Name
	// 证书有效期间
	// Validity bounds.
	NotBefore, NotAfter time.Time
	// 证书公钥的用途
	KeyUsage KeyUsage

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	// 公钥扩展用途
	// Sequence of extended key usages.
	ExtKeyUsage []ExtKeyUsage
	// 未知的公钥扩展用途
	// Encountered extended key usages unknown to this package.
	UnknownExtKeyUsage []asn1.ObjectIdentifier

	// 基础约束是否有效，控制 IsCA 与 MaxPathLen 是否有效
	// BasicConstraintsValid indicates whether IsCA, MaxPathLen,
	// and MaxPathLenZero are valid.
	BasicConstraintsValid bool
	// 是否CA证书
	//  IsCA为false时，表示该证书不是CA证书，MaxPathLen无效。
	//  IsCA为true时，表示该证书是CA证书，此时MaxPathLen表示该证书所属证书信任链中的中间CA证书的数量上限。
	IsCA bool
	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// When parsing a certificate, a positive non-zero MaxPathLen
	// means that the field was specified, -1 means it was unset,
	// and MaxPathLenZero being true mean that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	//
	// When generating a certificate, an unset pathLenConstraint
	// can be requested with either MaxPathLen == -1 or using the
	// zero value for both MaxPathLen and MaxPathLenZero.
	MaxPathLen int
	// MaxPathLenZero indicates that BasicConstraintsValid==true
	// and MaxPathLen==0 should be interpreted as an actual
	// maximum path length of zero. Otherwise, that combination is
	// interpreted as MaxPathLen not being set.
	MaxPathLenZero bool

	// 证书拥有者密钥ID
	// 以sm2公钥为例，计算方式为 将椭圆曲线上的公钥座标转换为字节数组再做sm3散列
	SubjectKeyId []byte
	// 证书签署者密钥ID(自签名时，AuthorityKeyId就是自己的SubjectKeyId；由父证书签名时，就是父证书的SubjectKeyId)
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// Subject Alternate Name values. (Note that these values may not be valid
	// if invalid values were contained within a parsed certificate. For
	// example, an element of DNSNames may not be a valid DNS domain name.)
	// go1.15开始废弃CommonName，使用SAN扩展信息。
	// SAN扩展信息由下面四个字段组成。
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL

	// Name constraints
	PermittedDNSDomainsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string

	// CRL Distribution Points
	CRLDistributionPoints []string

	PolicyIdentifiers []asn1.ObjectIdentifier
}

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

// An InsecureAlgorithmError
type InsecureAlgorithmError SignatureAlgorithm

func (e InsecureAlgorithmError) Error() string {
	return fmt.Sprintf("x509: cannot verify signature: insecure algorithm %v", SignatureAlgorithm(e))
}

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

func (c *Certificate) Equal(other *Certificate) bool {
	if c == nil || other == nil {
		return c == other
	}
	return bytes.Equal(c.Raw, other.Raw)
}

func (c *Certificate) hasSANExtension() bool {
	return oidInExtensions(oidExtensionSubjectAltName, c.Extensions)
}

// CheckSignatureFrom 检查对c做的签名是否是父证书拥有者的有效签名(使用父证书中的公钥验签)
// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	if parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return ConstraintViolationError{}
	}

	if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
		return ErrUnsupportedAlgorithm
	}

	// TODO(agl): don't ignore the path length constraint.

	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// CheckSignature 使用c的公钥检查签名是否有效
//   - algo : 签名算法
//   - signed : 签名内容
//   - signature : 签名DER字节数组
//
// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	return checkSignature(algo, signed, signature, c.PublicKey)
}

func (c *Certificate) hasNameConstraints() bool {
	return oidInExtensions(oidExtensionNameConstraints, c.Extensions)
}

func (c *Certificate) getSANExtension() []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

func signaturePublicKeyAlgoMismatchError(expectedPubKeyAlgo PublicKeyAlgorithm, pubKey interface{}) error {
	return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key of type %T", expectedPubKeyAlgo.String(), pubKey)
}

// checkSignature检查签名是否有效
// algo : 签名算法
// signed : 签名内容
// signature : 签名DER字节数组
// publicKey : 签名者公钥
//
// CheckSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(algo SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error) {
	var hashType Hash
	var pubKeyAlgo PublicKeyAlgorithm
	var opts crypto.SignerOpts

	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
			opts = details.opts
			break
		}
	}

	// 关于ecdsa_ext的特殊处理
	if pubKeyAlgo == ECDSAEXT {
		if pubKey, ok := publicKey.(*ecdsa.PublicKey); ok {
			publicKey = ecdsa_ext.ConvPubKeyFromOrigin(pubKey)
		}
	}

	switch hashType {
	case Hash(0):
		// ed25519与sm2不需要对消息做摘要计算
		if pubKeyAlgo != Ed25519 && pubKeyAlgo != SM2 {
			return ErrUnsupportedAlgorithm
		}
	case MD5:
		return InsecureAlgorithmError(algo)
	default:
		if !hashType.Available() {
			return ErrUnsupportedAlgorithm
		}
		h := hashType.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	switch pub := publicKey.(type) {
	case *sm2.PublicKey:
		if pubKeyAlgo != SM2 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if sm2Opts, ok := opts.(*sm2.SM2SignerOption); ok {
			_, err = pub.EcVerify(signed, signature, sm2Opts)
			if err != nil {
				zclog.ErrorStack("sm2 checkSignature 失败, 调用栈如下:")
				return errors.New("x509: SM2 verification failure")
			}
		} else {
			return errors.New("x509: 内建签名算法列表中sm2的opts类型不正确")
		}
		return nil
	case *rsa.PublicKey:
		if pubKeyAlgo != RSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if algo.isRSAPSS() {
			return rsa.VerifyPSS(pub, hashType.HashFunc(), signed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			return rsa.VerifyPKCS1v15(pub, hashType.HashFunc(), signed, signature)
		}
	case *ecdsa.PublicKey:
		if pubKeyAlgo != ECDSA && pubKeyAlgo != ECDSAEXT {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if ecOpts, ok := opts.(ecbase.EcSignerOpts); ok {
			if ecOpts.NeedLowS() {
				// 检查签名s值是否low-s
				isLow, err := ecdsa_ext.IsSigLowS(pub, signature)
				if err != nil {
					return err
				}
				if !isLow {
					return errors.New("ecdsa验签失败, 签名s值不是low-s值")
				}
			}
			if !ecdsa.VerifyASN1(pub, signed, signature) {
				zclog.ErrorStack("ecdsa checkSignature 失败, 调用栈如下:")
				zclog.Errorf("x509: ECDSA verification failure, 公钥SKI: %s, 签名主体: %s, 签名: %s", CreateEllipticSKI(pub.Curve, pub.X, pub.Y), hex.EncodeToString(signed), hex.EncodeToString(signature))
				return errors.New("x509: ECDSA verification failure")
			}
		} else {
			return errors.New("x509: 内建签名算法列表中ecdsa的opts类型不正确")
		}
		return nil
	case *ecdsa_ext.PublicKey:
		if pubKeyAlgo != ECDSA && pubKeyAlgo != ECDSAEXT {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if ecOpts, ok := opts.(ecbase.EcSignerOpts); ok {
			_, err = pub.EcVerify(signed, signature, ecOpts)
			if err != nil {
				zclog.ErrorStack("ecdsa_ext checkSignature 失败, 调用栈如下:")
				zclog.Errorf("x509: ECDSAEXT verification failure, 公钥SKI: %s, 签名主体: %s, 签名: %s", CreateEllipticSKI(pub.Curve, pub.X, pub.Y), hex.EncodeToString(signed), hex.EncodeToString(signature))
				return fmt.Errorf("x509: ECDSAEXT verification failure: %s", err.Error())
			}
		} else {
			return errors.New("x509: 内建签名算法列表中ecdsa的opts类型不正确")
		}
		return nil
	case ed25519.PublicKey:
		if pubKeyAlgo != Ed25519 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !ed25519.Verify(pub, signed, signature) {
			return errors.New("x509: Ed25519 verification failure")
		}
		return nil
	}
	return ErrUnsupportedAlgorithm
}

// CheckCRLSignature 检查证书撤销列表CRL是否由c签名。
// CheckCRLSignature checks that the signature in crl is from c.
func (c *Certificate) CheckCRLSignature(crl *pkix.CertificateList) error {
	algo := getSignatureAlgorithmFromAI(crl.SignatureAlgorithm)
	return c.CheckSignature(algo, crl.TBSCertList.Raw, crl.SignatureValue.RightAlign())
}

type UnhandledCriticalExtension struct{}

func (h UnhandledCriticalExtension) Error() string {
	return "x509: unhandled critical extension"
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// policyQualifiers omitted
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

// x509证书扩展信息oid定义
var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionCRLNumber             = []int{2, 5, 29, 20}

	// 扩展签名算法OID,`1.3.6.1.4.1`是ISO分配给私人企业的节点，`60387`是向IANA申请到的企业ID(zhaochuninhefei),`1`是该企业下的子节点，`1`是该子节点下的扩展签名算法OID
	oidExtensionSignatureAlgorithm = []int{1, 3, 6, 1, 4, 1, 60387, 1, 1}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// oidNotInExtensions reports whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// go1.15开始废弃CommonName，改为使用SAN(Subject Alternative Name)扩展。
// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		if err := isIA5String(name); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		if err := isIA5String(email); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		uriStr := uri.String()
		if err := isIA5String(uriStr); err != nil {
			return nil, err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uriStr)})
	}
	return asn1.Marshal(rawValues)
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

// 构建证书扩展信息
func buildCertExtensions(template *Certificate, subjectIsEmpty bool, authorityKeyId []byte, subjectKeyId []byte) (ret []pkix.Extension, err error) {
	// 扩展信息最大数量增加到11, 放置gmx509定义的签名算法
	ret = make([]pkix.Extension, 11 /* maximum number of elements. */)
	n := 0

	// 添加KeyUsage
	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalKeyUsage(template.KeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	// 添加ExtKeyUsage
	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n], err = marshalExtKeyUsage(template.ExtKeyUsage, template.UnknownExtKeyUsage)
		if err != nil {
			return nil, err
		}
		n++
	}

	// 添加BasicConstraints
	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		ret[n], err = marshalBasicConstraints(template.IsCA, template.MaxPathLen, template.MaxPathLenZero)
		if err != nil {
			return nil, err
		}
		n++
	}

	// 添加subjectKeyId
	if len(subjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(subjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	// 添加authorityKeyId
	if len(authorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{authorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	// 添加authorityInfoAccess
	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	// 添加SAN
	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		// From RFC 5280, Section 4.2.1.6:
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return
		}
		n++
	}

	// 添加PolicyIdentifiers
	if len(template.PolicyIdentifiers) > 0 &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n], err = marshalCertificatePolicies(template.PolicyIdentifiers)
		if err != nil {
			return nil, err
		}
		n++
	}

	// 添加NameConstraints
	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
			var b cryptobyte.Builder

			for _, name := range dns {
				if err = isIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyteasn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyteasn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = isIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyteasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = isIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyteasn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			return b.Bytes()
		}

		permitted, err := serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}

		excluded, err := serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b cryptobyte.Builder
		b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(cryptobyteasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(cryptobyteasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		ret[n].Value, err = b.Bytes()
		if err != nil {
			return nil, err
		}
		n++
	}

	// 添加CRLDistributionPoints
	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function and the list of
	// template fields used in CreateCertificate documentation.

	// TODO 添加gmx509的签名算法 SignatureAlgorithm
	if template.SignatureAlgorithm > 0 && !oidInExtensions(oidExtensionSignatureAlgorithm, template.ExtraExtensions) {
		zclog.Debugf("向x509证书写入扩展签名算法: %s", template.SignatureAlgorithm.String())
		ret[n] = marshalSignatureAlgorithm(template.SignatureAlgorithm)
		n++
	}

	return append(ret[:n], template.ExtraExtensions...), nil
}

func marshalSignatureAlgorithm(signAlg SignatureAlgorithm) pkix.Extension {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, uint32(signAlg))
	ext := pkix.Extension{
		Id:       oidExtensionSignatureAlgorithm,
		Critical: false,
		Value:    val,
	}
	return ext
}

func marshalKeyUsage(ku KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionKeyUsage, Critical: true}

	var a [2]byte
	a[0] = reverseBitsInAByte(byte(ku))
	a[1] = reverseBitsInAByte(byte(ku >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return ext, err
	}
	return ext, nil
}

func marshalExtKeyUsage(extUsages []ExtKeyUsage, unknownUsages []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionExtendedKeyUsage}

	oids := make([]asn1.ObjectIdentifier, len(extUsages)+len(unknownUsages))
	for i, u := range extUsages {
		if oid, ok := oidFromExtKeyUsage(u); ok {
			oids[i] = oid
		} else {
			return ext, errors.New("x509: unknown extended key usage")
		}
	}

	copy(oids[len(extUsages):], unknownUsages)

	var err error
	ext.Value, err = asn1.Marshal(oids)
	if err != nil {
		return ext, err
	}
	return ext, nil
}

func marshalBasicConstraints(isCA bool, maxPathLen int, maxPathLenZero bool) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true}
	// Leaving MaxPathLen as zero indicates that no maximum path
	// length is desired, unless MaxPathLenZero is set. A value of
	// -1 causes encoding/asn1 to omit the value as desired.
	if maxPathLen == 0 && !maxPathLenZero {
		maxPathLen = -1
	}
	var err error
	ext.Value, err = asn1.Marshal(basicConstraints{isCA, maxPathLen})
	if err != nil {
		return ext, nil
	}
	return ext, nil
}

func marshalCertificatePolicies(policyIdentifiers []asn1.ObjectIdentifier) (pkix.Extension, error) {
	ext := pkix.Extension{Id: oidExtensionCertificatePolicies}
	policies := make([]policyInformation, len(policyIdentifiers))
	for i, policy := range policyIdentifiers {
		policies[i].Policy = policy
	}
	var err error
	ext.Value, err = asn1.Marshal(policies)
	if err != nil {
		return ext, err
	}
	return ext, nil
}

func buildCSRExtensions(template *CertificateRequest) ([]pkix.Extension, error) {
	var ret []pkix.Extension

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		ret = append(ret, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}

	// 添加 oidExtensionSignatureAlgorithm
	if template.SignatureAlgorithm > 0 && !oidInExtensions(oidExtensionSignatureAlgorithm, template.ExtraExtensions) {
		ret = append(ret, marshalSignatureAlgorithm(template.SignatureAlgorithm))
	}

	return append(ret, template.ExtraExtensions...), nil
}

// 获取证书主题subject(证书拥有者)的字节数组
func subjectBytes(cert *Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// signingParamsForPublicKey 根据传入的公钥与签名算法获取签名参数(签名算法、散列算法与签名算法参数)
//
//	根据传入的公钥获取默认的签名参数，再根据传入的requestedSigAlgo从内建定义的签名算法列表中检查公钥类型是否匹配，并获取定义好的签名参数，覆盖之前的默认值。
//	当requestedSigAlgo传入0时，即只根据公钥获取默认的签名参数。
//	注意公钥必须是签署者使用的私钥对应的公钥，并不是证书拥有者的公钥。
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo SignatureAlgorithm) (signOpts crypto.SignerOpts, hashFunc Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType PublicKeyAlgorithm

	// 根据pub的公钥类型选择签名算法参数的默认值
	switch pub := pub.(type) {
	case *sm2.PublicKey:
		pubType = SM2
		// 检查曲线是否是sm2曲线
		switch pub.Curve {
		case sm2.P256Sm2():
			// 摘要算法
			hashFunc = Hash(0)
			// 签名算法
			sigAlgo.Algorithm = oidSignatureSM2WithSM3
			// 签名参数 sm2默认做ZA混合散列，不需要low-s处理
			signOpts = sm2.DefaultSM2SignerOption()
		default:
			err = errors.New("x509: unknown SM2 curve")
		}
		// 公钥是sm2时，只有一种签名算法和散列算法可以选择，这里其实可以直接返回。
		// 但为了扩展性以及对内建签名算法列表的检查，还是在后续做一次根据requestedSigAlgo的算法匹配检查。
	case *rsa.PublicKey:
		pubType = RSA
		// 公钥是rsa时并不能确定具体的签名算法与散列算法,这里先准备默认值
		// 传入的requestedSigAlgo非0时，后续会根据签名算法覆盖具体的签名算法与散列算法
		hashFunc = SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.NullRawValue
		signOpts = SHA256
	case *ecdsa.PublicKey:
		pubType = ECDSA
		// 公钥是ecdsa时并不能确定具体的签名算法与散列算法,这里先根据曲线准备默认值
		// 传入的requestedSigAlgo非0时，后续会根据签名算法覆盖具体的签名算法与散列算法
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}
		// ecdsa签名默认不做low-s处理
		signOpts = ecbase.CreateEcSignerOpts(crypto.Hash(hashFunc), false)
	case *ecdsa_ext.PublicKey:
		pubType = ECDSAEXT
		// 公钥是ecdsa时并不能确定具体的签名算法与散列算法,这里先根据曲线准备默认值
		// 传入的requestedSigAlgo非0时，后续会根据签名算法覆盖具体的签名算法与散列算法
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256():
			hashFunc = SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}
		// ecdsa_ext签名默认做low-s处理
		signOpts = ecbase.CreateEcSignerOpts(crypto.Hash(hashFunc), true)

	case ed25519.PublicKey:
		pubType = Ed25519
		sigAlgo.Algorithm = oidSignatureEd25519
		// ed25519不需要事先散列消息
		hashFunc = Hash(0)
		signOpts = hashFunc
		// ed25519与sm2一样，其实到这里已经可以直接返回了。
		// 但为了扩展性以及对内建签名算法列表的检查，还是在后续做一次根据requestedSigAlgo的算法匹配检查。

	default:
		err = errors.New("x509: only SM2, RSA, ECDSA and Ed25519 keys supported")
	}

	if err != nil {
		// 公钥获取参数失败时直接返回错误
		return signOpts, hashFunc, sigAlgo, err
	}
	if requestedSigAlgo == 0 {
		// 如果请求签名算法requestedSigAlgo为0，则直接返回公钥获取到的默认的签名参数
		return signOpts, hashFunc, sigAlgo, err
	}

	// 根据请求签名算法requestedSigAlgo匹配签名算法
	found := false
	for _, details := range signatureAlgorithmDetails {
		// 在内建的signatureAlgorithmDetails中匹配参数requestedSigAlgo
		if details.algo == requestedSigAlgo {
			// 检查匹配到的算法定义是否与传入的公钥类型匹配
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			// 根据匹配到的算法定义覆盖签名算法与散列算法
			sigAlgo.Algorithm, hashFunc, signOpts = details.oid, details.hash, details.opts
			// hashFunc定义为0时检查是不是Ed25519或SM2，只有这两个签名算法不需要事先散列
			if hashFunc == 0 && pubType != Ed25519 && pubType != SM2 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			// RSAPSS系列算法的特殊处理
			if requestedSigAlgo.isRSAPSS() {
				sigAlgo.Parameters = hashToPSSParameters[hashFunc]
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
// just an empty SEQUENCE.
var emptyASN1Subject = []byte{0x30, 0}

// CreateCertificate 根据证书模板生成gmx509证书(v3)的DER字节数组
//   - template : 证书模板
//   - parent : 父证书(自签名时与template传入相同参数即可)
//   - pub : 证书拥有者的公钥
//   - priv : 签名者的私钥(有父证书的话，就是父证书拥有者的私钥)
//
// 当父证书中含有公钥时，必须确保签名者私钥中的公钥与其一致。
//
// CreateCertificate creates a new X.509 v3 certificate based on a template.
// The following members of template are currently used:
//
//   - AuthorityKeyId
//   - BasicConstraintsValid
//   - CRLDistributionPoints
//   - DNSNames
//   - EmailAddresses
//   - ExcludedDNSDomains
//   - ExcludedEmailAddresses
//   - ExcludedIPRanges
//   - ExcludedURIDomains
//   - ExtKeyUsage
//   - ExtraExtensions
//   - IPAddresses
//   - IsCA
//   - IssuingCertificateURL
//   - KeyUsage
//   - MaxPathLen
//   - MaxPathLenZero
//   - NotAfter
//   - NotBefore
//   - OCSPServer
//   - PermittedDNSDomains
//   - PermittedDNSDomainsCritical
//   - PermittedEmailAddresses
//   - PermittedIPRanges
//   - PermittedURIDomains
//   - PolicyIdentifiers
//   - SerialNumber
//   - SignatureAlgorithm
//   - Subject
//   - SubjectKeyId
//   - URIs
//   - UnknownExtKeyUsage
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// certificate to be generated and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// The currently supported key types are *sm2.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey and
// ed25519.PublicKey. pub must be a supported key type, and priv must be a
// crypto.Signer with a supported public key.
//
// The AuthorityKeyId will be taken from the SubjectKeyId of parent, if any,
// unless the resulting certificate is self-signed. Otherwise the value from
// template will be used.
//
// If SubjectKeyId from template is empty and the template is a CA, SubjectKeyId
// will be generated from the hash of the public key.
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, priv interface{}) ([]byte, error) {
	// 检查签名者私钥是否实现了`crypto.Signer`接口
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}
	// 检查模板是否有SerialNumber
	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}
	// 检查MaxPathLen，只有CA证书才允许设置MaxPathLen
	if template.BasicConstraintsValid && !template.IsCA && template.MaxPathLen != -1 && (template.MaxPathLen != 0 || template.MaxPathLenZero) {
		return nil, errors.New("x509: only CAs are allowed to specify MaxPathLen")
	}
	// 根据签名者的公钥以及证书模板的签名算法配置推导本次新证书签名中使用的散列算法与签名算法
	signOpts, hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	// 将新证书拥有者的公钥转为证书公钥字节数组与证书公钥算法 (新证书的核心内容)
	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// 从父证书获取证书签署者字节数组
	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}
	// 从证书模板获取证书拥有者字节数组
	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}
	// 设置签署者密钥ID
	authorityKeyId := template.AuthorityKeyId
	// 非自签名且父证书的SubjectKeyId非空时，将父证书的 SubjectKeyId 设置为新证书的 AuthorityKeyId
	// 即新证书的签署者密钥ID就是父证书的拥有者密钥ID
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}
	// 设置拥有者密钥ID
	subjectKeyId := template.SubjectKeyId
	// 当证书模板没有设置拥有者密钥ID，且本证书为CA证书时，自行计算拥有者密钥ID
	if len(subjectKeyId) == 0 && template.IsCA {
		// SubjectKeyId generated using method 1 in RFC 5280, Section 4.2.1.2:
		//   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		//   value of the BIT STRING subjectPublicKey (excluding the tag,
		//   length, and number of unused bits).
		// 国密改造:改为sm3散列
		// h := sha1.Sum(publicKeyBytes)
		h := sm3.Sm3Sum(publicKeyBytes)
		subjectKeyId = h[:]
	}

	// 检查签署者私钥是否匹配父证书中的公钥
	// Check that the signer's public key matches the private key, if available.
	type publicKey interface {
		Equal(crypto.PublicKey) bool
	}
	if privPub, ok := key.Public().(publicKey); !ok {
		return nil, errors.New("x509: internal error: supported public key does not implement Equal")
	} else if parent.PublicKey != nil && !privPub.Equal(parent.PublicKey) {
		return nil, errors.New("x509: provided PrivateKey doesn't match parent's PublicKey")
	}
	// 构建本证书的扩展信息
	extensions, err := buildCertExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId, subjectKeyId)
	if err != nil {
		return nil, err
	}
	// 构建证书主体，即签名的内容
	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}
	// 证书主体字节数组
	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents
	// 签名前对签名内容做一次散列
	signed := tbsCertContents
	// 签名算法为sm2withsm3时，在其内部做散列，对应的hashFunc为0
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
		// TODO 打印散列算法
		zclog.Debugf("x509.CreateCertificate 对签名内容做散列的算法是: %s", hashFunc.String())
	}
	//// 签名需要将散列函数作为signerOpts传入
	//var signerOpts crypto.SignerOpts = hashFunc
	//// rsa的特殊处理
	//if template.SignatureAlgorithm != 0 && template.SignatureAlgorithm.isRSAPSS() {
	//	signerOpts = &rsa.PSSOptions{
	//		SaltLength: rsa.PSSSaltLengthEqualsHash,
	//		Hash:       hashFunc.HashFunc(),
	//	}
	//}
	// 签名
	var signature []byte
	signature, err = key.Sign(rand, signed, signOpts)
	if err != nil {
		return nil, err
	}
	// ecdsa签名做low-s处理
	if ecSignOpts, ok := signOpts.(ecbase.EcSignerOpts); ok {
		if ecSignOpts.NeedLowS() {
			// 对于ecdsa签名算法，如果指定了要做 low-s处理，那么这里需要针对使用`*ecdsa.PrivateKey`的场景做补丁处理。
			// 而如果使用的是`*ecdsa_ext.PrivateKey`,其内部已经根据EcSignerOpts参数做过low-s了，这里不需要额外再做一次。
			if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
				zclog.Debugln("x509证书签署后尝试low-s处理")
				doLow := false
				doLow, signature, err = ecdsa_ext.SignatureToLowS(&ecdsaPriv.PublicKey, signature)
				if err != nil {
					return nil, err
				}
				if doLow {
					zclog.Debugln("x509证书签署后完成low-s处理")
				}
			}
		}
	}
	zclog.Debugf("x509签名结果, 签名内容: %s, 签名: %s", hex.EncodeToString(signed), hex.EncodeToString(signature))
	// 构建证书(证书主体 + 签名算法 + 签名)，并转为字节数组
	signedCert, err := asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, err
	}

	// Check the signature to ensure the crypto.Signer behaved correctly.
	// We skip this check if the signature algorithm is MD5WithRSA as we
	// only support this algorithm for signing, and not verification.
	if sigAlg := getSignatureAlgorithmFromAI(signatureAlgorithm); sigAlg != MD5WithRSA {
		// 检查签名是否正确，注意此时使用签署者的公钥来验签
		if err := checkSignature(sigAlg, c.Raw, signature, key.Public()); err != nil {
			return nil, fmt.Errorf("x509: signature over certificate returned by signer is invalid: %w", err)
		}
	}

	return signedCert, nil
}

// CRL 证书吊销列表(Certificate Revocation List) 相关操作

// pemCRLPrefix is the magic string that indicates that we have a PEM encoded
// CRL.
var pemCRLPrefix = []byte("-----BEGIN X509 CRL")

// pemType is the type of a PEM encoded CRL.
var pemType = "X509 CRL"

// ParseCRL 将给定的字节数组(PEM/DER)转为CRL。
// ParseCRL parses a CRL from the given bytes. It's often the case that PEM
// encoded CRLs will appear where they should be DER encoded, so this function
// will transparently handle PEM encoding as long as there isn't any leading
// garbage.
func ParseCRL(crlBytes []byte) (*pkix.CertificateList, error) {
	if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
		block, _ := pem.Decode(crlBytes)
		if block != nil && block.Type == pemType {
			crlBytes = block.Bytes
		}
	}
	return ParseDERCRL(crlBytes)
}

// ParseDERCRL 将DER字节数组转为CRL。
// ParseDERCRL parses a DER encoded CRL from the given bytes.
func ParseDERCRL(derBytes []byte) (*pkix.CertificateList, error) {
	certList := new(pkix.CertificateList)
	if rest, err := asn1.Unmarshal(derBytes, certList); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after CRL")
	}
	return certList, nil
}

// CreateCRL 创建一个CRL
//   - priv : 撤销证书列表的签署者私钥, 如果是ecdsa私钥，那么这里并不支持low-s处理，验签时对应也不需要low-s检查。
//   - revokedCerts : 撤销证书列表
//
// CreateCRL returns a DER encoded CRL, signed by this Certificate, that
// contains the given list of revoked certificates.
//
// Note: this method does not generate an RFC 5280 conformant X.509 v2 CRL.
// To generate a standards compliant CRL, use CreateRevocationList instead.
func (c *Certificate) CreateCRL(rand io.Reader, priv interface{}, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}
	// 使用签署者的公钥获取签名参数: 散列函数与签名算法
	signOpts, hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(key.Public(), 0)
	if err != nil {
		return nil, err
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]pkix.RevokedCertificate, len(revokedCerts))
	for i, rc := range revokedCerts {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	tbsCertList := pkix.TBSCertificateList{
		Version:             1,
		Signature:           signatureAlgorithm,
		Issuer:              c.Subject.ToRDNSequence(),
		ThisUpdate:          now.UTC(),
		NextUpdate:          expiry.UTC(),
		RevokedCertificates: revokedCertsUTC,
	}

	// Authority Key Id
	if len(c.SubjectKeyId) > 0 {
		var aki pkix.Extension
		aki.Id = oidExtensionAuthorityKeyId
		aki.Value, err = asn1.Marshal(authKeyId{Id: c.SubjectKeyId})
		if err != nil {
			return
		}
		tbsCertList.Extensions = append(tbsCertList.Extensions, aki)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return
	}

	signed := tbsCertListContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	var signature []byte
	signature, err = key.Sign(rand, signed, signOpts)
	if err != nil {
		return
	}
	//// ecdsa签名做low-s处理
	//if ecSignOpts, ok := signOpts.(ecbase.EcSignerOpts); ok {
	//	if ecSignOpts.NeedLowS() {
	//		// 对于ecdsa签名算法，如果指定了要做 low-s处理，那么这里需要针对使用`*ecdsa.PrivateKey`的场景做补丁处理。
	//		// 而如果使用的是`*ecdsa_ext.PrivateKey`,其内部已经根据EcSignerOpts参数做过low-s了，这里不需要额外再做一次。
	//		if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
	//			zclog.Debugln("x509证书签署后尝试low-s处理")
	//			doLow := false
	//			doLow, signature, err = ecdsa_ext.SignatureToLowS(&ecdsaPriv.PublicKey, signature)
	//			if err != nil {
	//				return nil, err
	//			}
	//			if doLow {
	//				zclog.Debugln("x509证书签署后完成low-s处理")
	//			}
	//		}
	//	}
	//}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// CertificateRequest 证书申请
// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject               []byte // DER encoded Subject.

	Version            int
	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	Subject pkix.Name

	// Attributes contains the CSR attributes that can parse as
	// pkix.AttributeTypeAndValueSET.
	//
	// Deprecated: Use Extensions and ExtraExtensions instead for parsing and
	// generating the requestedExtensions attribute.
	Attributes []pkix.AttributeTypeAndValueSET

	// Extensions contains all requested extensions, in raw form. When parsing
	// CSRs, this can be used to extract extensions that are not parsed by this
	// package.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any CSR
	// marshaled by CreateCertificateRequest. Values override any extensions
	// that would otherwise be produced based on the other fields but are
	// overridden by any extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated by ParseCertificateRequest,
	// see Extensions instead.
	ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	// go1.15开始废弃CommonName，使用SAN扩展信息。
	// SAN扩展信息由下面四个字段组成。
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []*url.URL
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidExtensionRequest is a PKCS #9 OBJECT IDENTIFIER that indicates requested
// extensions in a CSR.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}

// parseRawAttributes Unmarshals RawAttributes into AttributeTypeAndValueSETs.
func parseRawAttributes(rawAttributes []asn1.RawValue) []pkix.AttributeTypeAndValueSET {
	var attributes []pkix.AttributeTypeAndValueSET
	for _, rawAttr := range rawAttributes {
		var attr pkix.AttributeTypeAndValueSET
		rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
		// Ignore attributes that don't parse into pkix.AttributeTypeAndValueSET
		// (i.e.: challengePassword or unstructuredName).
		if err == nil && len(rest) == 0 {
			attributes = append(attributes, attr)
		}
	}
	return attributes
}

// parseCSRExtensions parses the attributes from a CSR and extracts any
// requested extensions.
func parseCSRExtensions(rawAttributes []asn1.RawValue) ([]pkix.Extension, error) {
	// pkcs10Attribute reflects the Attribute structure from RFC 2986, Section 4.1.
	type pkcs10Attribute struct {
		Id     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}

	var ret []pkix.Extension
	for _, rawAttr := range rawAttributes {
		var attr pkcs10Attribute
		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 || len(attr.Values) == 0 {
			// Ignore attributes that don't parse.
			continue
		}

		if !attr.Id.Equal(oidExtensionRequest) {
			continue
		}

		var extensions []pkix.Extension
		if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &extensions); err != nil {
			return nil, err
		}
		ret = append(ret, extensions...)
	}

	return ret, nil
}

// CreateCertificateRequest 基于证书申请模板生成一个新的证书申请。
// 注意，证书申请内部的公钥信息就是签名者的公钥，即，证书申请是申请者自签名的。
//   - rand : 随机数获取用
//   - template : 证书申请模板
//   - priv : 申请者私钥
//
// CreateCertificateRequest creates a new certificate request based on a
// template. The following members of template are used:
//
//   - SignatureAlgorithm
//   - Subject
//   - DNSNames
//   - EmailAddresses
//   - IPAddresses
//   - URIs
//   - ExtraExtensions
//   - Attributes (deprecated)
//
// priv is the private key to sign the CSR with, and the corresponding public
// key will be included in the CSR. It must implement crypto.Signer and its
// Public() method must return a *rsa.PublicKey or a *ecdsa.PublicKey or a
// ed25519.PublicKey. (A *rsa.PrivateKey, *ecdsa.PrivateKey or
// ed25519.PrivateKey satisfies this.)
//
// The returned slice is the certificate request in DER encoding.
func CreateCertificateRequest(rand io.Reader, template *CertificateRequest, priv interface{}) (csr []byte, err error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}
	// 根据申请者的公钥与模板的签名算法获取散列函数与签名算法
	var signOpts crypto.SignerOpts
	var hashFunc Hash
	var sigAlgo pkix.AlgorithmIdentifier
	signOpts, hashFunc, sigAlgo, err = signingParamsForPublicKey(key.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	// 根据申请者的公钥生成证书申请的核心内容:公钥字节数组与公钥算法
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	// 构建证书申请扩展内容
	extensions, err := buildCSRExtensions(template)
	if err != nil {
		return nil, err
	}
	// Make a copy of template.Attributes because we may alter it below.
	//goland:noinspection GoDeprecation
	attributes := make([]pkix.AttributeTypeAndValueSET, 0, len(template.Attributes))
	//goland:noinspection GoDeprecation
	for _, attr := range template.Attributes {
		values := make([][]pkix.AttributeTypeAndValue, len(attr.Value))
		copy(values, attr.Value)
		attributes = append(attributes, pkix.AttributeTypeAndValueSET{
			Type:  attr.Type,
			Value: values,
		})
	}
	extensionsAppended := false
	if len(extensions) > 0 {
		// Append the extensions to an existing attribute if possible.
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}
			// specifiedExtensions contains all the extensions that we
			// found specified via template.Attributes.
			specifiedExtensions := make(map[string]bool)
			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}
			newValue := make([]pkix.AttributeTypeAndValue, 0, len(atvSet.Value[0])+len(extensions))
			newValue = append(newValue, atvSet.Value[0]...)
			for _, e := range extensions {
				if specifiedExtensions[e.Id.String()] {
					// Attributes already contained a value for
					// this extension and it takes priority.
					continue
				}
				newValue = append(newValue, pkix.AttributeTypeAndValue{
					// There is no place for the critical
					// flag in an AttributeTypeAndValue.
					Type:  e.Id,
					Value: e.Value,
				})
			}
			atvSet.Value[0] = newValue
			extensionsAppended = true
			break
		}
	}
	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return
	}
	// If not included in attributes, add a new attribute for the
	// extensions.
	if len(extensions) > 0 && !extensionsAppended {
		attr := struct {
			Type  asn1.ObjectIdentifier
			Value [][]pkix.Extension `asn1:"set"`
		}{
			Type:  oidExtensionRequest,
			Value: [][]pkix.Extension{extensions},
		}
		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, errors.New("x509: failed to serialise extensions attribute: " + err.Error())
		}
		var rawValue asn1.RawValue
		if _, err := asn1.Unmarshal(b, &rawValue); err != nil {
			return nil, err
		}
		rawAttributes = append(rawAttributes, rawValue)
	}
	// 证书申请者信息
	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
	}
	// 签名内容
	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}
	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents
	// 签名内容进行一次散列
	signed := tbsCSRContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}
	// 签名，注意，证书申请都是申请者自签名。
	var signature []byte
	signature, err = key.Sign(rand, signed, signOpts)
	if err != nil {
		return
	}
	// ecdsa签名做low-s处理
	if ecSignOpts, ok := signOpts.(ecbase.EcSignerOpts); ok {
		if ecSignOpts.NeedLowS() {
			// 对于ecdsa签名算法，如果指定了要做 low-s处理，那么这里需要针对使用`*ecdsa.PrivateKey`的场景做补丁处理。
			// 而如果使用的是`*ecdsa_ext.PrivateKey`,其内部已经根据EcSignerOpts参数做过low-s了，这里不需要额外再做一次。
			if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
				zclog.Debugln("x509证书签署后尝试low-s处理")
				doLow := false
				doLow, signature, err = ecdsa_ext.SignatureToLowS(&ecdsaPriv.PublicKey, signature)
				if err != nil {
					return nil, err
				}
				if doLow {
					zclog.Debugln("x509证书签署后完成low-s处理")
				}
			}
		}
	}
	// 返回证书申请DER字节数组
	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

// ParseCertificateRequest 将DER字节数组转为单个证书申请。
// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateRequest(&csr)
}

func parseCertificateRequest(in *certificateRequest) (*CertificateRequest, error) {
	//goland:noinspection GoDeprecation
	out := &CertificateRequest{
		Raw:                      in.Raw,
		RawTBSCertificateRequest: in.TBSCSR.Raw,
		RawSubjectPublicKeyInfo:  in.TBSCSR.PublicKey.Raw,
		RawSubject:               in.TBSCSR.Subject.FullBytes,

		Signature:          in.SignatureValue.RightAlign(),
		SignatureAlgorithm: getSignatureAlgorithmFromAI(in.SignatureAlgorithm),

		PublicKeyAlgorithm: getPublicKeyAlgorithmFromOID(in.TBSCSR.PublicKey.Algorithm.Algorithm),

		Version:    in.TBSCSR.Version,
		Attributes: parseRawAttributes(in.TBSCSR.RawAttributes),
	}

	var err error
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.TBSCSR.PublicKey)
	if err != nil {
		return nil, err
	}

	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 Subject")
	}

	out.Subject.FillFromRDNSequence(&subject)

	if out.Extensions, err = parseCSRExtensions(in.TBSCSR.RawAttributes); err != nil {
		return nil, err
	}

	for _, extension := range out.Extensions {
		switch {
		case extension.Id.Equal(oidExtensionSubjectAltName):
			out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(extension.Value)
			if err != nil {
				return nil, err
			}
		case extension.Id.Equal(oidExtensionSignatureAlgorithm):
			// SignatureAlgorithm反序列化操作
			signAlg := SignatureAlgorithm(binary.BigEndian.Uint32(extension.Value))
			if signAlg > 0 {
				out.SignatureAlgorithm = signAlg
			}
		}
	}

	return out, nil
}

// CheckSignature 检查证书申请c的签名是否有效
// CheckSignature reports whether the signature on c is valid.
func (c *CertificateRequest) CheckSignature() error {
	return checkSignature(c.SignatureAlgorithm, c.RawTBSCertificateRequest, c.Signature, c.PublicKey)
}

// ToX509Certificate gmx509转x509
func (c *Certificate) ToX509Certificate() *x509.Certificate {
	x509cert := &x509.Certificate{
		Raw:                         c.Raw,
		RawTBSCertificate:           c.RawTBSCertificate,
		RawSubjectPublicKeyInfo:     c.RawSubjectPublicKeyInfo,
		RawSubject:                  c.RawSubject,
		RawIssuer:                   c.RawIssuer,
		Signature:                   c.Signature,
		SignatureAlgorithm:          x509.SignatureAlgorithm(c.SignatureAlgorithm),
		PublicKeyAlgorithm:          x509.PublicKeyAlgorithm(c.PublicKeyAlgorithm),
		PublicKey:                   c.PublicKey,
		Version:                     c.Version,
		SerialNumber:                c.SerialNumber,
		Issuer:                      c.Issuer,
		Subject:                     c.Subject,
		NotBefore:                   c.NotBefore,
		NotAfter:                    c.NotAfter,
		KeyUsage:                    x509.KeyUsage(c.KeyUsage),
		Extensions:                  c.Extensions,
		ExtraExtensions:             c.ExtraExtensions,
		UnhandledCriticalExtensions: c.UnhandledCriticalExtensions,
		// ExtKeyUsage:	[]x509.ExtKeyUsage(c.ExtKeyUsage) ,
		UnknownExtKeyUsage:    c.UnknownExtKeyUsage,
		BasicConstraintsValid: c.BasicConstraintsValid,
		IsCA:                  c.IsCA,
		MaxPathLen:            c.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: c.MaxPathLenZero,
		SubjectKeyId:   c.SubjectKeyId,
		AuthorityKeyId: c.AuthorityKeyId,
		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            c.OCSPServer,
		IssuingCertificateURL: c.IssuingCertificateURL,
		// Subject Alternate Name values
		DNSNames:       c.DNSNames,
		EmailAddresses: c.EmailAddresses,
		IPAddresses:    c.IPAddresses,
		URIs:           c.URIs,
		// Name constraints
		PermittedDNSDomainsCritical: c.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         c.PermittedDNSDomains,
		ExcludedDNSDomains:          c.ExcludedDNSDomains,
		PermittedIPRanges:           c.PermittedIPRanges,
		ExcludedIPRanges:            c.ExcludedIPRanges,
		PermittedEmailAddresses:     c.PermittedEmailAddresses,
		ExcludedEmailAddresses:      c.ExcludedEmailAddresses,
		PermittedURIDomains:         c.PermittedURIDomains,
		ExcludedURIDomains:          c.ExcludedURIDomains,
		// CRL Distribution Points
		CRLDistributionPoints: c.CRLDistributionPoints,
		PolicyIdentifiers:     c.PolicyIdentifiers,
	}

	for _, val := range c.ExtKeyUsage {
		x509cert.ExtKeyUsage = append(x509cert.ExtKeyUsage, x509.ExtKeyUsage(val))
	}

	return x509cert
}

// FromX509Certificate x509转gmx509
func (c *Certificate) FromX509Certificate(x509Cert *x509.Certificate) {
	c.Raw = x509Cert.Raw
	c.RawTBSCertificate = x509Cert.RawTBSCertificate
	c.RawSubjectPublicKeyInfo = x509Cert.RawSubjectPublicKeyInfo
	c.RawSubject = x509Cert.RawSubject
	c.RawIssuer = x509Cert.RawIssuer
	c.Signature = x509Cert.Signature
	c.SignatureAlgorithm = SM2WithSM3
	c.PublicKeyAlgorithm = PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm)
	c.PublicKey = x509Cert.PublicKey
	c.Version = x509Cert.Version
	c.SerialNumber = x509Cert.SerialNumber
	c.Issuer = x509Cert.Issuer
	c.Subject = x509Cert.Subject
	c.NotBefore = x509Cert.NotBefore
	c.NotAfter = x509Cert.NotAfter
	c.KeyUsage = KeyUsage(x509Cert.KeyUsage)
	c.Extensions = x509Cert.Extensions
	c.ExtraExtensions = x509Cert.ExtraExtensions
	c.UnhandledCriticalExtensions = x509Cert.UnhandledCriticalExtensions
	c.UnknownExtKeyUsage = x509Cert.UnknownExtKeyUsage
	c.BasicConstraintsValid = x509Cert.BasicConstraintsValid
	c.IsCA = x509Cert.IsCA
	c.MaxPathLen = x509Cert.MaxPathLen
	c.MaxPathLenZero = x509Cert.MaxPathLenZero
	c.SubjectKeyId = x509Cert.SubjectKeyId
	c.AuthorityKeyId = x509Cert.AuthorityKeyId
	c.OCSPServer = x509Cert.OCSPServer
	c.IssuingCertificateURL = x509Cert.IssuingCertificateURL
	c.DNSNames = x509Cert.DNSNames
	c.EmailAddresses = x509Cert.EmailAddresses
	c.IPAddresses = x509Cert.IPAddresses
	c.URIs = x509Cert.URIs
	c.PermittedDNSDomainsCritical = x509Cert.PermittedDNSDomainsCritical
	c.PermittedDNSDomains = x509Cert.PermittedDNSDomains
	c.ExcludedDNSDomains = x509Cert.ExcludedDNSDomains
	c.PermittedIPRanges = x509Cert.PermittedIPRanges
	c.ExcludedIPRanges = x509Cert.ExcludedIPRanges
	c.PermittedEmailAddresses = x509Cert.PermittedEmailAddresses
	c.ExcludedEmailAddresses = x509Cert.ExcludedEmailAddresses
	c.PermittedURIDomains = x509Cert.PermittedURIDomains
	c.ExcludedURIDomains = x509Cert.ExcludedURIDomains
	c.CRLDistributionPoints = x509Cert.CRLDistributionPoints
	c.PolicyIdentifiers = x509Cert.PolicyIdentifiers
	for _, val := range x509Cert.ExtKeyUsage {
		c.ExtKeyUsage = append(c.ExtKeyUsage, ExtKeyUsage(val))
	}
}

// RevocationList contains the fields used to create an X.509 v2 Certificate
// Revocation list with CreateRevocationList.
type RevocationList struct {
	// SignatureAlgorithm is used to determine the signature algorithm to be
	// used when signing the CRL. If 0 the default algorithm for the signing
	// key will be used.
	SignatureAlgorithm SignatureAlgorithm

	// RevokedCertificates is used to populate the revokedCertificates
	// sequence in the CRL, it may be empty. RevokedCertificates may be nil,
	// in which case an empty CRL will be created.
	RevokedCertificates []pkix.RevokedCertificate

	// Number is used to populate the X.509 v2 cRLNumber extension in the CRL,
	// which should be a monotonically increasing sequence number for a given
	// CRL scope and CRL issuer.
	Number *big.Int
	// ThisUpdate is used to populate the thisUpdate field in the CRL, which
	// indicates the issuance date of the CRL.
	ThisUpdate time.Time
	// NextUpdate is used to populate the nextUpdate field in the CRL, which
	// indicates the date by which the next CRL will be issued. NextUpdate
	// must be greater than ThisUpdate.
	NextUpdate time.Time
	// ExtraExtensions contains any additional extensions to add directly to
	// the CRL.
	ExtraExtensions []pkix.Extension
}

// CreateRevocationList 创建x509 v2版本的证书撤销列表
//
//	注意，私钥是ecdsa类型时，不支持low-s处理。
//
// creates a new X.509 v2 Certificate Revocation List,
// according to RFC 5280, based on template.
//
// The CRL is signed by priv which should be the private key associated with
// the public key in the issuer certificate.
//
// The issuer may not be nil, and the crlSign bit must be set in KeyUsage in
// order to use it as a CRL issuer.
//
// The issuer distinguished name CRL field and authority key identifier
// extension are populated using the issuer certificate. issuer must have
// SubjectKeyId set.
func CreateRevocationList(rand io.Reader, template *RevocationList, issuer *Certificate, priv crypto.Signer) ([]byte, error) {
	if template == nil {
		return nil, errors.New("x509: template can not be nil")
	}
	if issuer == nil {
		return nil, errors.New("x509: issuer can not be nil")
	}
	if (issuer.KeyUsage & KeyUsageCRLSign) == 0 {
		return nil, errors.New("x509: issuer must have the crlSign key usage bit set")
	}
	if len(issuer.SubjectKeyId) == 0 {
		return nil, errors.New("x509: issuer certificate doesn't contain a subject key identifier")
	}
	if template.NextUpdate.Before(template.ThisUpdate) {
		return nil, errors.New("x509: template.ThisUpdate is after template.NextUpdate")
	}
	if template.Number == nil {
		return nil, errors.New("x509: template contains nil Number field")
	}

	signOpts, hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]pkix.RevokedCertificate, len(template.RevokedCertificates))
	for i, rc := range template.RevokedCertificates {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	aki, err := asn1.Marshal(authKeyId{Id: issuer.SubjectKeyId})
	if err != nil {
		return nil, err
	}
	crlNum, err := asn1.Marshal(template.Number)
	if err != nil {
		return nil, err
	}

	tbsCertList := pkix.TBSCertificateList{
		Version:    1, // v2
		Signature:  signatureAlgorithm,
		Issuer:     issuer.Subject.ToRDNSequence(),
		ThisUpdate: template.ThisUpdate.UTC(),
		NextUpdate: template.NextUpdate.UTC(),
		Extensions: []pkix.Extension{
			{
				Id:    oidExtensionAuthorityKeyId,
				Value: aki,
			},
			{
				Id:    oidExtensionCRLNumber,
				Value: crlNum,
			},
		},
	}
	if len(revokedCertsUTC) > 0 {
		tbsCertList.RevokedCertificates = revokedCertsUTC
	}

	//// 添加oidExtensionSignatureAlgorithm
	//if template.SignatureAlgorithm > 0 && !oidInExtensions(oidExtensionSignatureAlgorithm, template.ExtraExtensions) {
	//	tbsCertList.Extensions = append(tbsCertList.Extensions, marshalSignatureAlgorithm(template.SignatureAlgorithm))
	//}

	if len(template.ExtraExtensions) > 0 {
		tbsCertList.Extensions = append(tbsCertList.Extensions, template.ExtraExtensions...)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return nil, err
	}

	input := tbsCertListContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(tbsCertListContents)
		input = h.Sum(nil)
	}
	//var signerOpts crypto.SignerOpts = hashFunc
	//if template.SignatureAlgorithm.isRSAPSS() {
	//	signerOpts = &rsa.PSSOptions{
	//		SaltLength: rsa.PSSSaltLengthEqualsHash,
	//		Hash:       hashFunc.HashFunc(),
	//	}
	//}

	signature, err := priv.Sign(rand, input, signOpts)
	if err != nil {
		return nil, err
	}
	//// ecdsa签名做low-s处理
	//if ecSignOpts, ok := signOpts.(ecbase.EcSignerOpts); ok {
	//	if ecSignOpts.NeedLowS() {
	//		// 对于ecdsa签名算法，如果指定了要做 low-s处理，那么这里需要针对使用`*ecdsa.PrivateKey`的场景做补丁处理。
	//		// 而如果使用的是`*ecdsa_ext.PrivateKey`,其内部已经根据EcSignerOpts参数做过low-s了，这里不需要额外再做一次。
	//		if ecdsaPriv, ok := priv.(*ecdsa.PrivateKey); ok {
	//			zclog.Debugln("x509证书签署后尝试low-s处理")
	//			doLow := false
	//			doLow, signature, err = ecdsa_ext.SignatureToLowS(&ecdsaPriv.PublicKey, signature)
	//			if err != nil {
	//				return nil, err
	//			}
	//			if doLow {
	//				zclog.Debugln("x509证书签署后完成low-s处理")
	//			}
	//		}
	//	}
	//}

	return asn1.Marshal(pkix.CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}
