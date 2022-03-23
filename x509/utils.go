package x509

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

func ReadPrivateKeyFromPem(privateKeyPem []byte, pwd []byte) (*sm2.PrivateKey, error) {
	var block *pem.Block
	block, _ = pem.Decode(privateKeyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}
	priv, err := ParsePKCS8PrivateKey(block.Bytes, pwd)
	return priv, err
}

func WritePrivateKeyToPem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	var block *pem.Block
	der, err := MarshalSm2PrivateKey(key, pwd) //Convert private key to DER format
	if err != nil {
		return nil, err
	}
	if pwd != nil {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

func ReadPublicKeyFromPem(publicKeyPem []byte) (*sm2.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	return ParseSm2PublicKey(block.Bytes)
}

func WritePublicKeyToPem(key *sm2.PublicKey) ([]byte, error) {
	der, err := MarshalSm2PublicKey(key) //Convert publick key to DER format
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	certPem := pem.EncodeToMemory(block)
	return certPem, nil
}

// 读取16进制的数字D作为私钥，Dhex是sm2私钥的16进制字符串，对应sm2.PrivateKey.D
func ReadPrivateKeyFromHex(Dhex string) (*sm2.PrivateKey, error) {
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

func WritePrivateKeyToHex(key *sm2.PrivateKey) string {
	return key.D.Text(16)
}

func ReadPublicKeyFromHex(Qhex string) (*sm2.PublicKey, error) {
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

func WritePublicKeyToHex(key *sm2.PublicKey) string {
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

func ReadCertificateRequestFromPem(certPem []byte) (*CertificateRequest, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificateRequest(block.Bytes)
}

func CreateCertificateRequestToPem(template *CertificateRequest, signer crypto.Signer) ([]byte, error) {
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

func ReadCertificateFromPem(certPem []byte) (*Certificate, error) {
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate request")
	}
	return ParseCertificate(block.Bytes)
}

// CreateCertificate creates a new certificate based on a template. The
// following members of template are used: SerialNumber, Subject, NotBefore,
// NotAfter, KeyUsage, ExtKeyUsage, UnknownExtKeyUsage, BasicConstraintsValid,
// IsCA, MaxPathLen, SubjectKeyId, DNSNames, PermittedDNSDomainsCritical,
// PermittedDNSDomains, SignatureAlgorithm.
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// All keys types that are implemented via crypto.Signer are supported (This
// includes *rsa.PublicKey and *ecdsa.PublicKey.)

// 根据证书模板与父证书生成新证书
// template : 证书模板 *gmx509.Certificate
// parent : 父证书 *gmx509.Certificate
// publicKey : 新证书拥有者的公钥 (sm2/ecdsa/rsa)
// signer : 签名者(私钥)
func CreateCertificate(template, parent *Certificate, publicKey interface{}, signer crypto.Signer) ([]byte, error) {
	return CreateCertificateFromReader(rand.Reader, template, parent, publicKey, signer)
	// if template.SerialNumber == nil {
	// 	return nil, errors.New("x509: no SerialNumber given")
	// }
	// // 根据 签名者的公钥以及证书模板的签名算法配置推导本次新证书签名中使用的散列算法与签名算法
	// hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(signer.Public(), template.SignatureAlgorithm)
	// if err != nil {
	// 	return nil, err
	// }
	// // 将新证书拥有者的公钥转为证书公钥字节流与证书公钥算法 (新证书的核心内容)
	// publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(publicKey)
	// if err != nil {
	// 	return nil, err
	// }
	// // 从父证书获取证书签署者字节流
	// asn1Issuer, err := subjectBytes(parent)
	// if err != nil {
	// 	return nil, err
	// }
	// // 从证书模板获取证书拥有者字节流
	// asn1Subject, err := subjectBytes(template)
	// if err != nil {
	// 	return nil, err
	// }
	// // 非自签名时，将父证书的 SubjectKeyId 设置为新证书的 AuthorityKeyId
	// // 即新证书的签署者密钥ID就是父证书的拥有者密钥ID
	// if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
	// 	template.AuthorityKeyId = parent.SubjectKeyId
	// }
	// // 创建证书扩展信息
	// extensions, err := buildExtensions(template)
	// if err != nil {
	// 	return nil, err
	// }
	// // 生成证书的被签名内容
	// encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	// c := tbsCertificate{
	// 	Version:            2,
	// 	SerialNumber:       template.SerialNumber,
	// 	SignatureAlgorithm: signatureAlgorithm,
	// 	Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
	// 	Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
	// 	Subject:            asn1.RawValue{FullBytes: asn1Subject},
	// 	PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
	// 	Extensions:         extensions,
	// }
	// // 将被签名内容转为字节流
	// tbsCertContents, err := asn1.Marshal(c)
	// if err != nil {
	// 	return nil, err
	// }
	// c.Raw = tbsCertContents
	// // 根据签名算法决定是否需要对被签名内容做摘要
	// digest := tbsCertContents
	// switch template.SignatureAlgorithm {
	// case SM2WithSM3, SM2WithSHA1, SM2WithSHA256:
	// 	break
	// default:
	// 	h := hashFunc.New()
	// 	h.Write(tbsCertContents)
	// 	digest = h.Sum(nil)
	// }
	// // 设置 signerOpts 指定摘要算法
	// var signerOpts crypto.SignerOpts
	// signerOpts = hashFunc
	// // rsa的特殊处理
	// if template.SignatureAlgorithm != 0 && template.SignatureAlgorithm.isRSAPSS() {
	// 	signerOpts = &rsa.PSSOptions{
	// 		SaltLength: rsa.PSSSaltLengthEqualsHash,
	// 		Hash:       crypto.Hash(hashFunc),
	// 	}
	// }
	// // 签名
	// var signature []byte
	// signature, err = signer.Sign(rand.Reader, digest, signerOpts)
	// if err != nil {
	// 	return nil, err
	// }
	// // 返回新证书字节流(被签名内容 + 签名算法 + 签名)
	// return asn1.Marshal(certificate{
	// 	nil,
	// 	c,
	// 	signatureAlgorithm,
	// 	asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	// })
}

// CreateCertificateToPem creates a new certificate based on a template and
// encodes it to PEM format. It uses CreateCertificate to create certificate
// and returns its PEM format.
func CreateCertificateToPem(template, parent *Certificate, pubKey *sm2.PublicKey, signer crypto.Signer) ([]byte, error) {
	der, err := CreateCertificate(template, parent, pubKey, signer)
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

func ParseSm2CertifateToX509(asn1data []byte) (*x509.Certificate, error) {
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
	// Hash it
	hash := sha256.New()
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
