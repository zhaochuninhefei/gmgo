package x509test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/utils"
	"gitee.com/zhaochuninhefei/gmgo/x509"
)

func TestClearTestdata(t *testing.T) {
	dir, _ := os.ReadDir("testdata")
	for _, f := range dir {
		err := os.Remove(path.Join("testdata", f.Name()))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCreateCertFromCA_sm2(t *testing.T) {
	certTypePre := "sm2_"

	certType := certTypePre + "ca"
	caPriv, caCert, err := createCACert(certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成CA密钥对与CA证书成功 %s\n", certType)

	certType = certTypePre + "intermediateCA"
	intermediateCaPriv, intermediateCaCert, err := createIntermediateCACert(certType, caPriv, caCert)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成IntermediateCA密钥对与IntermediateCA证书成功 %s\n", certType)

	certType = certTypePre + "sign"
	err = createSignCert(intermediateCaPriv, intermediateCaCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "enc"
	err = createEncCert(intermediateCaPriv, intermediateCaCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "auth"
	err = createAuthCert(intermediateCaPriv, intermediateCaCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)
}

func TestCreateCertFromCA_ecdsa(t *testing.T) {
	certTypePre := "ecdsa_"
	certType := certTypePre + "ca"
	caPriv, caCert, err := createCACert(certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成CA密钥对与CA证书成功 %s\n", certType)

	certType = certTypePre + "intermediateCA"
	intermediateCaPriv, intermediateCaCert, err := createIntermediateCACert(certType, caPriv, caCert)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成IntermediateCA密钥对与IntermediateCA证书成功 %s\n", certType)

	certType = certTypePre + "sign"
	err = createSignCert(intermediateCaPriv, intermediateCaCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "enc"
	err = createEncCert(intermediateCaPriv, intermediateCaCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)

	certType = certTypePre + "auth"
	err = createAuthCert(intermediateCaPriv, intermediateCaCert, certType)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("生成 %s 密钥对并模拟CA为其颁发证书成功\n", certType)
}

func createCACert(certType string) (interface{}, *x509.Certificate, error) {
	// 生成密钥对
	privKey, pubKey, err := createKeys(certType)
	if err != nil {
		return nil, nil, err
	}
	userKeyUsage := x509.KeyUsageCertSign + x509.KeyUsageCRLSign
	//goland:noinspection GoPreferNilSlice
	userExtKeyUsage := []x509.ExtKeyUsage{
		// ExtKeyUsageAny,
		// ExtKeyUsageServerAuth,
		// ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 创建证书，ca证书自签名
	cert, err := createCertSignSelf("ca.test.com", "test", "ca", "CN", "Anhui Hefei", true, true, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}
	// 检查证书签名，因为是ca证书自签名，所以使用本证书自验
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return nil, nil, err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return privKey, cert, nil
}

func createIntermediateCACert(certType string, caPriv interface{}, caCert *x509.Certificate) (interface{}, *x509.Certificate, error) {
	// 生成密钥对
	privKey, pubKey, err := createKeys(certType)
	if err != nil {
		return nil, nil, err
	}
	userKeyUsage := x509.KeyUsageCertSign + x509.KeyUsageCRLSign
	//goland:noinspection GoPreferNilSlice
	userExtKeyUsage := []x509.ExtKeyUsage{
		// ExtKeyUsageAny,
		// ExtKeyUsageServerAuth,
		// ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 创建证书，ca证书自签名
	cert, err := createCertSignParent("intermediateCa.test.com", "test", "intermediateCa", "CN", "Anhui Hefei", true, true, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv, caCert)
	if err != nil {
		return nil, nil, err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return nil, nil, err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return privKey, cert, nil
}

func createSignCert(caPriv interface{}, caCert *x509.Certificate, certType string) error {
	// 生成sm2密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := x509.KeyUsageDigitalSignature + x509.KeyUsageContentCommitment
	userExtKeyUsage := []x509.ExtKeyUsage{
		// ExtKeyUsageAny,
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCertSignParent("server.test.com", "test", "server", "CN", "Anhui Hefei", false, false, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv, caCert)
	if err != nil {
		return err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return nil
}

func createEncCert(caPriv interface{}, caCert *x509.Certificate, certType string) error {
	// 生成密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := x509.KeyUsageKeyEncipherment + x509.KeyUsageDataEncipherment
	//goland:noinspection GoPreferNilSlice
	userExtKeyUsage := []x509.ExtKeyUsage{
		// ExtKeyUsageAny,
		// ExtKeyUsageServerAuth,
		// ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCertSignParent("server.test.com", "test", "server", "CN", "Anhui Hefei", false, false, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv, caCert)
	if err != nil {
		return err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return nil
}

func createAuthCert(caPriv interface{}, caCert *x509.Certificate, certType string) error {
	// 生成密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := x509.KeyUsageDigitalSignature + x509.KeyUsageContentCommitment
	userExtKeyUsage := []x509.ExtKeyUsage{
		// ExtKeyUsageAny,
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCertSignParent("client.test.com", "test", "client", "CN", "Anhui Hefei", false, false, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv, caCert)
	if err != nil {
		return err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return nil
}

func createKeys(certType string) (interface{}, interface{}, error) {
	var priv, pub interface{}
	var err error

	if strings.HasPrefix(certType, "sm2_") {
		// 生成sm2密钥对
		priv, err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*sm2.PrivateKey).PublicKey
	} else if strings.HasPrefix(certType, "ecdsa_") {
		// 生成ecdsa密钥对
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub = &priv.(*ecdsa.PrivateKey).PublicKey
	}
	// 生成私钥pem文件
	_, err = x509.WritePrivateKeytoPemFile("testdata/"+certType+"_key.pem", priv, nil)
	if err != nil {
		return nil, nil, err
	}
	// 生成公钥pem文件
	_, err = x509.WritePublicKeytoPemFile("testdata/"+certType+"_pubkey.pem", pub)
	if err != nil {
		return nil, nil, err
	}
	// 从pem文件读取私钥
	privKey, err := x509.ReadPrivateKeyFromPemFile("testdata/"+certType+"_key.pem", nil)
	if err != nil {
		return nil, nil, err
	}
	// 从pem文件读取公钥
	pubKey, err := x509.ReadPublicKeyFromPemFile("testdata/" + certType + "_pubkey.pem")
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func createCertSignSelf(cn string, o string, ou string, c string, st string, bcs bool, isca bool,
	ku x509.KeyUsage, ekus []x509.ExtKeyUsage, uekus []asn1.ObjectIdentifier,
	certType string, pubKey interface{}, privKey interface{}) (*x509.Certificate, error) {
	// 获取ski
	var ski []byte
	switch pk := pubKey.(type) {
	case *sm2.PublicKey:
		ski = x509.CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	case *ecdsa.PublicKey:
		ski = x509.CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	default:
		panic("不支持的公钥类型")
	}
	// 定义证书模板
	template := createTemplate(cn, o, ou, c, st, bcs, isca, ski, ku, ekus, uekus, privKey)
	// 创建自签名证书pem文件
	_, err := x509.CreateCertificateToPemFile("testdata/"+certType+"_cert.cer", template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/user_cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := x509.ReadCertificateFromPemFile("testdata/" + certType + "_cert.cer")
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func createCertSignParent(cn string, o string, ou string, c string, st string, bcs bool, isca bool,
	ku x509.KeyUsage, ekus []x509.ExtKeyUsage, uekus []asn1.ObjectIdentifier,
	certType string, pubKey interface{}, privKey interface{}, parent *x509.Certificate) (*x509.Certificate, error) {

	// 获取ski
	var ski []byte
	switch pk := pubKey.(type) {
	case *sm2.PublicKey:
		ski = x509.CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	case *ecdsa.PublicKey:
		ski = x509.CreateEllipticSKI(pk.Curve, pk.X, pk.Y)
	default:
		panic("不支持的公钥类型")
	}
	// 定义证书模板
	template := createTemplate(cn, o, ou, c, st, bcs, isca, ski, ku, ekus, uekus, privKey)
	// 创建自签名证书pem文件
	_, err := x509.CreateCertificateToPemFile("testdata/"+certType+"_cert.cer", template, parent, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/user_cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := x509.ReadCertificateFromPemFile("testdata/" + certType + "_cert.cer")
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func createTemplate(cn string, o string, ou string, c string, st string, bcs bool, isca bool, sId []byte, ku x509.KeyUsage, ekus []x509.ExtKeyUsage, uekus []asn1.ObjectIdentifier, privKey interface{}) *x509.Certificate {
	var signAlg x509.SignatureAlgorithm
	switch privKey.(type) {
	case *sm2.PrivateKey:
		signAlg = x509.SM2WithSM3
	case *ecdsa.PrivateKey:
		signAlg = x509.ECDSAWithSHA256
	default:
		panic("不支持的私钥类型")
	}

	// 定义证书模板
	template := &x509.Certificate{
		// 证书序列号
		SerialNumber: utils.GetRandBigInt(),
		// 证书拥有者
		Subject: pkix.Name{
			// CN 证书拥有者通用名, 一般是域名
			CommonName: cn,
			// O 证书拥有者组织机构
			Organization: []string{o},
			// OU 证书拥有者组织单位, 隶属于Organization
			OrganizationalUnit: []string{ou},
			// C 证书拥有者所在国家
			Country: []string{"China"},
			// 附加名称
			ExtraNames: []pkix.AttributeTypeAndValue{
				// This should override the Country, above.
				{
					// C 会覆盖Country
					Type:  []int{2, 5, 4, 6},
					Value: c,
				},
				{
					// ST 省市
					Type:  []int{2, 5, 4, 8},
					Value: st,
				},
			},
		},
		// 证书有效期 十年
		// NotBefore:             time.Now(),
		// NotAfter:              time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(87600 * time.Hour),
		// 证书签名算法
		SignatureAlgorithm:    signAlg,
		BasicConstraintsValid: bcs,
		IsCA:                  isca,
		SubjectKeyId:          sId,
		// AuthorityKeyId:        aId,
		KeyUsage:           ku,
		ExtKeyUsage:        ekus,
		UnknownExtKeyUsage: uekus,
		// x509 v3 版本不再使用 CommonName 而是使用这里的SAN扩展信息
		DNSNames:       []string{cn, "test.example.com"},
		EmailAddresses: []string{"test@example.com"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		URIs:           []*url.URL{parseURI("https://example.com/test#test")},
	}
	return template
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}
