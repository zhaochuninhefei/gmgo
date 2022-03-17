/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package x509

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

func TestX509(t *testing.T) {
	// 生成sm2密钥对
	// priv, err := sm2.GenerateKey(nil)
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 生成私钥文件字节流
	privPem, err := WritePrivateKeyToPem(priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	// 生成公钥文件字节流
	pubkeyPem, _ := WritePublicKeyToPem(pubKey)
	// 读取私钥
	privKey, err := ReadPrivateKeyFromPem(privPem, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 读取公钥
	pubKey, err = ReadPublicKeyFromPem(pubkeyPem)
	if err != nil {
		t.Fatal(err)
	}
	// 定义证书申请模板
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "pangzi.com",
			Organization: []string{"PANGZIXIEHUI"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	// 创建证书申请pem字节流并签名
	reqPem, err := CreateCertificateRequestToPem(&templateReq, privKey)
	if err != nil {
		t.Fatal(err)
	}
	// 从pem读取证书申请
	req, err := ReadCertificateRequestFromPem(reqPem)
	if err != nil {
		t.Fatal(err)
	}
	// 检查证书申请的签名
	err = req.CheckSignature()
	if err != nil {
		t.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "pangzi.com"
	// 定义证书模板
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"PANGZIXIEHUI"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.pangzi.com"},
		IssuingCertificateURL: []string{"http://crt.pangzi.com/ca1.crt"},

		DNSNames:       []string{"pangzi.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".pangzi.com", "pangzi.com"},

		CRLDistributionPoints: []string{"http://crl1.pangzi.com/ca1.crl", "http://crl2.pangzi.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	// pubKey, _ = priv.Public().(*sm2.PublicKey)
	// 创建证书pem字节流
	certpem, err := CreateCertificateToPem(&template, &template, pubKey, privKey)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	// 读取证书pem
	cert, err := ReadCertificateFromPem(certpem)
	if err != nil {
		t.Fatal("failed to read cert file")
	}
	// 检查证书签名
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func TestX509WithFile(t *testing.T) {
	// 生成sm2密钥对
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	// 生成私钥pem文件
	_, err = WritePrivateKeytoPem("testdata/pri_key.pem", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 生成公钥pem文件
	_, err = WritePublicKeytoPem("testdata/pub_key.pem", pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 从pem文件读取私钥
	privKey, err := ReadPrivateKeyFromPemFile("testdata/pri_key.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("读取到sm2私钥 : %v\n", privKey)
	// 从pem文件读取公钥
	pubKey, err := ReadPublicKeyFromPemFile("testdata/pub_key.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("读取到sm2公钥 : %v\n", pubKey)
	fmt.Println("测试sm2私钥与公钥文件读写成功")

	// 定义证书申请模板
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			// Subject行的CN
			CommonName: "test.pangzi.com",
			// Subject行的O
			Organization: []string{"PANGZIXIEHUI", "dapangzixiehui"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	// 创建证书申请pem字节流并签名
	_, err = CreateCertificateRequestToPemFile("testdata/csr.pem", &templateReq, privKey)
	if err != nil {
		t.Fatal(err)
	}
	// 创建证书申请csr文件后，可以用`openssl req -noout -text -in testdata/csr.pem`命令查看文件内容

	// 模拟ca检查证书申请
	// 从pem读取证书申请
	req, err := ReadCertificateRequestFromPemFile("testdata/csr.pem")
	if err != nil {
		t.Fatal(err)
	}
	// 检查证书申请的签名
	err = req.CheckSignature()
	if err != nil {
		t.Fatalf("证书申请验签失败 : %v", err)
	} else {
		fmt.Printf("证书申请验签成功\n")
	}
	fmt.Println("测试证书申请文件读写与验签成功")

	// 模拟ca发布证书
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.pangzi.com"
	// 定义证书模板
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			// Subject行的CN
			CommonName: commonName,
			// Subject行的O
			Organization: []string{"PANGZIXIEHUI", "dapangzixiehui"},
			Country:      []string{"China"},
			// CN之后的附加名称
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					// GN
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					// C
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.pangzi.com"},
		IssuingCertificateURL: []string{"http://crt.pangzi.com/ca1.crt"},

		DNSNames:       []string{"test.pangzi.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".pangzi.com", "pangzi.com"},

		CRLDistributionPoints: []string{"http://crl1.pangzi.com/ca1.crl", "http://crl2.pangzi.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	// 创建证书pem文件
	_, err = CreateCertificateToPemFile("testdata/cert.cer", &template, &template, pubKey, privKey)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := ReadCertificateFromPemFile("testdata/cert.cer")
	if err != nil {
		t.Fatal("failed to read cert file")
	}
	// 检查证书签名
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	fmt.Println("测试证书文件读写与验签成功")
}

func TestCreateCertFromCA(t *testing.T) {
	caPriv, caCert, err := createCACert()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("生成CA密钥对与CA证书成功")

	err = createSignCert(caPriv, caCert)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("生成sm2_sign密钥对并模拟CA为其颁发证书成功")

	err = createEncCert(caPriv, caCert)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("生成sm2_enc密钥对并模拟CA为其颁发证书成功")

	err = createAuthCert(caPriv, caCert)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("生成sm2_auth密钥对并模拟CA为其颁发证书成功")
}

// 创建ca证书，并返回ca私钥与ca证书
func createCACert() (*sm2.PrivateKey, *Certificate, error) {
	certType := "sm2_ca"
	// 生成sm2密钥对
	privKey, pubKey, err := createKeys(certType)
	if err != nil {
		return nil, nil, err
	}
	userKeyUsage := KeyUsageCertSign + KeyUsageCRLSign
	userExtKeyUsage := []ExtKeyUsage{
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
	sid := []byte{0, 0, 0, 1}
	aid := []byte{0, 0, 0, 1}
	// 创建证书，ca证书自签名
	cert, err := createCert(1, "test.example.com", "example.com", "CN", "He Fei", true, true, sid, aid, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, privKey)
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

func createSignCert(caPriv *sm2.PrivateKey, caCert *Certificate) error {
	certType := "sm2_sign"
	// 生成sm2密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := KeyUsageDigitalSignature + KeyUsageContentCommitment
	userExtKeyUsage := []ExtKeyUsage{
		// ExtKeyUsageAny,
		ExtKeyUsageServerAuth,
		ExtKeyUsageClientAuth,
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
	sid := []byte{0, 0, 0, 2}
	aid := caCert.SubjectKeyId
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCert(2, "test.example.com", "example.com", "CN", "He Fei", false, false, sid, aid, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv)
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

func createEncCert(caPriv *sm2.PrivateKey, caCert *Certificate) error {
	certType := "sm2_enc"
	// 生成sm2密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := KeyUsageKeyEncipherment + KeyUsageDataEncipherment
	userExtKeyUsage := []ExtKeyUsage{
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
	sid := []byte{0, 0, 0, 3}
	aid := caCert.SubjectKeyId
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCert(3, "test.example.com", "example.com", "CN", "He Fei", false, false, sid, aid, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv)
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

func createAuthCert(caPriv *sm2.PrivateKey, caCert *Certificate) error {
	certType := "sm2_auth"
	// 生成sm2密钥对
	_, pubKey, err := createKeys(certType)
	if err != nil {
		return err
	}
	userKeyUsage := KeyUsageDigitalSignature + KeyUsageContentCommitment
	userExtKeyUsage := []ExtKeyUsage{
		// ExtKeyUsageAny,
		ExtKeyUsageServerAuth,
		ExtKeyUsageClientAuth,
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
	sid := []byte{0, 0, 0, 4}
	aid := caCert.SubjectKeyId
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCert(4, "test.example.com", "example.com", "CN", "He Fei", false, false, sid, aid, userKeyUsage, userExtKeyUsage, nil, certType, pubKey, caPriv)
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

func createKeys(certType string) (*sm2.PrivateKey, *sm2.PublicKey, error) {
	// 生成sm2密钥对
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := &priv.PublicKey
	// 生成私钥pem文件
	_, err = WritePrivateKeytoPem("testdata/"+certType+"_key.pem", priv, nil)
	if err != nil {
		return nil, nil, err
	}
	// 生成公钥pem文件
	_, err = WritePublicKeytoPem("testdata/"+certType+"_pubkey.pem", pub, nil)
	if err != nil {
		return nil, nil, err
	}
	// 从pem文件读取私钥
	privKey, err := ReadPrivateKeyFromPemFile("testdata/"+certType+"_key.pem", nil)
	if err != nil {
		return nil, nil, err
	}
	// 从pem文件读取公钥
	pubKey, err := ReadPublicKeyFromPemFile("testdata/"+certType+"_pubkey.pem", nil)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func createCert(sn int64, cn string, o string, c string, st string, bcs bool, isca bool, sId []byte, aId []byte,
	ku KeyUsage, ekus []ExtKeyUsage, uekus []asn1.ObjectIdentifier,
	certType string, pubKey *sm2.PublicKey, privKey *sm2.PrivateKey) (*Certificate, error) {
	// 定义证书模板
	template := &Certificate{
		SerialNumber: big.NewInt(sn),
		Subject: pkix.Name{
			// Subject行的CN
			CommonName: cn,
			// Subject行的O
			Organization: []string{o},
			Country:      []string{"China"},
			// 附加名称
			ExtraNames: []pkix.AttributeTypeAndValue{
				// This should override the Country, above.
				{
					// C
					Type:  []int{2, 5, 4, 6},
					Value: c,
				},
				{
					// ST
					Type:  []int{2, 5, 4, 8},
					Value: st,
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),
		SignatureAlgorithm:    SM2WithSM3,
		BasicConstraintsValid: bcs,
		IsCA:                  isca,
		SubjectKeyId:          sId,
		AuthorityKeyId:        aId,
		KeyUsage:              ku,
		ExtKeyUsage:           ekus,
		UnknownExtKeyUsage:    uekus,
	}
	// 创建证书pem文件
	_, err := CreateCertificateToPemFile("testdata/"+certType+"_cert.cer", template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/user_cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := ReadCertificateFromPemFile("testdata/" + certType + "_cert.cer")
	if err != nil {
		return nil, err
	}
	// // 检查证书签名
	// err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	// if err != nil {
	// 	return nil, nil, err
	// } else {
	// 	fmt.Printf("CheckSignature ok\n")
	// }
	return cert, nil
}

func TestCreateRevocationList(t *testing.T) {
	priv, err := sm2.GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	privPem, err := WritePrivateKeyToPem(priv, nil) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := ReadPrivateKeyFromPem(privPem, nil) // 读取密钥
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate rsa key: %s", err)
	}
	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *Certificate
		template      *RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           privKey,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           privKey,
			issuer:        nil,
			template:      &RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCertSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "invalid signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "valid",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, rsa2048 key",
			key:  rsaPriv,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				SignatureAlgorithm: SM2WithSM3,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  privKey,
			issuer: &Certificate{
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateRevocationList(rand.Reader, tc.template, tc.issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseDERCRL(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}
			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
				!parsedCRL.SignatureAlgorithm.Algorithm.Equal(signatureAlgorithmDetails[tc.template.SignatureAlgorithm].oid) {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates)
			}

			if len(parsedCRL.TBSCertList.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.TBSCertList.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[1], crlExt)
			}
			if len(parsedCRL.TBSCertList.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions)
			}
		})
	}
}
