// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package tls_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/gmtls"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

//goland:noinspection GoUnusedConst
const (
	SM2CaCertPath   = "./certs/sm2_ca_cert.cer"
	SM2AuthCertPath = "./certs/sm2_auth_cert.cer"
	SM2AuthKeyPath  = "./certs/sm2_auth_key.pem"
	sm2SignCertPath = "./certs/sm2_sign_cert.cer"
	sm2SignKeyPath  = "./certs/sm2_sign_key.pem"
	sm2UserCertPath = "./certs/sm2_auth_cert.cer"
	sm2UserKeyPath  = "./certs/sm2_auth_key.pem"

	ecdsaCaCertPath   = "./certs/ecdsa_ca_cert.cer"
	ecdsaAuthCertPath = "./certs/ecdsa_auth_cert.cer"
	ecdsaAuthKeyPath  = "./certs/ecdsa_auth_key.pem"
	ecdsaSignCertPath = "./certs/ecdsa_sign_cert.cer"
	ecdsaSignKeyPath  = "./certs/ecdsa_sign_key.pem"
	ecdsaUserCertPath = "./certs/ecdsa_auth_cert.cer"
	ecdsaUserKeyPath  = "./certs/ecdsa_auth_key.pem"

	ecdsaextCaCertPath   = "./certs/ecdsaext_ca_cert.cer"
	ecdsaextAuthCertPath = "./certs/ecdsaext_auth_cert.cer"
	ecdsaextAuthKeyPath  = "./certs/ecdsaext_auth_key.pem"
	ecdsaextSignCertPath = "./certs/ecdsaext_sign_cert.cer"
	ecdsaextSignKeyPath  = "./certs/ecdsaext_sign_key.pem"
	ecdsaextUserCertPath = "./certs/ecdsaext_auth_cert.cer"
	ecdsaextUserKeyPath  = "./certs/ecdsaext_auth_key.pem"
)

func TestMain(m *testing.M) {
	go ServerRun(true)
	time.Sleep(5 * time.Second)
	m.Run()
}

var end chan bool

func Test_tls13_sm2(t *testing.T) {
	end = make(chan bool, 64)
	go ClientRunTls13("sm2")
	<-end
	fmt.Println("Test_tls13 over.")
}

func Test_tls13_ecdsa(t *testing.T) {
	end = make(chan bool, 64)
	go ClientRunTls13("ecdsa")
	<-end
	fmt.Println("Test_tls13 over.")
}

func Test_tls13_ecdsaext(t *testing.T) {
	end = make(chan bool, 64)
	go ClientRunTls13("ecdsaext")
	<-end
	fmt.Println("Test_tls13 over.")
}

func Test_gmssl_sm2(t *testing.T) {
	end = make(chan bool, 64)
	go ClientRunGMSSL("sm2")
	<-end
	fmt.Println("Test_gmssl_sm2 over.")
}

func Test_gmssl_ecdsa(t *testing.T) {
	end = make(chan bool, 64)
	go ClientRunGMSSL("ecdsa")
	<-end
	fmt.Println("Test_gmssl_ecdsa over.")
}

func Test_gmssl_ecdsaext(t *testing.T) {
	end = make(chan bool, 64)
	go ClientRunGMSSL("ecdsaext")
	<-end
	fmt.Println("Test_gmssl_ecdsaext over.")
}

// 启动服务端
func ServerRun(needClientAuth bool) {
	err := zclog.ClearDir("logs")
	if err != nil {
		panic(err)
	}
	zcgologConfig := &zclog.Config{
		LogFileDir:        "logs",
		LogFileNamePrefix: "tlstest",
		LogMod:            zclog.LOG_MODE_LOCAL,
		LogLevelGlobal:    zclog.LOG_LEVEL_DEBUG,
	}
	zclog.InitLogger(zcgologConfig)
	// 导入tls配置
	config, err := loadServerConfig(needClientAuth)
	if err != nil {
		panic(err)
	}
	// 定义tls监听器
	ln, err := gmtls.Listen("tcp", ":50052", config)
	if err != nil {
		zclog.Println(err)
		return
	}
	defer func(ln net.Listener) {
		err := ln.Close()
		if err != nil {
			panic(err)
		}
	}(ln)

	// 定义http请求处理
	http.HandleFunc("/test", func(writer http.ResponseWriter, request *http.Request) {
		clientName := request.URL.Query().Get("clientName")
		fmt.Printf("接受到来自 %s 的http请求...\n", clientName)
		// 在http响应中写入内容
		_, err := fmt.Fprintf(writer, "你好, %s ! \n", clientName)
		if err != nil {
			panic(err)
		}
	})

	// 在tls监听器上开启https服务
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}

func ClientRunGMSSL(certType string) {
	// 创建客户端本地的证书池
	certPool := x509.NewCertPool()
	var cacert []byte
	var cert gmtls.Certificate
	// 客户端优先曲线列表
	var curvePreference []gmtls.CurveID
	// 客户端优先密码套件列表
	var cipherSuitesPrefer []uint16
	// 客户端优先签名算法
	var sigAlgPrefer []gmtls.SignatureScheme
	var err error
	switch certType {
	case "sm2":
		// 读取sm2 ca证书
		cacert, err = ioutil.ReadFile(SM2CaCertPath)
		// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
		// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
		// 此时该证书应该由第三方ca机构颁发签名。
		cert, _ = gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)
		curvePreference = append(curvePreference, gmtls.Curve256Sm2)
		cipherSuitesPrefer = append(cipherSuitesPrefer, gmtls.TLS_SM4_GCM_SM3)
	case "ecdsa":
		// 读取ecdsa ca证书
		cacert, err = ioutil.ReadFile(ecdsaCaCertPath)
		// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
		// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
		// 此时该证书应该由第三方ca机构颁发签名。
		cert, _ = gmtls.LoadX509KeyPair(ecdsaUserCertPath, ecdsaUserKeyPath)
		curvePreference = append(curvePreference, gmtls.CurveP256)
		cipherSuitesPrefer = append(cipherSuitesPrefer, gmtls.TLS_AES_128_GCM_SHA256)
		sigAlgPrefer = append(sigAlgPrefer, gmtls.ECDSAWithP256AndSHA256)
	case "ecdsaext":
		// 读取ecdsaext ca证书
		cacert, err = ioutil.ReadFile(ecdsaextCaCertPath)
		// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
		// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
		// 此时该证书应该由第三方ca机构颁发签名。
		cert, _ = gmtls.LoadX509KeyPair(ecdsaextUserCertPath, ecdsaextUserKeyPath)
		curvePreference = append(curvePreference, gmtls.CurveP256)
		cipherSuitesPrefer = append(cipherSuitesPrefer, gmtls.TLS_AES_128_GCM_SHA256)
		sigAlgPrefer = append(sigAlgPrefer, gmtls.ECDSAEXTWithP256AndSHA256)
	default:
		err = errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}
	if err != nil {
		zclog.Fatal(err)
	}
	// 将ca证书作为根证书加入证书池
	// 即，客户端相信持有该ca颁发的证书的服务端
	certPool.AppendCertsFromPEM(cacert)

	// 定义gmtls配置
	// 选择最高tls协议版本为VersionGMSSL, 服务端选择的默认密码套件将是 TLS_SM4_GCM_SM3
	config := &gmtls.Config{
		RootCAs:      certPool,
		Certificates: []gmtls.Certificate{cert},
		// 因为sm2相关证书是由`x509/x509_test.go`的`TestCreateCertFromCA`生成的，
		// 指定了SAN包含"server.test.com"
		ServerName:         "server.test.com",
		MaxVersion:         gmtls.VersionGMSSL,
		CurvePreferences:   curvePreference,
		PreferCipherSuites: cipherSuitesPrefer,
		SignAlgPrefer:      sigAlgPrefer,
	}

	// 向服务端拨号，建立tls连接
	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
	if err != nil {
		panic(err)
	}
	defer func(conn *gmtls.Conn) {
		err := conn.Close()
		if err != nil {
			panic(err)
		}
	}(conn)

	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(gmssl) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	// 从tls连接中读取http请求响应
	buff := make([]byte, 1024)
	for {
		n, _ := conn.Read(buff)
		if n <= 0 {
			break
		} else {
			fmt.Printf("%s", buff[0:n])
		}
	}
	end <- true
}

func ClientRunTls13(certType string) {
	// 创建客户端本地的CA证书池
	caPool := x509.NewCertPool()
	// ca证书
	var cacert []byte
	// 客户端证书
	var cert gmtls.Certificate
	// 客户端优先曲线列表
	var curvePreference []gmtls.CurveID
	// 客户端优先密码套件列表
	var cipherSuitesPrefer []uint16
	// 客户端优先签名算法
	var sigAlgPrefer []gmtls.SignatureScheme
	var err error
	switch certType {
	case "sm2":
		// 读取sm2 ca证书
		cacert, err = ioutil.ReadFile(SM2CaCertPath)
		// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
		// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
		// 此时该证书应该由第三方ca机构颁发签名。
		cert, err = gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)
		curvePreference = append(curvePreference, gmtls.Curve256Sm2)
		cipherSuitesPrefer = append(cipherSuitesPrefer, gmtls.TLS_SM4_GCM_SM3)
	case "ecdsa":
		// 读取ecdsa ca证书
		cacert, err = ioutil.ReadFile(ecdsaCaCertPath)
		// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
		// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
		// 此时该证书应该由第三方ca机构颁发签名。
		cert, err = gmtls.LoadX509KeyPair(ecdsaUserCertPath, ecdsaUserKeyPath)
		curvePreference = append(curvePreference, gmtls.CurveP256)
		cipherSuitesPrefer = append(cipherSuitesPrefer, gmtls.TLS_AES_128_GCM_SHA256)
		sigAlgPrefer = append(sigAlgPrefer, gmtls.ECDSAWithP256AndSHA256)
	case "ecdsaext":
		// 读取ecdsaext ca证书
		cacert, err = ioutil.ReadFile(ecdsaextCaCertPath)
		// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
		// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
		// 此时该证书应该由第三方ca机构颁发签名。
		cert, err = gmtls.LoadX509KeyPair(ecdsaextUserCertPath, ecdsaextUserKeyPath)
		curvePreference = append(curvePreference, gmtls.CurveP256)
		cipherSuitesPrefer = append(cipherSuitesPrefer, gmtls.TLS_AES_128_GCM_SHA256)
		sigAlgPrefer = append(sigAlgPrefer, gmtls.ECDSAEXTWithP256AndSHA256)
	default:
		err = errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}
	if err != nil {
		zclog.Fatal(err)
	}
	// 将ca证书作为根证书加入证书池
	// 即，客户端相信持有该ca颁发的证书的服务端
	caPool.AppendCertsFromPEM(cacert)

	// 定义gmtls配置
	config := &gmtls.Config{
		RootCAs:      caPool,
		Certificates: []gmtls.Certificate{cert},
		// 因为相关证书是由`x509/x509_test.go`的`TestCreateCertFromCA`生成的，
		// 指定了SAN包含"server.test.com"
		ServerName:         "server.test.com",
		CurvePreferences:   curvePreference,
		PreferCipherSuites: cipherSuitesPrefer,
		SignAlgPrefer:      sigAlgPrefer,
	}
	// 要启用psk,除了默认SessionTicketsDisabled为false,还需要配置客户端会话缓存为非nil。
	// 这样服务端才会在握手完成后发出 newSessionTicketMsgTLS13 将加密并认证的会话票据发送给客户端。
	config.ClientSessionCache = gmtls.NewLRUClientSessionCache(1)

	// 向服务端拨号，建立tls连接
	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
	if err != nil {
		panic(err)
	}
	defer func(conn *gmtls.Conn) {
		err := conn.Close()
		if err != nil {
			panic(err)
		}
	}(conn)

	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(tls1.3) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	// 从tls连接中读取http请求响应
	buff := make([]byte, 1024)
	for {
		n, _ := conn.Read(buff)
		if n <= 0 {
			break
		} else {
			fmt.Printf("%s", buff[0:n])
		}
	}
	end <- true
}

func loadServerConfig(needClientAuth bool) (*gmtls.Config, error) {
	// 准备服务端证书，分别是sm2,ecdsa,ecdsaext
	var certs []gmtls.Certificate
	// 读取sm2Sign证书与私钥，作为国密tls场景的服务器证书用
	sm2Cert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	certs = append(certs, sm2Cert)
	// 读取ecdsaSign证书与私钥，作为国密tls场景的服务器证书用
	ecdsaCert, err := gmtls.LoadX509KeyPair(ecdsaSignCertPath, ecdsaSignKeyPath)
	if err != nil {
		return nil, err
	}
	certs = append(certs, ecdsaCert)
	// 读取ecdsaextSign证书与私钥，作为国密tls场景的服务器证书用
	ecdsaextCert, err := gmtls.LoadX509KeyPair(ecdsaextSignCertPath, ecdsaextSignKeyPath)
	if err != nil {
		return nil, err
	}
	certs = append(certs, ecdsaextCert)

	// 创建gmtls配置
	config := &gmtls.Config{
		Certificates:   certs,
		GetCertificate: nil,
	}

	// 如果开启对客户端的身份验证，则需要导入颁发客户端证书的CA证书
	if needClientAuth {
		// 如果服务端想要验证客户端身份，在这里添加对应配置信任的根证书
		certPool := x509.NewCertPool()
		sm2CaCert, err := ioutil.ReadFile(SM2CaCertPath)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(sm2CaCert)
		ecdsaCaCert, err := ioutil.ReadFile(ecdsaCaCertPath)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(ecdsaCaCert)
		ecdsaextCaCert, err := ioutil.ReadFile(ecdsaextCaCertPath)
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(ecdsaextCaCert)
		config.ClientAuth = gmtls.RequireAndVerifyClientCert
		config.ClientCAs = certPool
		// config.SessionTicketsDisabled = false
		fmt.Println("------ debug用 : 服务端配置了ClientAuth")
	}

	return config, nil
}

func Test_clearLogs(t *testing.T) {
	err := zclog.ClearDir("logs")
	if err != nil {
		panic(err)
	}
}
