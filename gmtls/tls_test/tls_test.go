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

var end chan bool

func Test_tls13_sm2(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(true, "sm2")
	time.Sleep(5 * time.Second)
	go ClientRunTls13("sm2")
	<-end
	fmt.Println("Test_tls13 over.")
}

func Test_tls13_ecdsa(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(true, "ecdsa")
	time.Sleep(5 * time.Second)
	go ClientRunTls13("ecdsa")
	<-end
	fmt.Println("Test_tls13 over.")
}

func Test_tls13_ecdsaext(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(true, "ecdsaext")
	time.Sleep(5 * time.Second)
	go ClientRunTls13("ecdsaext")
	<-end
	fmt.Println("Test_tls13 over.")
}

func Test_gmssl(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(true, "sm2")
	time.Sleep(5 * time.Second)
	go ClientRunGMSSL("sm2")
	<-end
	fmt.Println("Test_gmssl over.")
}

// 启动服务端
func ServerRun(needClientAuth bool, certType string) {
	err := zclog.ClearDir("logs")
	if err != nil {
		panic(err)
	}
	zcgologConfig := &zclog.Config{
		LogFileDir:        "logs",
		LogFileNamePrefix: "tlstest",
		LogMod:            zclog.LOG_MODE_SERVER,
		LogLevelGlobal:    zclog.LOG_LEVEL_DEBUG,
	}
	zclog.InitLogger(zcgologConfig)
	// 导入tls配置
	config, err := loadServerConfig(needClientAuth, certType)
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
	// fmt.Println("============ HTTP服务(基于GMSSL或TLS) 已启动 ============")

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
	var err error
	switch certType {
	case "sm2":
		// 读取sm2 ca证书
		cacert, err = ioutil.ReadFile(SM2CaCertPath)
	case "ecdsa":
		// 读取ecdsa ca证书
		cacert, err = ioutil.ReadFile(ecdsaCaCertPath)
	case "ecdsaext":
		// 读取ecdsaext ca证书
		cacert, err = ioutil.ReadFile(ecdsaextCaCertPath)
	default:
		err = errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}
	// 将ca证书作为根证书加入证书池
	// 即，客户端相信持有该ca颁发的证书的服务端
	certPool.AppendCertsFromPEM(cacert)

	// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
	// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
	// 此时该证书应该由第三方ca机构颁发签名。
	var cert gmtls.Certificate
	switch certType {
	case "sm2":
		cert, _ = gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)
	case "ecdsa":
		cert, _ = gmtls.LoadX509KeyPair(ecdsaUserCertPath, ecdsaUserKeyPath)
	case "ecdsaext":
		cert, _ = gmtls.LoadX509KeyPair(ecdsaextUserCertPath, ecdsaextUserKeyPath)
	default:
		err = errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}
	if err != nil {
		zclog.Fatal(err)
	}

	// 定义gmtls配置
	// 选择最高tls协议版本为VersionGMSSL, 服务端选择的默认密码套件将是 TLS_SM4_GCM_SM3
	config := &gmtls.Config{
		RootCAs:      certPool,
		Certificates: []gmtls.Certificate{cert},
		// 因为sm2相关证书是由`x509/x509_test.go`的`TestCreateCertFromCA`生成的，
		// 指定了SAN包含"server.test.com"
		ServerName: "server.test.com",
		MaxVersion: gmtls.VersionGMSSL,
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

	// fmt.Println("============ gmtls客户端(gmssl)连接服务端，握手成功 ============")
	// time.Sleep(time.Minute)
	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(gmssl) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	// fmt.Println("============ gmtls客户端(gmssl)向服务端发送http请求 ============")

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
	// fmt.Println("============ gmtls客户端(gmssl)与服务端连接测试成功 ============")
	end <- true
}

func ClientRunTls13(certType string) {
	// 创建客户端本地的证书池
	certPool := x509.NewCertPool()
	var cacert []byte
	var err error
	switch certType {
	case "sm2":
		// 读取sm2 ca证书
		cacert, err = ioutil.ReadFile(SM2CaCertPath)
	case "ecdsa":
		// 读取ecdsa ca证书
		cacert, err = ioutil.ReadFile(ecdsaCaCertPath)
	case "ecdsaext":
		// 读取ecdsaext ca证书
		cacert, err = ioutil.ReadFile(ecdsaextCaCertPath)
	default:
		err = errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}
	if err != nil {
		zclog.Fatal(err)
	}
	// 将ca证书作为根证书加入证书池
	// 即，客户端相信持有该ca颁发的证书的服务端
	certPool.AppendCertsFromPEM(cacert)

	// 读取User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
	// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
	// 此时该证书应该由第三方ca机构颁发签名。
	var cert gmtls.Certificate
	switch certType {
	case "sm2":
		cert, err = gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)
	case "ecdsa":
		cert, err = gmtls.LoadX509KeyPair(ecdsaUserCertPath, ecdsaUserKeyPath)
	case "ecdsaext":
		cert, err = gmtls.LoadX509KeyPair(ecdsaextUserCertPath, ecdsaextUserKeyPath)
	default:
		err = errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}
	if err != nil {
		zclog.Fatal(err)
	}

	// 定义gmtls配置
	// 默认最高tls协议版本为tls1.3, 服务端选择的默认密码套件将是 TLS_SM4_GCM_SM3
	var curvePreference []gmtls.CurveID
	switch certType {
	case "sm2":
		curvePreference = append(curvePreference, gmtls.Curve256Sm2)
	case "ecdsa", "ecdsaext":
		curvePreference = append(curvePreference, gmtls.CurveP256)
	default:
		err = errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}

	config := &gmtls.Config{
		RootCAs:      certPool,
		Certificates: []gmtls.Certificate{cert},
		// 因为相关证书是由`x509/x509_test.go`的`TestCreateCertFromCA`生成的，
		// 指定了SAN包含"server.test.com"
		ServerName:       "server.test.com",
		CurvePreferences: curvePreference,
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

	// fmt.Println("============ gmtls客户端(tls1.3)连接服务端，握手成功 ============")
	// time.Sleep(time.Minute)
	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(tls1.3) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	// fmt.Println("============ gmtls客户端(tls1.3)向服务端发送http请求 ============")

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
	// fmt.Println("============ gmtls客户端(tls1.3)与服务端连接测试成功 ============")
	end <- true
}

func loadServerConfig(needClientAuth bool, certType string) (*gmtls.Config, error) {
	var sigCert gmtls.Certificate
	var err error
	switch certType {
	case "sm2":
		// 读取sm2Sign证书与私钥，作为国密tls场景的服务器证书用
		sigCert, err = gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	case "ecdsa":
		// 读取ecdsaSign证书与私钥，作为国密tls场景的服务器证书用
		sigCert, err = gmtls.LoadX509KeyPair(ecdsaSignCertPath, ecdsaSignKeyPath)
	case "ecdsaext":
		// 读取ecdsaextSign证书与私钥，作为国密tls场景的服务器证书用
		sigCert, err = gmtls.LoadX509KeyPair(ecdsaextSignCertPath, ecdsaextSignKeyPath)
	default:
		return nil, errors.New("目前只支持sm2/ecdsa/ecdsaext")
	}
	if err != nil {
		return nil, err
	}
	// 返回服务端配置
	config, err := gmtls.NewServerConfigByClientHello(&sigCert, &sigCert)
	if err != nil {
		return nil, err
	}

	if needClientAuth {
		// 如果服务端想要验证客户端身份，在这里添加对应配置信任的根证书
		certPool := x509.NewCertPool()
		var cacert []byte
		switch certType {
		case "sm2":
			cacert, err = ioutil.ReadFile(SM2CaCertPath)
		case "ecdsa":
			cacert, err = ioutil.ReadFile(ecdsaCaCertPath)
		case "ecdsaext":
			cacert, err = ioutil.ReadFile(ecdsaextCaCertPath)
		default:
			return nil, errors.New("目前只支持sm2/ecdsa/ecdsaext")
		}
		if err != nil {
			return nil, err
		}
		certPool.AppendCertsFromPEM(cacert)
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
