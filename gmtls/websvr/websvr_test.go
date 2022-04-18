package websvr

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/x509"

	"gitee.com/zhaochuninhefei/gmgo/gmtls"
)

const (
	// rsaCertPath = "certs/rsa_sign.cer"
	// rsaKeyPath  = "certs/rsa_sign_key.pem"
	// rsaCacertPath = "certs/rsa_CA.cer"
	// sm2SignCertPath = "certs/sm2_sign_cert.cer"
	// sm2SignKeyPath  = "certs/sm2_sign_key.pem"
	// sm2EncCertPath  = "certs/sm2_enc_cert.cer"
	// sm2EncKeyPath   = "certs/sm2_enc_key.pem"
	// SM2CaCertPath   = "certs/SM2_CA.cer"
	sm2UserCertPath = "certs/sm2_auth_cert.cer"
	sm2UserKeyPath  = "certs/sm2_auth_key.pem"
)

// 启动服务端
func ServerRun(needClientAuth bool) {
	// 导入tls配置
	config, err := loadAutoSwitchConfig(needClientAuth)
	if err != nil {
		panic(err)
	}
	// 定义tls监听器
	ln, err := gmtls.Listen("tcp", ":50052", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()

	// 定义http请求处理
	http.HandleFunc("/test", func(writer http.ResponseWriter, request *http.Request) {
		clientName := request.URL.Query().Get("clientName")
		fmt.Printf("接受到来自 %s 的http请求...\n", clientName)
		// 在http响应中写入内容
		fmt.Fprintf(writer, "你好, %s ! \n", clientName)
	})
	fmt.Println("============ HTTP服务(基于GMSSL或TLS) 已启动 ============")

	// 在tls监听器上开启https服务
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}

// 启动普通tls连接的客户端
func ClientRun() {
	// 定义tls配置
	var config = tls.Config{
		MaxVersion:         gmtls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	// tls拨号连接目标tls服务
	conn, err := tls.Dial("tcp", "localhost:50052", &config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("============ 普通tls客户端连接服务端，握手成功 ============")

	// 定义http请求
	req := []byte("GET /test?clientName=tlsClient HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	conn.Write(req)

	fmt.Println("============ 普通tls客户端向服务端发送http请求 ============")

	// 从tls连接中读取http请求响应
	buff := make([]byte, 1024)
	for {
		// 从conn读取消息，没有消息时会阻塞，直到超时
		n, _ := conn.Read(buff)
		if n <= 0 {
			// 读取不到内容时结束
			break
		} else {
			// 输出读取到的内容
			fmt.Printf("普通tls客户端从服务端获取到http响应: %s", buff[0:n])
		}
	}
	fmt.Println("============ 普通tls客户端与服务端连接测试成功 ============")
	// 将结束flag写入通道 end
	end <- true
}

func ClientRunGMSSL() {
	// 创建客户端本地的证书池
	certPool := x509.NewCertPool()
	// 读取sm2 ca证书
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		log.Fatal(err)
	}
	// 将sm2ca证书作为根证书加入证书池
	// 即，客户端相信持有该ca颁发的证书的服务端
	certPool.AppendCertsFromPEM(cacert)

	// 读取sm2User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
	// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
	// 此时该证书应该由第三方ca机构颁发签名。
	cert, _ := gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)

	// 定义gmtls配置
	// 选择最高tls协议版本为VersionGMSSL, 服务端选择的默认密码套件将是 TLS_SM4_128_GCM_SM3
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
	defer conn.Close()

	fmt.Println("============ gmtls客户端(gmssl)连接服务端，握手成功 ============")
	// time.Sleep(time.Minute)
	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(gmssl) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	fmt.Println("============ gmtls客户端(gmssl)向服务端发送http请求 ============")

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
	fmt.Println("============ gmtls客户端(gmssl)与服务端连接测试成功 ============")
	end <- true
}

func ClientRunTls13() {
	// 创建客户端本地的证书池
	certPool := x509.NewCertPool()
	// 读取sm2 ca证书
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		log.Fatal(err)
	}
	// 将sm2ca证书作为根证书加入证书池
	// 即，客户端相信持有该ca颁发的证书的服务端
	certPool.AppendCertsFromPEM(cacert)

	// 读取sm2User证书与私钥，作为客户端的证书与私钥，一般用作密钥交换证书。
	// 但如果服务端要求查看客户端证书(双向tls通信)则也作为客户端身份验证用证书，
	// 此时该证书应该由第三方ca机构颁发签名。
	cert, _ := gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)

	// 定义gmtls配置
	// 默认最高tls协议版本为tls1.3, 服务端选择的默认密码套件将是 TLS_SM4_128_GCM_SM3
	config := &gmtls.Config{
		RootCAs:      certPool,
		Certificates: []gmtls.Certificate{cert},
		// 因为sm2相关证书是由`x509/x509_test.go`的`TestCreateCertFromCA`生成的，
		// 指定了SAN包含"server.test.com"
		ServerName: "server.test.com",
	}
	// 要启用psk,除了默认SessionTicketsDisabled为false,还需要配置客户端会话缓存为非nil。
	// 这样服务端才会在握手完成后发出 newSessionTicketMsgTLS13 将加密并认证的会话票据发送给客户端。
	config.ClientSessionCache = gmtls.NewLRUClientSessionCache(1)

	// 向服务端拨号，建立tls连接
	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("============ gmtls客户端(tls1.3)连接服务端，握手成功 ============")
	// time.Sleep(time.Minute)
	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(tls1.3) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	fmt.Println("============ gmtls客户端(tls1.3)向服务端发送http请求 ============")

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
	fmt.Println("============ gmtls客户端(tls1.3)与服务端连接测试成功 ============")
	end <- true
}

var end chan bool

func Test_tls(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(false)
	time.Sleep(time.Second)
	go ClientRun()
	<-end
	go ClientRunTls13()
	<-end
	go ClientRunGMSSL()
	<-end
	fmt.Println("Test_tls over.")
}

func Test_tls12(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(false)
	time.Sleep(time.Second)
	go ClientRun()
	<-end
	fmt.Println("Test_tls12 over.")
}

func Test_tls13(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(true)
	time.Sleep(time.Second)
	go ClientRunTls13()
	<-end
	fmt.Println("Test_tls13 over.")
}

func Test_gmssl(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun(true)
	time.Sleep(time.Second)
	go ClientRunGMSSL()
	<-end
	fmt.Println("Test_tls13 over.")
}
