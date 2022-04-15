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
func ServerRun() {
	// 导入tls配置
	//config, err := loadRsaConfig()
	// config, err := loadSM2Config()
	// 自动根据客户端支持的协议选择对应的TLS配置(gmssl或普通tls)
	config, err := loadAutoSwitchConfig()
	//config, err:=loadAutoSwitchConfigClientAuth()
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

func gmClientRun() {
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
	// 注意没有指定客户端密码套件列表，握手时会调用 gmtls/gm_support.go 的 getCipherSuites 函数。
	// 而该函数在没有显式传入密码套件列表时，默认的列表中第一个是 GMTLS_ECC_SM4_CBC_SM3 。
	// 这就是gmtls连接默认使用的密码套件。
	config := &gmtls.Config{
		// GMSupport:    &gmtls.GMSupport{},
		RootCAs:      certPool,
		Certificates: []gmtls.Certificate{cert},
		// 因为sm2相关证书是由`x509/x509_test.go`的`TestCreateCertFromCA`生成的，
		// 指定了CN为"server.test.com"，因此客户端配置需要显式指定ServerName
		ServerName: "server.test.com",
	}

	// 向服务端拨号，建立tls连接
	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("============ gmtls客户端(GMTLS_ECC_SM4_CBC_SM3)连接服务端，握手成功 ============")
	// time.Sleep(time.Minute)
	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(GMTLS_ECC_SM4_CBC_SM3) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	fmt.Println("============ gmtls客户端(GMTLS_ECC_SM4_CBC_SM3)向服务端发送http请求 ============")

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
	fmt.Println("============ gmtls客户端(GMTLS_ECC_SM4_CBC_SM3)与服务端连接测试成功 ============")
	end <- true
}

// gmGCMClientRun GCM模式测试
func gmGCMClientRun() {
	// 建立本地信任的证书池，放入sm2ca根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)

	// 读取客户端证书
	cert, _ := gmtls.LoadX509KeyPair(sm2UserCertPath, sm2UserKeyPath)
	// 创建gmtls配置
	// 注意这里显式传入了密码套件列表，只有 GMTLS_ECC_SM4_GCM_SM3
	config := &gmtls.Config{
		// GMSupport:    &gmtls.GMSupport{},
		RootCAs:      certPool,
		Certificates: []gmtls.Certificate{cert},
		// CipherSuites: []uint16{gmtls.GMTLS_ECC_SM4_GCM_SM3},
		ServerName: "server.test.com",
	}

	// 向服务端拨号，建立tls连接
	conn, err := gmtls.Dial("tcp", "localhost:50052", config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("============ gmtls客户端(GMTLS_ECC_SM4_GCM_SM3)连接服务端，握手成功 ============")

	// 定义http请求
	req := []byte("GET /test?clientName=gmtlsClient(GMTLS_ECC_SM4_GCM_SM3) HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Connection: close\r\n\r\n")
	// 向tls连接写入请求
	_, _ = conn.Write(req)

	fmt.Println("============ gmtls客户端(GMTLS_ECC_SM4_GCM_SM3)向服务端发送http请求 ============")

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
	fmt.Println("============ gmtls客户端(GMTLS_ECC_SM4_GCM_SM3)与服务端连接测试成功 ============")
	end <- true
}

var end chan bool

func Test_tls(t *testing.T) {
	end = make(chan bool, 64)
	go ServerRun()
	time.Sleep(time.Second)
	go ClientRun()
	<-end
	go gmClientRun()
	<-end
	go gmGCMClientRun()
	<-end
	fmt.Println("Test_tls over.")
}
