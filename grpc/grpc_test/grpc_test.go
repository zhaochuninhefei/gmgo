// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/*
grpc_test 是对`gitee.com/zhaochuninhefei/gmgo/grpc`的测试包
*/

package grpc_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/gmtls"
	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"gitee.com/zhaochuninhefei/gmgo/grpc/credentials"
	"gitee.com/zhaochuninhefei/gmgo/grpc/grpc_test/echo"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

//goland:noinspection GoSnakeCaseUsage
const (
	port    = ":50051"
	address = "localhost:50051"
	//ca       = "testdata/ca.cert"
	//signCert = "testdata/sign.cert"
	//signKey  = "testdata/sign.key"
	//userCert = "testdata/user.cert"
	//userKey  = "testdata/user.key"

	sm2_ca       = "testdata/sm2_ca.cert"
	sm2_signCert = "testdata/sm2_sign.cert"
	sm2_signKey  = "testdata/sm2_sign.key"
	sm2_userCert = "testdata/sm2_user.cert"
	sm2_userKey  = "testdata/sm2_user.key"

	ecdsa_ca       = "testdata/ecdsa_ca.cert"
	ecdsa_signCert = "testdata/ecdsa_sign.cert"
	ecdsa_signKey  = "testdata/ecdsa_sign.key"
	ecdsa_userCert = "testdata/ecdsa_user.cert"
	ecdsa_userKey  = "testdata/ecdsa_user.key"

	ecdsaext_ca       = "testdata/ecdsaext_ca.cert"
	ecdsaext_signCert = "testdata/ecdsaext_sign.cert"
	ecdsaext_signKey  = "testdata/ecdsaext_sign.key"
	ecdsaext_userCert = "testdata/ecdsaext_user.cert"
	ecdsaext_userKey  = "testdata/ecdsaext_user.key"
)

func TestMain(m *testing.M) {
	zcgologConfig := &zclog.Config{
		LogLevelGlobal: zclog.LOG_LEVEL_DEBUG,
	}
	zclog.InitLogger(zcgologConfig)
	go serverRun()
	time.Sleep(1000000)
	m.Run()
}

var end chan bool

func Test_credentials(t *testing.T) {
	end = make(chan bool, 64)
	//go serverRun()
	//time.Sleep(1000000)
	go clientRun()
	<-end
}

func serverRun() {
	// 准备3份服务端证书, 分别是sm2, ecdsa, ecdsaext
	var certs []gmtls.Certificate
	sm2SignCert, err := gmtls.LoadX509KeyPair(sm2_signCert, sm2_signKey)
	if err != nil {
		log.Fatal(err)
	}
	certs = append(certs, sm2SignCert)
	ecdsaSignCert, err := gmtls.LoadX509KeyPair(ecdsa_signCert, ecdsa_signKey)
	if err != nil {
		log.Fatal(err)
	}
	certs = append(certs, ecdsaSignCert)
	ecdsaextSignCert, err := gmtls.LoadX509KeyPair(ecdsaext_signCert, ecdsaext_signKey)
	if err != nil {
		log.Fatal(err)
	}
	certs = append(certs, ecdsaextSignCert)

	// 准备CA证书池，导入颁发客户端证书的CA证书
	certPool := x509.NewCertPool()
	sm2CaCert, err := ioutil.ReadFile(sm2_ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(sm2CaCert)
	ecdsaCaCert, err := ioutil.ReadFile(ecdsa_ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(ecdsaCaCert)
	ecdsaextCaCert, err := ioutil.ReadFile(ecdsaext_ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(ecdsaextCaCert)

	// 创建gmtls配置
	config := &gmtls.Config{
		Certificates: certs,
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	// 创建grpc服务端
	creds := credentials.NewTLS(config)
	s := grpc.NewServer(grpc.Creds(creds))
	echo.RegisterEchoServer(s, &server{})

	// 开启tcp监听端口
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("fail to listen: %v", err)
	}
	// 启动grpc服务
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("Serve: %v", err)
	}
}

func clientRun() {
	cert, err := gmtls.LoadX509KeyPair(sm2_userCert, sm2_userKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(sm2_ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	creds := credentials.NewTLS(&gmtls.Config{
		ServerName:   "server.test.com",
		Certificates: []gmtls.Certificate{cert},
		RootCAs:      certPool,
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
	})
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("cannot to connect: %v", err)
	}
	defer func(conn *grpc.ClientConn) {
		_ = conn.Close()
	}(conn)
	c := echo.NewEchoClient(conn)
	echoInClient(c)
	end <- true
}

// 客户端echo处理
func echoInClient(c echo.EchoClient) {
	msgClient := "hello, this is client."
	fmt.Printf("客户端发出消息: %s\n", msgClient)
	r, err := c.Echo(context.Background(), &echo.EchoRequest{Req: msgClient})
	if err != nil {
		log.Fatalf("failed to echo: %v", err)
	}
	msgServer := r.Result
	fmt.Printf("客户端收到消息: %s\n", msgServer)
}

type server struct{}

// Echo 服务端echo处理
//goland:noinspection GoUnusedParameter
func (s *server) Echo(ctx context.Context, req *echo.EchoRequest) (*echo.EchoResponse, error) {
	msgClient := req.Req
	fmt.Printf("服务端接收到消息: %s\n", msgClient)
	msgServer := "hello,this is server."
	fmt.Printf("服务端返回消息: %s\n", msgServer)
	return &echo.EchoResponse{Result: msgServer}, nil
}
