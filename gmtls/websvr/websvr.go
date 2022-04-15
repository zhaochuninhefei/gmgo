package websvr

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"gitee.com/zhaochuninhefei/gmgo/gmtls"
	gx509 "gitee.com/zhaochuninhefei/gmgo/x509"
)

const (
	rsaCertPath     = "./certs/rsa_sign.cer"
	rsaKeyPath      = "./certs/rsa_sign_key.pem"
	RSACaCertPath   = "./certs/RSA_CA.cer"
	RSAAuthCertPath = "./certs/rsa_auth_cert.cer"
	RSAAuthKeyPath  = "./certs/rsa_auth_key.pem"
	SM2CaCertPath   = "./certs/sm2_ca_cert.cer"
	SM2AuthCertPath = "./certs/sm2_auth_cert.cer"
	SM2AuthKeyPath  = "./certs/sm2_auth_key.pem"
	sm2SignCertPath = "./certs/sm2_sign_cert.cer"
	sm2SignKeyPath  = "./certs/sm2_sign_key.pem"
	sm2EncCertPath  = "./certs/sm2_enc_cert.cer"
	sm2EncKeyPath   = "./certs/sm2_enc_key.pem"
)

// RSA配置
func loadRsaConfig() (*gmtls.Config, error) {
	cert, err := gmtls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{Certificates: []gmtls.Certificate{cert}}, nil
}

// SM2配置
func loadSM2Config() (*gmtls.Config, error) {
	sigCert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		// GMSupport:    &gmtls.GMSupport{},
		Certificates: []gmtls.Certificate{sigCert, encCert},
	}, nil
}

// 切换GMSSL/TSL
func loadAutoSwitchConfig() (*gmtls.Config, error) {
	// 读取rsa证书与私钥，作为普通tls场景的服务器证书用
	rsaKeypair, err := gmtls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	// 读取sm2Sign证书与私钥，作为国密tls场景的服务器证书用
	sigCert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	// 读取sm2Enc证书与私钥，作为国密tls场景的密钥交换证书用
	encCert, err := gmtls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err
	}
	// 返回自动切换的配置
	config, err := gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
	if err != nil {
		return nil, err
	}

	// 如果服务端想要验证客户端身份，在这里添对应配置
	// // 信任的根证书
	// certPool := gx509.NewCertPool()
	// cacert, err := ioutil.ReadFile(SM2CaCertPath)
	// if err != nil {
	// 	return nil, err
	// }
	// certPool.AppendCertsFromPEM(cacert)
	// config.ClientAuth = gmtls.RequireAndVerifyClientCert
	// config.ClientCAs = certPool
	// fmt.Println("------ debug用 : 服务端配置了双向tls通信")

	return config, nil
}

// 双向身份认证 服务端配置
func loadServerMutualTLCPAuthConfig() (*gmtls.Config, error) {
	// 签名密钥对/证书 和 加密密钥对/证书
	sigCert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err

	}

	// 信任的根证书
	certPool := gx509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &gmtls.Config{
		// GMSupport:    gmtls.NewGMSupport(),
		Certificates: []gmtls.Certificate{sigCert, encCert},
		ClientCAs:    certPool,
		ClientAuth:   gmtls.RequireAndVerifyClientCert,
	}, nil
}

// 要求客户端身份认证
func loadAutoSwitchConfigClientAuth() (*gmtls.Config, error) {
	config, err := loadAutoSwitchConfig()
	if err != nil {
		return nil, err
	}
	// 设置需要客户端证书请求，标识需要进行客户端的身份认证
	config.ClientAuth = gmtls.RequireAndVerifyClientCert
	return config, nil
}

// 获取 客户端服务端双向身份认证 配置
func bothAuthConfig() (*gmtls.Config, error) {
	// 信任的根证书
	certPool := gx509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := gmtls.LoadX509KeyPair(SM2AuthCertPath, SM2AuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		// GMSupport:          &gmtls.GMSupport{},
		RootCAs:            certPool,
		Certificates:       []gmtls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func singleSideAuthConfig() (*gmtls.Config, error) {
	// 信任的根证书
	certPool := gx509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &gmtls.Config{
		// GMSupport: &gmtls.GMSupport{},
		RootCAs: certPool,
	}, nil
}

// 获取 客户端服务端双向身份认证 配置
func rsaBothAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tls.LoadX509KeyPair(RSAAuthCertPath, RSAAuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func rsaSingleSideAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tls.Config{
		MaxVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}, nil
}
