// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/*
gmtls是基于`golang/go`的`tls`包实现的国密改造版本。
对应版权声明: thrid_licenses/github.com/golang/go/LICENSE
*/

// Package gmtls partially implements TLS 1.2, as specified in RFC 5246,
// and TLS 1.3, as specified in RFC 8446.
package gmtls

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecdsa_ext"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"net"
	"os"
	"strings"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
)

// Server 生成tls通信Server
// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	// 绑定握手函数
	c.handshakeFn = c.serverHandshake
	return c
}

// Client 生成tls通信Client
// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	// 绑定握手函数
	c.handshakeFn = c.clientHandshake
	return c
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *Config
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with Server.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("gmtls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

// type timeoutError struct{}

// func (timeoutError) Error() string   { return "gmtls: DialWithDialer timed out" }
// func (timeoutError) Timeout() bool   { return true }
// func (timeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of Config for the defaults.
//
// DialWithDialer uses context.Background internally; to specify the context,
// use Dialer.DialContext with NetDialer set to the desired dialer.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

// 客户端拨号,发起tls通信请求
func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}

	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := Client(rawConn, config)
	// 客户端发起tls握手
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
// Dial interprets a nil configuration as equivalent to
// the zero configuration; see the documentation of Config
// for the defaults.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// Dialer dials TLS connections given a configuration and a Dialer for the
// underlying connection.
type Dialer struct {
	// NetDialer is the optional dialer to use for the TLS connections'
	// underlying TCP connections.
	// A nil NetDialer is equivalent to the net.Dialer zero value.
	NetDialer *net.Dialer

	// Config is the TLS configuration to use for new connections.
	// A nil configuration is equivalent to the zero
	// configuration; see the documentation of Config for the
	// defaults.
	Config *Config
}

// Dial connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The returned Conn, if any, will always be of type *Conn.
//
// Dial uses context.Background internally; to specify the context,
// use DialContext.
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// DialContext connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// The returned Conn, if any, will always be of type *Conn.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		// Don't return c (a typed nil) in an interface.
		return nil, err
	}
	return c, nil
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var cert Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		// 将证书PEM字节数组解码为DER字节数组
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			// 将证书DER字节数组加入证书链的证书列表
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("gmtls: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("gmtls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("gmtls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("gmtls: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("gmtls: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("gmtls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}
	// 读取证书链中的首个证书(子证书)，转为x509.Certificate
	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	var signatures []SignatureScheme
	zclog.Debugf("x509Cert.SignatureAlgorithm: %s", x509Cert.SignatureAlgorithm.String())
	switch x509Cert.SignatureAlgorithm {
	case x509.SM2WithSM3:
		signatures = append(signatures, SM2WITHSM3)
	case x509.ECDSAWithSHA256:
		signatures = append(signatures, ECDSAWithP256AndSHA256)
	case x509.ECDSAWithSHA384:
		signatures = append(signatures, ECDSAWithP384AndSHA384)
	case x509.ECDSAWithSHA512:
		signatures = append(signatures, ECDSAWithP521AndSHA512)
	case x509.ECDSAEXTWithSHA256:
		signatures = append(signatures, ECDSAEXTWithP256AndSHA256)
	case x509.ECDSAEXTWithSHA384:
		signatures = append(signatures, ECDSAEXTWithP384AndSHA384)
	case x509.ECDSAEXTWithSHA512:
		signatures = append(signatures, ECDSAEXTWithP521AndSHA512)
	}
	if len(signatures) > 0 {
		cert.SupportedSignatureAlgorithms = signatures
	}
	zclog.Debugf("cert.SupportedSignatureAlgorithms: %s", cert.SupportedSignatureAlgorithms)

	// 将key的DER字节数组转为私钥
	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}
	// ECDSA_EXT私钥特殊处理
	if keyDERBlock.Type == "ECDSA_EXT PRIVATE KEY" {
		if privKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey); ok {
			cert.PrivateKey = &ecdsa_ext.PrivateKey{
				PrivateKey: *privKey,
			}
			zclog.Debugln("读取到ECDSA_EXT PRIVATE KEY，并转为ecdsa_ext.PrivateKey")
			hasEcdsaExt := false
			for _, algorithm := range cert.SupportedSignatureAlgorithms {
				if algorithm == ECDSAEXTWithP256AndSHA256 ||
					algorithm == ECDSAEXTWithP384AndSHA384 ||
					algorithm == ECDSAEXTWithP521AndSHA512 {
					hasEcdsaExt = true
					break
				}
			}
			if !hasEcdsaExt {
				// 临时对应，解决SupportedSignatureAlgorithms在ecdsa_ext时可能不正确的问题
				cert.SupportedSignatureAlgorithms = []SignatureScheme{ECDSAEXTWithP256AndSHA256}
				zclog.Debugf("临时修改cert.SupportedSignatureAlgorithms为: %s", cert.SupportedSignatureAlgorithms)
			}
		} else if _, ok := cert.PrivateKey.(*ecdsa_ext.PrivateKey); ok {
			// ok
		} else {
			return fail(errors.New("pem文件类型为`ECDSA_EXT PRIVATE KEY`, 但证书中的私钥类型不是*ecdsa.PrivateKey"))
		}
	}
	// 检查私钥与证书中的公钥是否匹配
	switch pub := x509Cert.PublicKey.(type) {
	// 补充SM2分支
	case *sm2.PublicKey:
		priv, ok := cert.PrivateKey.(*sm2.PrivateKey)
		if !ok {
			return fail(errors.New("gmtls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("gmtls: private key does not match public key"))
		}
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("gmtls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("gmtls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			privExt, okExt := cert.PrivateKey.(*ecdsa_ext.PrivateKey)
			if !okExt {
				return fail(errors.New("gmtls: private key type does not match public key type"))
			}
			if pub.X.Cmp(privExt.X) != 0 || pub.Y.Cmp(privExt.Y) != 0 {
				return fail(errors.New("gmtls: private key does not match public key"))
			}
		} else {
			if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
				return fail(errors.New("gmtls: private key does not match public key"))
			}
		}
	case *ecdsa_ext.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa_ext.PrivateKey)
		if !ok {
			return fail(errors.New("gmtls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("gmtls: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("gmtls: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("gmtls: private key does not match public key"))
		}
	default:
		return fail(errors.New("gmtls: unknown public key algorithm"))
	}

	return cert, nil
}

// 将DER字节数组转为对应的私钥
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		// 添加SM2, ecdsa_ext
		case *sm2.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey, *ecdsa_ext.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("gmtls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("gmtls: failed to parse private key")
}

// NewServerConfigByClientHello 根据客户端发出的ClientHello的协议与密码套件决定Server的证书链
//  当客户端支持tls1.3或gmssl，且客户端支持的密码套件包含 TLS_SM4_GCM_SM3 时，服务端证书采用gmSigCert。
//  - gmSigCert 国密证书
//  - genericCert 一般证书
//goland:noinspection GoUnusedExportedFunction
func NewServerConfigByClientHello(gmSigCert, genericCert *Certificate) (*Config, error) {
	// 根据ClientHelloInfo中支持的协议，返回服务端证书
	fncGetSignCertKeypair := func(info *ClientHelloInfo) (*Certificate, error) {
		gmFlag := false
		// 检查客户端支持的协议中是否包含TLS1.3或GMSSL
		for _, v := range info.SupportedVersions {
			if v == VersionGMSSL || v == VersionTLS13 {
				for _, curveID := range info.SupportedCurves {
					if curveID == Curve256Sm2 {
						gmFlag = true
						break
					}
				}
				if gmFlag {
					break
				}
				// 检查客户端支持的密码套件是否包含 TLS_SM4_GCM_SM3
				for _, c := range info.CipherSuites {
					if c == TLS_SM4_GCM_SM3 {
						gmFlag = true
						break
					}
				}
				break
			}
		}
		if gmFlag {
			return gmSigCert, nil
		} else {
			return genericCert, nil
		}
	}

	return &Config{
		Certificates:   nil,
		GetCertificate: fncGetSignCertKeypair,
	}, nil
}

//func NewServerConfigByClientHelloCurve(certMap map[string]*Certificate) (*Config, error) {
//	// 根据ClientHelloInfo中支持的协议，返回服务端证书
//	fncGetSignCertKeypair := func(info *ClientHelloInfo) (*Certificate, error) {
//		//info.config.CurvePreferences
//
//		gmFlag := false
//		// 检查客户端支持的协议中是否包含TLS1.3或GMSSL
//		for _, v := range info.SupportedVersions {
//			if v == VersionGMSSL || v == VersionTLS13 {
//				// 检查客户端支持的密码套件是否包含 TLS_SM4_GCM_SM3
//				for _, c := range info.CipherSuites {
//					if c == TLS_SM4_GCM_SM3 {
//						gmFlag = true
//						break
//					}
//				}
//				break
//			}
//		}
//		if gmFlag {
//			return gmSigCert, nil
//		} else {
//			return genericCert, nil
//		}
//	}
//
//	return &Config{
//		Certificates:   nil,
//		GetCertificate: fncGetSignCertKeypair,
//	}, nil
//}
