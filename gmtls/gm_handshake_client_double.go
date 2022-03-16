// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
)

type clientHandshakeStateGM struct {
	c            *Conn
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *ClientSessionState
}

// 创建国密ClientHello
func makeClientHelloGM(config *Config) (*clientHelloMsg, error) {
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	hello := &clientHelloMsg{
		// tls协议版本 : VersionGMSSL
		vers: config.GMSupport.GetVersion(),
		// 压缩方法列表
		compressionMethods: []uint8{compressionNone},
		// ClientRadom 后续计算主密钥时使用
		random:     make([]byte, 32),
		serverName: hostnameInSNI(config.ServerName),
	}
	// 定义客户端密码套件列表
	possibleCipherSuites := getCipherSuites(config)
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

	// 将gmtls支持的国密密码套件补充进来
NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range config.GMSupport.cipherSuites() {
			if suite.id != suiteId {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	// 填充ClientRandom
	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	return hello, nil
}

// 由客户端发起的握手
// Does the handshake, either a full one or resumes old session.
// Requires hs.c, hs.hello, and, optionally, hs.session to be set.
func (hs *clientHandshakeStateGM) handshake() error {
	c := hs.c

	// send ClientHello
	// 向tls连接写入 ClientHello
	// fmt.Println("------ debug用 : 客户端向tls连接写入 ClientHello")
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	// 等待服务端返回握手消息
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	// 首次返回的握手信息应该是 ServerHello
	var ok bool
	if hs.serverHello, ok = msg.(*serverHelloMsg); !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(hs.serverHello, msg)
	}
	// fmt.Println("------ debug用 : 客户端接收到 ServerHello")

	// 匹配tls协议
	if hs.serverHello.vers != VersionGMSSL {
		hs.c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x, while expecting %x", hs.serverHello.vers, VersionGMSSL)
	}

	// 匹配密码套件
	if err = hs.pickCipherSuite(); err != nil {
		return err
	}

	// 检查 ServerHello
	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	// 创建Finished
	hs.finishedHash = newFinishedHashGM(hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}
	// 向finished写入ClientHello与ServerHello
	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		// 执行完整握手
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		// 创建会话密钥
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// 发送finished
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		// 读取服务端finished
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	c.didResume = isResume
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// 匹配密码套件
func (hs *clientHandshakeStateGM) pickCipherSuite() error {
	if hs.suite = mutualCipherSuiteGM(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

// 接收到ServerHello之后执行完整握手
func (hs *clientHandshakeStateGM) doFullHandshake() error {
	c := hs.c

	// 从连接读取下一条握手信息
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	// ServerHello之后应该是 ServerCertificate
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	// fmt.Println("------ debug用 : 客户端接收到 ServerCertificate")

	// mod by syl only one cert
	// Thanks to dual certificates mechanism, length of certificates in GMT0024 must great than 2
	if len(certMsg.certificates) < 2 {
		c.sendAlert(alertInsufficientSecurity)
		return fmt.Errorf("tls: length of certificates in GMT0024 must great than 2")
	}
	// 在finished中写入ServerCertificate
	hs.finishedHash.Write(certMsg.marshal())

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		certs := make([]*x509.Certificate, len(certMsg.certificates))
		for i, asn1Data := range certMsg.certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			// 检查证书公钥类型是否sm2
			// TODO ecdsa -> sm2
			pubKey, _ := cert.PublicKey.(*sm2.PublicKey)
			// 直接检查公钥的椭圆曲线参数是否匹配sm2
			if pubKey.Curve != sm2.P256Sm2() {
				c.sendAlert(alertUnsupportedCertificate)
				return fmt.Errorf("tls: pubkey type of cert is error, expect sm2.publicKey")
			}

			//cert[0] is for signature while cert[1] is for encipher, refer to  GMT0024
			//check key usage
			// 服务端证书的第一个是签名证书，第二个是密码协商用证书。
			switch i {
			case 0:
				if cert.KeyUsage == 0 || (cert.KeyUsage&(x509.KeyUsageDigitalSignature|cert.KeyUsage&x509.KeyUsageContentCommitment)) == 0 {
					c.sendAlert(alertInsufficientSecurity)
					return fmt.Errorf("tls: the keyusage of cert[0] does not exist or is not for KeyUsageDigitalSignature/KeyUsageContentCommitment, value:%d", cert.KeyUsage)
				}
			case 1:
				if cert.KeyUsage == 0 || (cert.KeyUsage&(x509.KeyUsageDataEncipherment|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement)) == 0 {
					c.sendAlert(alertInsufficientSecurity)
					return fmt.Errorf("tls: the keyusage of cert[1] does not exist or is not for KeyUsageDataEncipherment/KeyUsageKeyEncipherment/KeyUsageKeyAgreement, value:%d", cert.KeyUsage)
				}
			}

			certs[i] = cert
		}

		// 对服务端证书做验签
		if !c.config.InsecureSkipVerify {
			opts := x509.VerifyOptions{
				Roots:         c.config.RootCAs,
				CurrentTime:   c.config.time(),
				DNSName:       c.config.ServerName,
				Intermediates: x509.NewCertPool(),
			}
			if opts.Roots == nil {
				opts.Roots = x509.NewCertPool()
			}

			for _, rootca := range getCAs() {
				opts.Roots.AddCert(rootca)
			}
			for i, cert := range certs {
				// GM SSL 证书链中不含根证书 第1张为签名证书、第2张为加密证书，其他的证书都认为是根证书
				if i == 0 || i == 1 {
					// 只验证 签名证书  和 加密证书
					c.verifiedChains, err = certs[i].Verify(opts)
					if err != nil {
						_ = c.sendAlert(alertBadCertificate)
						return err
					}
					continue
				}
				opts.Intermediates.AddCert(cert)
			}

		}

		if c.config.VerifyPeerCertificate != nil {
			if err := c.config.VerifyPeerCertificate(certMsg.certificates, c.verifiedChains); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}

		switch certs[0].PublicKey.(type) {
		case *sm2.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey:
			break
		default:
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
		}

		c.peerCertificates = certs
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	// 获取下一条握手信息，这里应该是 ServerKeyExchange
	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	keyAgreement := hs.suite.ka(c.vers)
	if ka, ok := keyAgreement.(*eccKeyAgreementGM); ok {
		ka.encipherCert = c.peerCertificates[1]
	}

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		// fmt.Println("------ debug用 : 客户端接收到 ServerKeyExchange")
		// 将ServerKeyExchange写入finished
		hs.finishedHash.Write(skx.marshal())
		// 检查ServerKeyExchange 这里好像是检查签名之类的处理。 具体实现代码位置 : gmtls/gm_key_agreement.go
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		// 读取下一条握手信息，这里可能是 ServerHelloDone 或 CertificateRequest
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// 如果刚刚收到的握手消息是 CertificateRequest
	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsgGM)
	if ok {
		// fmt.Println("------ debug用 : 客户端接收到 CertificateRequest")
		certRequested = true
		// 将CertificateRequest写入finished
		hs.finishedHash.Write(certReq.marshal())
		// 根据 CertificateRequest 创建客户端证书链
		if chainToSend, err = hs.getCertificate(certReq); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		// 读取下一条握手信息，这里是 ServerHelloDone
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	// fmt.Println("------ debug用 : 客户端接收到 ServerHelloDone")
	// 将ServerHelloDone写入finished
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	// 如果服务端请求客户端证书，这里需要先发送客户端证书链
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		// 将客户端发送的 Certificate 写入finished
		hs.finishedHash.Write(certMsg.marshal())
		// 发送 客户端 Certificate
		// fmt.Println("------ debug用 : 客户端发送 Certificate")
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	// 计算预主密钥 preMasterSecret ，并创建 ClientKeyExchange ，代码位于: gmtls/gm_key_agreement.go
	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[1])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		// 向finished写入 ClientKeyExchange
		hs.finishedHash.Write(ckx.marshal())
		// 发送 ClientKeyExchange
		// fmt.Println("------ debug用 : 客户端发送 ClientKeyExchange")
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	// 如果发送了客户端证书，这里就需要发送客户端证书的 CertificateVerify
	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}
		// 获取客户端证书私钥
		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}
		// 计算签名内容摘要 TODO 这里是否需要补充sm2的特殊对应: sm2的签名不需要实现计算摘要值。
		digest := hs.finishedHash.client.Sum(nil)
		// 签名
		certVerify.signature, err = key.Sign(c.config.rand(), digest, nil)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		// 将 CertificateVerify 写入finished
		hs.finishedHash.Write(certVerify.marshal())
		// 发送 CertificateVerify
		// fmt.Println("------ debug用 : 客户端发送 CertificateVerify")
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	// 计算主密钥
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

// 根据主密钥创建会话密钥
func (hs *clientHandshakeStateGM) establishKeys() error {
	c := hs.c

	// 根据主密钥创建本次会话使用的相关密钥: clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV
	// clientMAC, serverMAC : 对消息块进行散列认证的key
	// clientKey, serverKey : 对消息块进行对称加密的key
	// clientIV, serverIV : 对消息块进行对称加密的初始化向量
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeStateGM) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

// 检查ServerHello
func (hs *clientHandshakeStateGM) processServerHello() (bool, error) {
	c := hs.c

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	clientDidNPN := hs.hello.nextProtoNeg
	clientDidALPN := len(hs.hello.alpnProtocols) > 0
	serverHasNPN := hs.serverHello.nextProtoNeg
	serverHasALPN := len(hs.serverHello.alpnProtocol) > 0

	if !clientDidNPN && serverHasNPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested NPN extension")
	}

	if !clientDidALPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested ALPN extension")
	}

	if serverHasNPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised both NPN and ALPN extensions")
	}

	if serverHasALPN {
		c.clientProtocol = hs.serverHello.alpnProtocol
		c.clientProtocolFallback = false
	}
	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret and peerCerts from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	return true, nil
}

func (hs *clientHandshakeStateGM) readFinished(out []byte) error {
	c := hs.c

	// 读取服务端 ChangeCipherSpec
	c.readRecord(recordTypeChangeCipherSpec)
	if c.in.err != nil {
		return c.in.err
	}
	// fmt.Println("------ debug用 : 客户端接受到 ChangeCipherSpec")

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}
	// fmt.Println("------ debug用 : 客户端接受到 serverFinished")

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeStateGM) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
	}

	return nil
}

// 发送 Finished
func (hs *clientHandshakeStateGM) sendFinished(out []byte) error {
	c := hs.c
	// 先发送 ChangeCipherSpec 告诉服务端，之后的通信使用协商好的会话密钥
	// fmt.Println("------ debug用 : 客户端发送 ChangeCipherSpec")
	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		hs.finishedHash.Write(nextProto.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, nextProto.marshal()); err != nil {
			return err
		}
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	// 发送 Finished
	// fmt.Println("------ debug用 : 客户端发送 Finished")
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

//// tls11SignatureSchemes contains the signature schemes that we synthesise for
//// a TLS <= 1.1 connection, based on the supported certificate types.
//var tls11SignatureSchemes = []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1}
//
//const (
//	// tls11SignatureSchemesNumECDSA is the number of initial elements of
//	// tls11SignatureSchemes that use ECDSA.
//	tls11SignatureSchemesNumECDSA = 3
//	// tls11SignatureSchemesNumRSA is the number of trailing elements of
//	// tls11SignatureSchemes that use RSA.
//	tls11SignatureSchemesNumRSA = 4
//)

func (hs *clientHandshakeStateGM) getCertificate(certReq *certificateRequestMsgGM) (*Certificate, error) {
	c := hs.c

	if c.config.GetClientCertificate != nil {
		var signatureSchemes []SignatureScheme

		return c.config.GetClientCertificate(&CertificateRequestInfo{
			AcceptableCAs:    certReq.certificateAuthorities,
			SignatureSchemes: signatureSchemes,
		})
	}

	// RFC 4346 on the certificateAuthorities field: A list of the
	// distinguished names of acceptable certificate authorities.
	// These distinguished names may specify a desired
	// distinguished name for a root CA or for a subordinate CA;
	// thus, this message can be used to describe both known roots
	// and a desired authorization space. If the
	// certificate_authorities list is empty then the client MAY
	// send any certificate of the appropriate
	// ClientCertificateType, unless there is some external
	// arrangement to the contrary.

	// We need to search our list of client certs for one
	// where SignatureAlgorithm is acceptable to the server and the
	// Issuer is in certReq.certificateAuthorities
findCert:
	for i, chain := range c.config.Certificates {

		for j, cert := range chain.Certificate {
			x509Cert := chain.Leaf
			// parse the certificate if this isn't the leaf
			// node, or if chain.Leaf was nil
			if j != 0 || x509Cert == nil {
				var err error
				if x509Cert, err = x509.ParseCertificate(cert); err != nil {
					c.sendAlert(alertInternalError)
					return nil, errors.New("tls: failed to parse client certificate #" + strconv.Itoa(i) + ": " + err.Error())
				}
			}

			var isGMCert bool

			if x509Cert.PublicKeyAlgorithm == x509.ECDSA {
				pubKey, ok := x509Cert.PublicKey.(*ecdsa.PublicKey)
				if ok && pubKey.Curve == sm2.P256Sm2() {
					isGMCert = true
				}
			}

			if !isGMCert {
				continue findCert
			}

			if len(certReq.certificateAuthorities) == 0 {
				// they gave us an empty list, so just take the
				// first cert from c.config.Certificates
				return &chain, nil
			}

			for _, ca := range certReq.certificateAuthorities {
				if bytes.Equal(x509Cert.RawIssuer, ca) {
					return &chain, nil
				}
			}
		}
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}
