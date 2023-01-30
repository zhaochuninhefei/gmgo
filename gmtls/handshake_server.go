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

package gmtls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync/atomic"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c            *Conn
	ctx          context.Context
	clientHello  *clientHelloMsg
	hello        *serverHelloMsg
	suite        *cipherSuite
	ecdheOk      bool
	ecSignOk     bool
	rsaDecryptOk bool
	rsaSignOk    bool
	sessionState *sessionState
	finishedHash finishedHash
	masterSecret []byte
	cert         *Certificate
}

// 服务端握手
// serverHandshake performs a TLS handshake as a server.
func (c *Conn) serverHandshake(ctx context.Context) error {
	zclog.Debug("===== 开始服务端握手过程")
	// 读取 ClientHello
	clientHello, err := c.readClientHello(ctx)
	if err != nil {
		return err
	}
	// GMSSL目前采用tls1.3的处理
	if c.vers == VersionTLS13 || c.vers == VersionGMSSL {
		zclog.Debug("===== 服务端执行tls1.3或gmssl的握手过程")
		hs := serverHandshakeStateTLS13{
			c:           c,
			ctx:         ctx,
			clientHello: clientHello,
		}
		return hs.handshake()
	}
	zclog.Debug("===== 服务端执行tls1.2或更老版本的握手过程")
	hs := serverHandshakeState{
		c:           c,
		ctx:         ctx,
		clientHello: clientHello,
	}
	return hs.handshake()
}

// tls1.2及更老版本在读取ClientHello之后的握手过程
func (hs *serverHandshakeState) handshake() error {
	c := hs.c

	if err := hs.processClientHello(); err != nil {
		return err
	}

	// For an overview of TLS handshaking, see RFC 5246, Section 7.3.
	c.buffering = true
	if hs.checkForResumption() {
		// The client has included a session ticket and so we do an abbreviated handshake.
		c.didResume = true
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.readFinished(nil); err != nil {
			return err
		}
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if err := hs.pickCipherSuite(); err != nil {
			return err
		}
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		c.buffering = true
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// 读取ClientHello并选择协议版本。
// readClientHello reads a ClientHello message and selects the protocol version.
func (c *Conn) readClientHello(ctx context.Context) (*clientHelloMsg, error) {
	// 读取ClientHello
	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		errNew := unexpectedMessageError(clientHello, msg)
		err1 := c.sendAlert(alertUnexpectedMessage)
		if err1 != nil {
			return nil, fmt.Errorf("%s. Error happened when sendAlert: %s", errNew, err1)
		}
		return nil, errNew
	}
	zclog.Debug("===== 服务端读取到 ClientHello")

	var configForClient *Config
	originalConfig := c.config
	if c.config.GetConfigForClient != nil {
		chi := clientHelloInfo(ctx, c, clientHello)
		if configForClient, err = c.config.GetConfigForClient(chi); err != nil {
			errNew := fmt.Errorf("gmtls: GetConfigForClient时发生错误: %s", err)
			err1 := c.sendAlert(alertInternalError)
			if err1 != nil {
				return nil, fmt.Errorf("%s. Error happened when sendAlert: %s", errNew, err1)
			}
			return nil, errNew
		} else if configForClient != nil {
			c.config = configForClient
		}
	}
	// 为当前连接设置ticketKeys
	c.ticketKeys = originalConfig.ticketKeys(configForClient)
	// 获取ClientHello的协议版本信息，默认使用supportedVersions，没有设置supportedVersions的情况下使用vers
	clientVersions := clientHello.supportedVersions
	if len(clientHello.supportedVersions) == 0 {
		clientVersions = supportedVersionsFromMax(clientHello.vers)
	}
	// 协商tls协议版本
	c.vers, ok = c.config.mutualVersion(clientVersions)
	if !ok {
		errNew := fmt.Errorf("gmtls: client offered only unsupported versions: %x", clientVersions)
		err1 := c.sendAlert(alertProtocolVersion)
		if err1 != nil {
			return nil, fmt.Errorf("%s. Error happened when sendAlert: %s", errNew, err1)
		}
		return nil, errNew
	}
	zclog.Debug("===== 服务端选择本次tls连接使用的版本是:", ShowTLSVersion(int(c.vers)))
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers

	return clientHello, nil
}

func (hs *serverHandshakeState) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)
	hs.hello.vers = c.vers

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return fmt.Errorf("gmtls: client does not support uncompressed connections. Error happened when sendAlert: %s", err)
		}
		return errors.New("gmtls: client does not support uncompressed connections")
	}

	hs.hello.random = make([]byte, 32)
	serverRandom := hs.hello.random
	// Downgrade protection canaries. See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion()
	if maxVers >= VersionTLS12 && c.vers < maxVers || testingOnlyForceDowngradeCanary {
		if c.vers == VersionTLS12 {
			copy(serverRandom[24:], downgradeCanaryTLS12)
		} else {
			copy(serverRandom[24:], downgradeCanaryTLS11)
		}
		serverRandom = serverRandom[:24]
	}
	_, err := io.ReadFull(c.config.rand(), serverRandom)
	if err != nil {
		errNew := fmt.Errorf("gmtls: 创建serverRandom失败: %s", err)
		err1 := c.sendAlert(alertInternalError)
		if err1 != nil {
			return fmt.Errorf("%s. Error happened when sendAlert: %s", errNew, err1)
		}
		return errNew
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		err := c.sendAlert(alertHandshakeFailure)
		if err != nil {
			return fmt.Errorf("gmtls: initial handshake had non-empty renegotiation extension. Error happened when sendAlert: %s", err)
		}
		return errors.New("gmtls: initial handshake had non-empty renegotiation extension")
	}

	hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols)
	if err != nil {
		err1 := c.sendAlert(alertNoApplicationProtocol)
		if err1 != nil {
			return fmt.Errorf("%s. Error happened when sendAlert: %s", err, err1)
		}
		return err
	}
	hs.hello.alpnProtocol = selectedProto
	c.clientProtocol = selectedProto

	hs.cert, err = c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		var alt alert
		if err == errNoCertificates {
			alt = alertUnrecognizedName
		} else {
			alt = alertInternalError
		}
		err1 := c.sendAlert(alt)
		if err1 != nil {
			return fmt.Errorf("%s. Error happened when sendAlert: %s", err, err1)
		}
		return err
	}
	if hs.clientHello.scts {
		hs.hello.scts = hs.cert.SignedCertificateTimestamps
	}

	hs.ecdheOk = supportsECDHE(c.config, hs.clientHello.supportedCurves, hs.clientHello.supportedPoints)

	if hs.ecdheOk {
		// Although omitting the ec_point_formats extension is permitted, some
		// old OpenSSL version will refuse to handshake if not present.
		//
		// Per RFC 4492, section 5.1.2, implementations MUST support the
		// uncompressed point format. See golang.org/issue/31943.
		hs.hello.supportedPoints = []uint8{pointFormatUncompressed}
	}

	if priv, ok := hs.cert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *sm2.PublicKey, *ecdsa.PublicKey:
			hs.ecSignOk = true
		case ed25519.PublicKey:
			hs.ecSignOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			errNew := fmt.Errorf("gmtls: unsupported signing key type (%T)", priv.Public())
			err1 := c.sendAlert(alertInternalError)
			if err1 != nil {
				return fmt.Errorf("%s. Error happened when sendAlert: %s", errNew, err1)
			}
			return errNew
		}
	}
	if priv, ok := hs.cert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			errNew := fmt.Errorf("gmtls: unsupported decryption key type (%T)", priv.Public())
			err1 := c.sendAlert(alertInternalError)
			if err1 != nil {
				return fmt.Errorf("%s. Error happened when sendAlert: %s", errNew, err1)
			}
			return errNew
		}
	}

	return nil
}

// negotiateALPN picks a shared ALPN protocol that both sides support in server
// preference order. If ALPN is not configured or the peer doesn't support it,
// it returns "" and no error.
func negotiateALPN(serverProtos, clientProtos []string) (string, error) {
	if len(serverProtos) == 0 || len(clientProtos) == 0 {
		return "", nil
	}
	var http11fallback bool
	for _, s := range serverProtos {
		for _, c := range clientProtos {
			if s == c {
				return s, nil
			}
			if s == "h2" && c == "http/1.1" {
				http11fallback = true
			}
		}
	}
	// As a special case, let http/1.1 clients connect to h2 servers as if they
	// didn't support ALPN. We used not to enforce protocol overlap, so over
	// time a number of HTTP servers were configured with only "h2", but
	// expected to accept connections from "http/1.1" clients. See Issue 46310.
	if http11fallback {
		return "", nil
	}
	return "", fmt.Errorf("gmtls: client requested unsupported application protocols (%s)", clientProtos)
}

// supportsECDHE returns whether ECDHE key exchanges can be used with this
// pre-TLS 1.3 client.
func supportsECDHE(c *Config, supportedCurves []CurveID, supportedPoints []uint8) bool {
	supportsCurve := false
	for _, curve := range supportedCurves {
		if c.supportsCurve(curve) {
			supportsCurve = true
			break
		}
	}

	supportsPointFormat := false
	for _, pointFormat := range supportedPoints {
		if pointFormat == pointFormatUncompressed {
			supportsPointFormat = true
			break
		}
	}

	return supportsCurve && supportsPointFormat
}

func (hs *serverHandshakeState) pickCipherSuite() error {
	c := hs.c

	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(hs.clientHello.cipherSuites) {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}

	configCipherSuites := c.config.cipherSuites()
	preferenceList := make([]uint16, 0, len(configCipherSuites))
	for _, suiteID := range preferenceOrder {
		for _, id := range configCipherSuites {
			if id == suiteID {
				preferenceList = append(preferenceList, id)
				break
			}
		}
	}

	hs.suite = selectCipherSuite(preferenceList, hs.clientHello.cipherSuites, hs.cipherSuiteOk)
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("gmtls: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id

	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection. See RFC 7507.
			if hs.clientHello.vers < c.config.maxSupportedVersion() {
				c.sendAlert(alertInappropriateFallback)
				return errors.New("gmtls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return nil
}

func (hs *serverHandshakeState) cipherSuiteOk(c *cipherSuite) bool {
	if c.flags&suiteECDHE != 0 {
		if !hs.ecdheOk {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !hs.ecSignOk {
				return false
			}
		} else if !hs.rsaSignOk {
			return false
		}
	} else if !hs.rsaDecryptOk {
		return false
	}
	if hs.c.vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
		return false
	}
	return true
}

// checkForResumption reports whether we should perform resumption on this connection.
func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return false
	}

	plaintext, usedOldKey := c.decryptTicket(hs.clientHello.sessionTicket)
	if plaintext == nil {
		return false
	}
	hs.sessionState = &sessionState{usedOldKey: usedOldKey}
	ok := hs.sessionState.unmarshal(plaintext)
	if !ok {
		return false
	}

	createdAt := time.Unix(int64(hs.sessionState.createdAt), 0)
	if c.config.time().Sub(createdAt) > maxSessionTicketLifetime {
		return false
	}

	// Never resume a session for a different TLS version.
	if c.vers != hs.sessionState.vers {
		return false
	}

	cipherSuiteOk := false
	// Check that the client is still offering the ciphersuite in the session.
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}

	// Check that we also support the ciphersuite from the session.
	hs.suite = selectCipherSuite([]uint16{hs.sessionState.cipherSuite},
		c.config.cipherSuites(), hs.cipherSuiteOk)
	if hs.suite == nil {
		return false
	}

	sessionHasClientCerts := len(hs.sessionState.certificates) != 0
	needClientCerts := requiresClientCert(c.config.ClientAuth)
	if needClientCerts && !sessionHasClientCerts {
		return false
	}
	if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
		return false
	}

	return true
}

func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	c.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.ticketSupported = hs.sessionState.usedOldKey
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	if err := c.processCertsFromClient(Certificate{
		Certificate: hs.sessionState.certificates,
	}); err != nil {
		return err
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	hs.masterSecret = hs.sessionState.masterSecret

	return nil
}

// 完整握手过程 tls1.2
func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	if c.config.ClientAuth == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	certMsg := new(certificateMsg)
	certMsg.certificates = hs.cert.Certificate
	hs.finishedHash.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	if hs.hello.ocspStapling {
		certStatus := new(certificateStatusMsg)
		certStatus.response = hs.cert.OCSPStaple
		hs.finishedHash.Write(certStatus.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certStatus.marshal()); err != nil {
			return err
		}
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(c.config, hs.cert, hs.clientHello, hs.hello)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		hs.finishedHash.Write(skx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, skx.marshal()); err != nil {
			return err
		}
	}

	var certReq *certificateRequestMsg
	if c.config.ClientAuth >= RequestClientCert {
		// Request a client certificate
		certReq = new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		if c.vers >= VersionTLS12 {
			certReq.hasSignatureAlgorithm = true
			certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms
		}

		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		hs.finishedHash.Write(certReq.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certReq.marshal()); err != nil {
			return err
		}
	}

	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, helloDone.marshal()); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey // public key for client auth, if any

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	// If we requested a client certificate, then the client must send a
	// certificate message, even if it's empty.
	if c.config.ClientAuth >= RequestClientCert {
		certMsg, ok := msg.(*certificateMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}
		hs.finishedHash.Write(certMsg.marshal())

		if err := c.processCertsFromClient(Certificate{
			Certificate: certMsg.certificates,
		}); err != nil {
			return err
		}
		if len(certMsg.certificates) != 0 {
			pub = c.peerCertificates[0].PublicKey
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	hs.finishedHash.Write(ckx.marshal())

	// 获取预主密钥, 分为RSA与ECDHE
	preMasterSecret, err := keyAgreement.processClientKeyExchange(c.config, hs.cert, ckx, c.vers)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	// 根据预主密钥，随机数C、S，使用PRF函数计算主密钥
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.clientHello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	// If we received a client cert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg. This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	if len(c.peerCertificates) > 0 {
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		var sigType uint8
		var sigHash x509.Hash
		if c.vers >= VersionTLS12 {
			if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, certReq.supportedSignatureAlgorithms) {
				c.sendAlert(alertIllegalParameter)
				return errors.New("gmtls: client certificate used with invalid signature algorithm")
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
			if err != nil {
				return c.sendAlert(alertInternalError)
			}
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(pub)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash, hs.masterSecret)
		if err := verifyHandshakeSignature(sigType, pub, sigHash, signed, certVerify.signature); err != nil {
			c.sendAlert(alertDecryptError)
			return errors.New("gmtls: invalid signature by the client certificate: " + err.Error())
		}

		hs.finishedHash.Write(certVerify.marshal())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

// 派生会话密钥 tls1.2
func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c
	// 根据主密钥、随机数C/S，使用PRF函数派生出6个会话密钥
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("gmtls: client's Finished message is incorrect")
	}

	hs.finishedHash.Write(clientFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *serverHandshakeState) sendSessionTicket() error {
	// ticketSupported is set in a resumption handshake if the
	// ticket from the client was encrypted with an old session
	// ticket key and thus a refreshed ticket should be sent.
	if !hs.hello.ticketSupported {
		return nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	createdAt := uint64(c.config.time().Unix())
	if hs.sessionState != nil {
		// If this is re-wrapping an old key, then keep
		// the original time it was created.
		createdAt = hs.sessionState.createdAt
	}

	var certsFromClient [][]byte
	for _, cert := range c.peerCertificates {
		certsFromClient = append(certsFromClient, cert.Raw)
	}
	state := sessionState{
		vers:         c.vers,
		cipherSuite:  hs.suite.id,
		createdAt:    createdAt,
		masterSecret: hs.masterSecret,
		certificates: certsFromClient,
	}
	var err error
	m.ticket, err = c.encryptTicket(state.marshal())
	if err != nil {
		return err
	}

	hs.finishedHash.Write(m.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, m.marshal()); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	copy(out, finished.verifyData)

	return nil
}

// 检查客户端证书。
// processCertsFromClient takes a chain of client certificates either from a
// Certificates message or from a sessionState and verifies them. It returns
// the public key of the leaf certificate.
func (c *Conn) processCertsFromClient(certificate Certificate) error {
	certificates := certificate.Certificate
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("gmtls: failed to parse client certificate: " + err.Error())
		}
	}

	if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
		c.sendAlert(alertBadCertificate)
		return errors.New("gmtls: client didn't provide a certificate")
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		// 从子证书开始验证签名并尝试构建信任链
		chains, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("gmtls: failed to verify client certificate: " + err.Error())
		}

		c.verifiedChains = chains
	}

	c.peerCertificates = certs
	c.ocspResponse = certificate.OCSPStaple
	c.scts = certificate.SignedCertificateTimestamps

	if len(certs) > 0 {
		// 补充sm2条件
		switch certs[0].PublicKey.(type) {
		case *sm2.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		default:
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("gmtls: client certificate contains an unsupported public key of type %T", certs[0].PublicKey)
		}
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

func clientHelloInfo(ctx context.Context, c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVersions := clientHello.supportedVersions
	if len(clientHello.supportedVersions) == 0 {
		supportedVersions = supportedVersionsFromMax(clientHello.vers)
	}

	return &ClientHelloInfo{
		CipherSuites:      clientHello.cipherSuites,
		ServerName:        clientHello.serverName,
		SupportedCurves:   clientHello.supportedCurves,
		SupportedPoints:   clientHello.supportedPoints,
		SignatureSchemes:  clientHello.supportedSignatureAlgorithms,
		SupportedProtos:   clientHello.alpnProtocols,
		SupportedVersions: supportedVersions,
		Conn:              c.conn,
		config:            c.config,
		ctx:               ctx,
	}
}
