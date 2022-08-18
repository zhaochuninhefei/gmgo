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
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"errors"
	"hash"
	"io"
	"sync/atomic"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

// maxClientPSKIdentities is the number of client PSK identities the server will
// attempt to validate. It will ignore the rest not to let cheap ClientHello
// messages cause too much work in session ticket decryption attempts.
const maxClientPSKIdentities = 5

type serverHandshakeStateTLS13 struct {
	c               *Conn
	ctx             context.Context
	clientHello     *clientHelloMsg
	hello           *serverHelloMsg
	sentDummyCCS    bool
	usingPSK        bool
	suite           *cipherSuiteTLS13
	cert            *Certificate
	sigAlg          SignatureScheme
	earlySecret     []byte
	sharedKey       []byte
	handshakeSecret []byte
	masterSecret    []byte
	trafficSecret   []byte // client_application_traffic_secret_0
	transcript      hash.Hash
	clientFinished  []byte
}

// tls1.3在接收到ClientHello之后的握手过程
func (hs *serverHandshakeStateTLS13) handshake() error {
	c := hs.c

	// For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.

	// 处理ClientHello,协商密码套件,计算共享密钥
	if err := hs.processClientHello(); err != nil {
		return err
	}
	// 检查会话恢复
	if err := hs.checkForResumption(); err != nil {
		return err
	}
	// 选择服务端证书
	if err := hs.pickCertificate(); err != nil {
		return err
	}
	c.buffering = true
	// 发送 ServerHello,DummyChangeCipherSpec,EncryptedExtensions
	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	// 发送 certificateRequestMsgTLS13,certificateMsgTLS13,certificateVerifyMsg
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	// 发送 ServerFinished
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	// Note that at this point we could start sending application data without
	// waiting for the client's second flight, but the application might not
	// expect the lack of replay protection of the ClientHello parameters.
	if _, err := c.flush(); err != nil {
		return err
	}
	// 读取客户端证书，验证后发送 sessionTicket
	if err := hs.readClientCertificate(); err != nil {
		return err
	}
	// 读取 ClientFinished
	if err := hs.readClientFinished(); err != nil {
		return err
	}

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// 对 ClientHello 进行处理, 协商密码套件并计算共享密钥
func (hs *serverHandshakeStateTLS13) processClientHello() error {
	c := hs.c

	hs.hello = new(serverHelloMsg)
	// 兼容性对应
	// TLS 1.3 froze the ServerHello.legacy_version field, and uses
	// supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
	hs.hello.vers = VersionTLS12
	// 扩展信息 supportedVersion 使用之前协商好的tls协议版本
	hs.hello.supportedVersion = c.vers

	if len(hs.clientHello.supportedVersions) == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: client used the legacy version field to negotiate TLS 1.3")
	}

	// Abort if the client is doing a fallback and landing lower than what we
	// support. See RFC 7507, which however does not specify the interaction
	// with supported_versions. The only difference is that with
	// supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
	// handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
	// it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
	// TLS 1.2, because a TLS 1.3 server would abort here. The situation before
	// supported_versions was not better because there was just no way to do a
	// TLS 1.4 handshake without risking the server selecting TLS 1.3.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// Use c.vers instead of max(supported_versions) because an attacker
			// could defeat this by adding an arbitrary high version otherwise.
			if c.vers < c.config.maxSupportedVersion() {
				c.sendAlert(alertInappropriateFallback)
				return errors.New("gmtls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	if len(hs.clientHello.compressionMethods) != 1 ||
		hs.clientHello.compressionMethods[0] != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: TLS 1.3 client supports illegal compression methods")
	}

	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("gmtls: initial handshake had non-empty renegotiation extension")
	}

	if hs.clientHello.earlyData {
		// See RFC 8446, Section 4.2.10 for the complicated behavior required
		// here. The scenario is that a different server at our address offered
		// to accept early data in the past, which we can't handle. For now, all
		// 0-RTT enabled session tickets need to expire before a Go server can
		// replace a server or join a pool. That's the same requirement that
		// applies to mixing or replacing with any TLS 1.2 server.
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("gmtls: client sent unexpected early data")
	}

	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.compressionMethod = compressionNone
	// 协商密码套件
	preferenceList := defaultCipherSuitesTLS13
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(hs.clientHello.cipherSuites) {
		preferenceList = defaultCipherSuitesTLS13NoAES
	}
	for _, suiteID := range preferenceList {
		hs.suite = mutualCipherSuiteTLS13(hs.clientHello.cipherSuites, suiteID)
		if hs.suite != nil {
			break
		}
	}
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("gmtls: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id
	hs.hello.cipherSuite = hs.suite.id
	zclog.Debugf("===== 服务端协商密码套件: %s", CipherSuiteName(hs.suite.id))
	// 使用密码套件的散列函数作为握手数据摘要函数
	hs.transcript = hs.suite.hash.New()

	// Pick the ECDHE group in server preference order, but give priority to
	// groups with a key share, to avoid a HelloRetryRequest round-trip.
	var selectedGroup CurveID
	var clientKeyShare *keyShare
GroupSelection:
	for _, preferredGroup := range c.config.curvePreferences() {
		for _, ks := range hs.clientHello.keyShares {
			if ks.group == preferredGroup {
				selectedGroup = ks.group
				clientKeyShare = &ks
				break GroupSelection
			}
		}
		if selectedGroup != 0 {
			continue
		}
		for _, group := range hs.clientHello.supportedCurves {
			if group == preferredGroup {
				selectedGroup = group
				break
			}
		}
	}
	if selectedGroup == 0 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("gmtls: no ECDHE curve supported by both client and server")
	}
	// 未能获取客户端共享密钥
	if clientKeyShare == nil {
		// 请求客户端重新发送ClientHello以获取共享密钥
		if err := hs.doHelloRetryRequest(selectedGroup); err != nil {
			return err
		}
		clientKeyShare = &hs.clientHello.keyShares[0]
	}
	// var curve elliptic.Curve
	var curveOk bool
	var curveName string
	if curveName, curveOk = CheckCurveNameById(selectedGroup); !curveOk {
		c.sendAlert(alertInternalError)
		return errors.New("gmtls: CurvePreferences includes unsupported curve")
	}
	// 生成服务端的密钥交换算法参数，即对应曲线的公私钥
	params, err := generateECDHEParameters(c.config.rand(), selectedGroup)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	zclog.Debugf("===== 服务端使用曲线 %s 生成密钥交换算法参数", curveName)
	// 设置服务端密钥交换算法参数(曲线ID + 服务端公钥)
	hs.hello.serverShare = keyShare{group: selectedGroup, data: params.PublicKey()}
	// 根据客户端公钥与服务端公钥计算预主密钥
	zclog.Debugf("===== 服务端使用曲线 %s 与客户端公钥计算共享密钥", curveName)
	hs.sharedKey = params.SharedKey(clientKeyShare.data)
	if hs.sharedKey == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: invalid client key share")
	}

	c.serverName = hs.clientHello.serverName
	return nil
}

// 检查会话恢复
func (hs *serverHandshakeStateTLS13) checkForResumption() error {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return nil
	}

	modeOK := false
	for _, mode := range hs.clientHello.pskModes {
		if mode == pskModeDHE {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return nil
	}

	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: invalid or missing PSK binders")
	}
	if len(hs.clientHello.pskIdentities) == 0 {
		return nil
	}
	// 尝试从 ClientHello的pskid集合中选取一个作为本次会话的公钥密钥。
	// 如果客户端就是本代码实现的客户端，那么pskIdentities中最多只会有一个 pskIdentitie
	for i, identity := range hs.clientHello.pskIdentities {
		if i >= maxClientPSKIdentities {
			break
		}
		// 对pskIdentitie的label解密得到sessionStateTLS13的序列化明文
		plaintext, _ := c.decryptTicket(identity.label)
		if plaintext == nil {
			continue
		}
		// 反序列化为sessionStateTLS13
		sessionState := new(sessionStateTLS13)
		if ok := sessionState.unmarshal(plaintext); !ok {
			continue
		}
		// 检查sessionTicket最大存活时间
		createdAt := time.Unix(int64(sessionState.createdAt), 0)
		if c.config.time().Sub(createdAt) > maxSessionTicketLifetime {
			continue
		}

		// We don't check the obfuscated ticket age because it's affected by
		// clock skew and it's only a freshness signal useful for shrinking the
		// window for replay attacks, which don't affect us as we don't do 0-RTT.

		// 选取该会话的密码套件
		pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
		if pskSuite == nil || pskSuite.hash != hs.suite.hash {
			continue
		}

		// PSK connections don't re-establish client certificates, but carry
		// them over in the session ticket. Ensure the presence of client certs
		// in the ticket is consistent with the configured requirements.
		sessionHasClientCerts := len(sessionState.certificate.Certificate) != 0
		needClientCerts := requiresClientCert(c.config.ClientAuth)
		if needClientCerts && !sessionHasClientCerts {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
			continue
		}
		// 使用会话状态中保存的恢复用机密扩展为psk
		psk := hs.suite.expandLabel(sessionState.resumptionSecret, "resumption",
			nil, hs.suite.hash.Size())
		// 再基于psk派生早期机密
		hs.earlySecret = hs.suite.extract(psk, nil)
		// 再基于早期机密派生绑定者密钥
		binderKey := hs.suite.deriveSecret(hs.earlySecret, resumptionBinderLabel, nil)
		// 复制一个转录散列函数
		// Clone the transcript in case a HelloRetryRequest was recorded.
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			c.sendAlert(alertInternalError)
			return errors.New("gmtls: internal error: failed to clone hash")
		}
		// 向转录散列写入不带pskBinders的ClientHello
		transcript.Write(hs.clientHello.marshalWithoutBinders())
		// 生成pskBinders: 使用绑定者密钥和转录散列生成的Finished消息散列
		pskBinder := hs.suite.finishedHash(binderKey, transcript)
		// 检查clientHello与服务端计算出的pskBinder的认证码是否一致
		if !hmac.Equal(hs.clientHello.pskBinders[i], pskBinder) {
			c.sendAlert(alertDecryptError)
			return errors.New("gmtls: invalid PSK binder")
		}
		// 向连接写入会话恢复标识
		c.didResume = true
		// 检查客户端短证书
		if err := c.processCertsFromClient(sessionState.certificate); err != nil {
			return err
		}
		// 在ServerHello中填写会话恢复相关字段
		hs.hello.selectedIdentityPresent = true
		hs.hello.selectedIdentity = uint16(i)
		hs.usingPSK = true
		return nil
	}

	return nil
}

// cloneHash uses the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
// interfaces implemented by standard library hashes to clone the state of in
// to a new instance of h. It returns nil if the operation fails.
func cloneHash(in hash.Hash, h x509.Hash) hash.Hash {
	// Recreate the interface to avoid importing encoding.
	type binaryMarshaler interface {
		MarshalBinary() (data []byte, err error)
		UnmarshalBinary(data []byte) error
	}
	marshaler, ok := in.(binaryMarshaler)
	if !ok {
		return nil
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil
	}
	out := h.New()
	unmarshaler, ok := out.(binaryMarshaler)
	if !ok {
		return nil
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil
	}
	return out
}

// 选择服务端证书
func (hs *serverHandshakeStateTLS13) pickCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
	if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
		return c.sendAlert(alertMissingExtension)
	}

	certificate, err := c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			c.sendAlert(alertUnrecognizedName)
		} else {
			c.sendAlert(alertInternalError)
		}
		return err
	}
	hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
	if err != nil {
		// getCertificate returned a certificate that is unsupported or
		// incompatible with the client's signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.cert = certificate

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	_, err := hs.c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// 向客户端发送 HelloRetryRequest , 请求重新发送 ClientHello
func (hs *serverHandshakeStateTLS13) doHelloRetryRequest(selectedGroup CurveID) error {
	c := hs.c
	// 将ClientHello散列后重新写入握手数据摘要
	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	hs.transcript.Write(hs.clientHello.marshal())
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	// 创建 HelloRetryRequest
	helloRetryRequest := &serverHelloMsg{
		vers:              hs.hello.vers,
		random:            helloRetryRequestRandom, // 客户端通过该random值判断是否HelloRetryRequest
		sessionId:         hs.hello.sessionId,
		cipherSuite:       hs.hello.cipherSuite,
		compressionMethod: hs.hello.compressionMethod,
		supportedVersion:  hs.hello.supportedVersion,
		selectedGroup:     selectedGroup,
	}
	// 将HelloRetryRequest写入握手数据摘要
	hs.transcript.Write(helloRetryRequest.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, helloRetryRequest.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发送 HelloRetryRequest")
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	// 读取下一条消息, 客户端重新发送的 ClientHello
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientHello, msg)
	}
	zclog.Debug("===== 服务端读取到客户端重新发送的 ClientHello")
	if len(clientHello.keyShares) != 1 || clientHello.keyShares[0].group != selectedGroup {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: client sent invalid key share in second ClientHello")
	}

	if clientHello.earlyData {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: client indicated early data in second ClientHello")
	}

	if illegalClientHelloChange(clientHello, hs.clientHello) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: client illegally modified second ClientHello")
	}

	hs.clientHello = clientHello
	return nil
}

// illegalClientHelloChange reports whether the two ClientHello messages are
// different, with the exception of the changes allowed before and after a
// HelloRetryRequest. See RFC 8446, Section 4.1.2.
func illegalClientHelloChange(ch, ch1 *clientHelloMsg) bool {
	if len(ch.supportedVersions) != len(ch1.supportedVersions) ||
		len(ch.cipherSuites) != len(ch1.cipherSuites) ||
		len(ch.supportedCurves) != len(ch1.supportedCurves) ||
		len(ch.supportedSignatureAlgorithms) != len(ch1.supportedSignatureAlgorithms) ||
		len(ch.supportedSignatureAlgorithmsCert) != len(ch1.supportedSignatureAlgorithmsCert) ||
		len(ch.alpnProtocols) != len(ch1.alpnProtocols) {
		return true
	}
	for i := range ch.supportedVersions {
		if ch.supportedVersions[i] != ch1.supportedVersions[i] {
			return true
		}
	}
	for i := range ch.cipherSuites {
		if ch.cipherSuites[i] != ch1.cipherSuites[i] {
			return true
		}
	}
	for i := range ch.supportedCurves {
		if ch.supportedCurves[i] != ch1.supportedCurves[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithms {
		if ch.supportedSignatureAlgorithms[i] != ch1.supportedSignatureAlgorithms[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsCert {
		if ch.supportedSignatureAlgorithmsCert[i] != ch1.supportedSignatureAlgorithmsCert[i] {
			return true
		}
	}
	for i := range ch.alpnProtocols {
		if ch.alpnProtocols[i] != ch1.alpnProtocols[i] {
			return true
		}
	}
	return ch.vers != ch1.vers ||
		!bytes.Equal(ch.random, ch1.random) ||
		!bytes.Equal(ch.sessionId, ch1.sessionId) ||
		!bytes.Equal(ch.compressionMethods, ch1.compressionMethods) ||
		ch.serverName != ch1.serverName ||
		ch.ocspStapling != ch1.ocspStapling ||
		!bytes.Equal(ch.supportedPoints, ch1.supportedPoints) ||
		ch.ticketSupported != ch1.ticketSupported ||
		!bytes.Equal(ch.sessionTicket, ch1.sessionTicket) ||
		ch.secureRenegotiationSupported != ch1.secureRenegotiationSupported ||
		!bytes.Equal(ch.secureRenegotiation, ch1.secureRenegotiation) ||
		ch.scts != ch1.scts ||
		!bytes.Equal(ch.cookie, ch1.cookie) ||
		!bytes.Equal(ch.pskModes, ch1.pskModes)
}

// 发送 ServerHello,DummyChangeCipherSpec,EncryptedExtensions
func (hs *serverHandshakeStateTLS13) sendServerParameters() error {
	c := hs.c
	// 向握手数据摘要写入ClientHello与ServerHello
	hs.transcript.Write(hs.clientHello.marshal())
	hs.transcript.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发送 ServerHello")
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发送 DummyChangeCipherSpec")
	// 如果是会话恢复，这里已经存在早期机密，如果不存在，则初始化早期机密
	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret = hs.suite.extract(nil, nil)
	}
	// 使用HKDF算法,根据之前计算出的预主密钥与早期机密计算出主密钥
	hs.handshakeSecret = hs.suite.extract(hs.sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))
	// 使用HKDF算法,根据主密钥与目前的握手数据摘要计算出客户端会话机密,并设置到连接通道
	clientSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, clientSecret)
	// 使用HKDF算法,根据主密钥与目前的握手数据摘要计算出服务端会话机密,并设置到连接通道
	serverSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	// 生成加密扩展信息
	encryptedExtensions := new(encryptedExtensionsMsg)
	// 协商ALPN协议
	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols)
	if err != nil {
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	encryptedExtensions.alpnProtocol = selectedProto
	c.clientProtocol = selectedProto
	// 向握手数据摘要写入加密扩展信息
	hs.transcript.Write(encryptedExtensions.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, encryptedExtensions.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发送 EncryptedExtensions")

	return nil
}

func (hs *serverHandshakeStateTLS13) requestClientCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

// 发送 certificateRequestMsgTLS13,certificateMsgTLS13,certificateVerifyMsg
func (hs *serverHandshakeStateTLS13) sendServerCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	if hs.requestClientCert() {
		// Request a client certificate
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		// 向握手数据摘要写入 certificateRequestMsgTLS13
		hs.transcript.Write(certReq.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certReq.marshal()); err != nil {
			return err
		}
		zclog.Debug("===== 服务端发送 certificateRequestMsgTLS13")
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0
	// 向握手数据摘要写入 certificateMsgTLS13
	hs.transcript.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发送 certificateMsgTLS13")
	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	certVerifyMsg.signatureAlgorithm = hs.sigAlg

	sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash.HashFunc()}
	}
	sig, err := hs.cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		public := hs.cert.PrivateKey.(crypto.Signer).Public()
		if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
			rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
			c.sendAlert(alertHandshakeFailure)
		} else {
			c.sendAlert(alertInternalError)
		}
		return errors.New("gmtls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig
	// 向握手数据摘要写入 certificateVerifyMsg
	hs.transcript.Write(certVerifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certVerifyMsg.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发送 certificateVerifyMsg")
	return nil
}

// 发送 ServerFinished
func (hs *serverHandshakeStateTLS13) sendServerFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}
	// 向握手数据摘要写入 ServerFinished
	hs.transcript.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发送 ServerFinished")
	// Derive secrets that take context through the server Finished.
	// 重新派生主机密
	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))
	// 重新派生客户端通信机密,但暂时不设置到连接通道
	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	// 重新派生服务端通信机密，并设置到连接通道
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	// If we did not request client certificates, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) shouldSendSessionTickets() bool {
	if hs.c.config.SessionTicketsDisabled {
		zclog.Debug("===== config.SessionTicketsDisabled is true")
		return false
	}

	// Don't send tickets the client wouldn't use. See RFC 8446, Section 4.2.9.
	for _, pskMode := range hs.clientHello.pskModes {
		if pskMode == pskModeDHE {
			return true
		}
	}
	return false
}

// 发送 newSessionTicketMsgTLS13
func (hs *serverHandshakeStateTLS13) sendSessionTickets() error {
	c := hs.c

	hs.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	hs.transcript.Write(finishedMsg.marshal())

	if !hs.shouldSendSessionTickets() {
		zclog.Debug("===== shouldSendSessionTickets is false")
		return nil
	}
	// 派生会话恢复用机密
	resumptionSecret := hs.suite.deriveSecret(hs.masterSecret,
		resumptionLabel, hs.transcript)
	// 创建 newSessionTicketMsgTLS13
	m := new(newSessionTicketMsgTLS13)
	var certsFromClient [][]byte
	for _, cert := range c.peerCertificates {
		certsFromClient = append(certsFromClient, cert.Raw)
	}
	state := sessionStateTLS13{
		cipherSuite:      hs.suite.id,
		createdAt:        uint64(c.config.time().Unix()),
		resumptionSecret: resumptionSecret,
		certificate: Certificate{
			Certificate:                 certsFromClient,
			OCSPStaple:                  c.ocspResponse,
			SignedCertificateTimestamps: c.scts,
		},
	}
	var err error
	// 序列化 newSessionTicketMsgTLS13 并加密
	m.label, err = c.encryptTicket(state.marshal())
	if err != nil {
		return err
	}
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)
	if _, err := c.writeRecord(recordTypeHandshake, m.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 服务端发出 newSessionTicketMsgTLS13")
	return nil
}

// 读取并验证客户端证书，并发送本次会话票据信息给客户端。
func (hs *serverHandshakeStateTLS13) readClientCertificate() error {
	c := hs.c

	if !hs.requestClientCert() {
		// Make sure the connection is still being verified whether or not
		// the server requested a client certificate.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	// If we requested a client certificate, then the client must send a
	// certificate message. If it's empty, no CertificateVerify is sent.
	// 读取 ClientCertificate
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	zclog.Debug("===== 服务端读取到 ClientCertificate")
	hs.transcript.Write(certMsg.marshal())
	// 检查客户端证书
	if err := c.processCertsFromClient(certMsg.certificate); err != nil {
		return err
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if len(certMsg.certificate.Certificate) != 0 {
		// 读取 ClientCertVerify
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}
		zclog.Debug("===== 服务端读取到 ClientCertVerify")
		// See RFC 8446, Section 4.4.3.
		if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("gmtls: client certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
		if err != nil {
			return c.sendAlert(alertInternalError)
		}
		if sigType == signaturePKCS1v15 || sigHash == x509.SHA1 {
			c.sendAlert(alertIllegalParameter)
			return errors.New("gmtls: client certificate used with invalid signature algorithm")
		}
		signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
		if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
			sigHash, signed, certVerify.signature); err != nil {
			c.sendAlert(alertDecryptError)
			return errors.New("gmtls: invalid signature by the client certificate: " + err.Error())
		}

		hs.transcript.Write(certVerify.marshal())
	}
	// 在需求验证客户端证书且验证Ok之后，向客户端发送本次会话新创建的票据信息。
	// 该消息属于握手消息，但是在客户端完成握手之后才会接收。
	// PS : 如果要使用会话恢复功能，服务端就必须验证客户端身份。
	// If we waited until the client certificates to send session tickets, we
	// are ready to do it now.
	if err := hs.sendSessionTickets(); err != nil {
		return err
	}

	return nil
}

// 读取 ClientFinished
func (hs *serverHandshakeStateTLS13) readClientFinished() error {
	c := hs.c
	// 读取 ClientFinished
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}
	zclog.Debug("===== 服务端读取到 ClientFinished")
	if !hmac.Equal(hs.clientFinished, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("gmtls: invalid client finished hash")
	}
	// 将之前重新生成的客户端通信机密设置到连接in通道
	c.in.setTrafficSecret(hs.suite, hs.trafficSecret)

	return nil
}
