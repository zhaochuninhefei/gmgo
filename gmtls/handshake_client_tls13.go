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
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecbase"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"hash"
	"sync/atomic"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

// tls1.3客户端握手状态
// GMSSL目前也使用tls1.3的处理
type clientHandshakeStateTLS13 struct {
	c           *Conn
	ctx         context.Context
	serverHello *serverHelloMsg
	hello       *clientHelloMsg
	ecdheParams ecdheParameters

	session     *ClientSessionState
	earlySecret []byte
	binderKey   []byte

	certReq       *certificateRequestMsgTLS13
	usingPSK      bool
	sentDummyCCS  bool
	suite         *cipherSuiteTLS13
	transcript    hash.Hash
	masterSecret  []byte
	trafficSecret []byte // client_application_traffic_secret_0
}

// tls1.3在收到ServerHello之后的握手过程
// handshake requires hs.c, hs.hello, hs.serverHello, hs.ecdheParams, and,
// optionally, hs.session, hs.earlySecret and hs.binderKey to be set.
func (hs *clientHandshakeStateTLS13) handshake() error {
	c := hs.c

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakes > 0 {
		_ = c.sendAlert(alertProtocolVersion)
		return errors.New("gmtls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if hs.ecdheParams == nil || len(hs.hello.keyShares) != 1 {
		_ = c.sendAlert(alertInternalError)
		return nil
	}
	// 检查ServerHello或HelloRetryRequest,并设置协商好的密码套件
	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}
	// 使用协商好的密码套件中的散列函数作为握手数据摘要的计算函数
	hs.transcript = hs.suite.hash.New()
	// 将ClientHello的序列化结果写入握手数据摘要
	hs.transcript.Write(hs.hello.marshal())
	// 检查是ServerHello还是HelloRetryRequest
	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		// 出于兼容性考虑，发出一个假的ChangeCipherSpec消息。
		// 实际不会现在改变c.out的加密和MAC状态。
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		// 应服务端的 HelloRetryRequest 请求，修改ClientHello，重新发送ClientHello，重新接收并检查ServerHello。
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}
	// 将ServerHello写入握手数据摘要
	hs.transcript.Write(hs.serverHello.marshal())

	c.buffering = true
	// 检查ServerHello
	if err := hs.processServerHello(); err != nil {
		return err
	}
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	// 根据ServerHello的服务端公钥生成共享密钥，进一步生成握手密钥与对应的客户端/服务端会话密钥。
	// 因为tls1.3中，ServerHello之后的通信都是加密的，必须在这里就完成密钥协商，生成对应的会话密钥。
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	// 读取服务端加密扩展信息
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	// 读取证书请求/服务端证书/certificateVerifyMsg
	if err := hs.readServerCertificate(); err != nil {
		return err
	}
	// 读取 ServerFinished 并重新派生会话密钥
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	// 发送客户端证书与客户端证书验证消息
	if err := hs.sendClientCertificate(); err != nil {
		return err
	}
	// 发送 ClientFinished
	if err := hs.sendClientFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}
	// 将握手状态改为1
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// 检查ServerHello或HelloRetryRequest。
// checkServerHelloOrHRR does validity checks that apply to both ServerHello and
// HelloRetryRequest messages. It sets hs.suite.
func (hs *clientHandshakeStateTLS13) checkServerHelloOrHRR() error {
	c := hs.c

	if hs.serverHello.supportedVersion == 0 {
		_ = c.sendAlert(alertMissingExtension)
		return errors.New("gmtls: server selected TLS 1.3 using the legacy version field")
	}
	// GMSSL采取相同处理
	if hs.serverHello.supportedVersion != VersionTLS13 && hs.serverHello.supportedVersion != VersionGMSSL {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server selected an invalid version after a HelloRetryRequest")
	}
	// 出于兼容性原因，vers只能写VersionTLS12
	if hs.serverHello.vers != VersionTLS12 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server sent an incorrect legacy version")
	}
	// 检查ServerHello是否包含tls1.3禁用的扩展信息
	if hs.serverHello.ocspStapling ||
		hs.serverHello.ticketSupported ||
		hs.serverHello.secureRenegotiationSupported ||
		len(hs.serverHello.secureRenegotiation) != 0 ||
		len(hs.serverHello.alpnProtocol) != 0 ||
		len(hs.serverHello.scts) != 0 {
		_ = c.sendAlert(alertUnsupportedExtension)
		return errors.New("gmtls: server sent a ServerHello extension forbidden in TLS 1.3")
	}
	// 检查双方sessionID是否一致
	if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server did not echo the legacy session ID")
	}
	// 检查是否不支持压缩,tls1.3不再支持压缩
	if hs.serverHello.compressionMethod != compressionNone {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server selected unsupported compression format")
	}
	// 协商tls1.3密码套件
	selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
	if hs.suite != nil && selectedSuite != hs.suite {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server changed cipher suite after a HelloRetryRequest")
	}
	if selectedSuite == nil {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server chose an unconfigured cipher suite")
	}
	zclog.Debugf("===== 客户端确认协商好的密码套件: %s", CipherSuiteName(selectedSuite.id))
	// 设置协商好的密码套件
	hs.suite = selectedSuite
	c.cipherSuite = hs.suite.id

	return nil
}

// sendDummyChangeCipherSpec 发送 ChangeCipherSpec 记录，用来与未正确实现TLS的中间件兼容。
// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *clientHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	_, err := hs.c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	zclog.Debug("===== 客户端发送 DummyChangeCipherSpec")
	return err
}

// processHelloRetryRequest handles the HRR in hs.serverHello, modifies and
// resends hs.hello, and reads the new ServerHello into hs.serverHello.
func (hs *clientHandshakeStateTLS13) processHelloRetryRequest() error {
	c := hs.c

	// 对已经写入握手数据摘要的ClientHello进行散列，并重新写入握手数据摘要，然后写入ServerHellod的序列化结果。
	// 即，发生HelloRetryRequest的话，握手数据摘要中的ClientHello会被重复散列。
	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. (The idea is that the server might offload transcript
	// storage to the client in the cookie.) See RFC 8446, Section 4.4.1.
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	hs.transcript.Write(hs.serverHello.marshal())

	// The only HelloRetryRequest extensions we support are key_share and
	// cookie, and clients must abort the handshake if the HRR would not result
	// in any change in the ClientHello.
	if hs.serverHello.selectedGroup == 0 && hs.serverHello.cookie == nil {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server sent an unnecessary HelloRetryRequest message")
	}

	if hs.serverHello.cookie != nil {
		hs.hello.cookie = hs.serverHello.cookie
	}

	if hs.serverHello.serverShare.group != 0 {
		_ = c.sendAlert(alertDecodeError)
		return errors.New("gmtls: server sent a malformed key_share extension")
	}

	// 如果ServerHello中有key_share，那么检查是否与之前发出的ClientHello中的key_share相同，
	// 并重新生成一个key_share。
	// If the server sent a key_share extension selecting a group, ensure it's
	// a group we advertised but did not send a key share for, and send a key
	// share for it this time.
	if curveID := hs.serverHello.selectedGroup; curveID != 0 {
		curveOK := false
		for _, id := range hs.hello.supportedCurves {
			if id == curveID {
				curveOK = true
				break
			}
		}
		if !curveOK {
			_ = c.sendAlert(alertIllegalParameter)
			return errors.New("gmtls: server selected unsupported group")
		}
		if hs.ecdheParams.CurveID() == curveID {
			_ = c.sendAlert(alertIllegalParameter)
			return errors.New("gmtls: server sent an unnecessary HelloRetryRequest key_share")
		}
		if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
			_ = c.sendAlert(alertInternalError)
			return errors.New("gmtls: CurvePreferences includes unsupported curve")
		}
		// 再次生成密钥交换参数
		params, err := generateECDHEParameters(c.config.rand(), curveID)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return fmt.Errorf("gmtls: ECDHE密钥协商失败: %s", err)
		}
		hs.ecdheParams = params
		hs.hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}
	}

	hs.hello.raw = nil
	if len(hs.hello.pskIdentities) > 0 {
		pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
		if pskSuite == nil {
			_ = c.sendAlert(alertInternalError)
			return nil
		}
		if pskSuite.hash == hs.suite.hash {
			// Update binders and obfuscated_ticket_age.
			ticketAge := uint32(c.config.time().Sub(hs.session.receivedAt) / time.Millisecond)
			hs.hello.pskIdentities[0].obfuscatedTicketAge = ticketAge + hs.session.ageAdd

			transcript := hs.suite.hash.New()
			transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
			transcript.Write(chHash)
			transcript.Write(hs.serverHello.marshal())
			transcript.Write(hs.hello.marshalWithoutBinders())
			pskBinders := [][]byte{hs.suite.finishedHash(hs.binderKey, transcript)}
			hs.hello.updateBinders(pskBinders)
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hs.hello.pskIdentities = nil
			hs.hello.pskBinders = nil
		}
	}
	// 将ServerHello写入握手数据摘要
	hs.transcript.Write(hs.hello.marshal())
	// 再次发送ClientHello
	zclog.Debug("===== 客户端再次发出ClientHello(HelloRetryRequest)")
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}
	// 读取下一条握手信息
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	hs.serverHello = serverHello
	zclog.Debug("===== 客户端再次读取到ServerHello(HelloRetryRequest)")

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	return nil
}

// 对ServerHello做检查处理
func (hs *clientHandshakeStateTLS13) processServerHello() error {
	c := hs.c
	// 服务端只能请求一次 HelloRetryRequest
	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		_ = c.sendAlert(alertUnexpectedMessage)
		return errors.New("gmtls: server sent two HelloRetryRequest messages")
	}

	if len(hs.serverHello.cookie) != 0 {
		_ = c.sendAlert(alertUnsupportedExtension)
		return errors.New("gmtls: server sent a cookie in a normal ServerHello")
	}

	if hs.serverHello.selectedGroup != 0 {
		_ = c.sendAlert(alertDecodeError)
		return errors.New("gmtls: malformed key_share extension")
	}

	if hs.serverHello.serverShare.group == 0 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server did not send a key share")
	}
	// 检查服务端的密钥协商参数的曲线是否与客户端的对应曲线ID一致
	if hs.serverHello.serverShare.group != hs.ecdheParams.CurveID() {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server selected unsupported group")
	}
	// ServerHello没有选择会话恢复用的ID时，处理结束。
	if !hs.serverHello.selectedIdentityPresent {
		return nil
	}

	if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server selected an invalid PSK")
	}

	if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
		return c.sendAlert(alertInternalError)
	}
	pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
	if pskSuite == nil {
		return c.sendAlert(alertInternalError)
	}
	if pskSuite.hash != hs.suite.hash {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: server selected an invalid PSK and cipher suite pair")
	}
	// 会话恢复场景的属性设置
	hs.usingPSK = true
	c.didResume = true
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	c.scts = hs.session.scts
	return nil
}

// 创建握手密钥
func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c
	// 根据服务端公钥计算预主密钥
	zclog.Debug("===== 利用服务端公钥计算预主密钥")
	sharedKey := hs.ecdheParams.SharedKey(hs.serverHello.serverShare.data)
	if sharedKey == nil {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: invalid server key share")
	}
	// 获取之前的密钥
	earlySecret := hs.earlySecret
	if !hs.usingPSK {
		// 不是会话恢复场景时，初始化 earlySecret
		earlySecret = hs.suite.extract(nil, nil)
	}
	// 生成本次会话的握手阶段密钥
	handshakeSecret := hs.suite.extract(sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))
	// 派生握手阶段的客户端会话密钥,后续还要根据最新的握手数据摘要重新派生
	clientSecret := hs.suite.deriveSecret(handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, clientSecret)
	// 派生握手阶段的服务端会话密钥,后续还要根据最新的握手数据摘要重新派生
	serverSecret := hs.suite.deriveSecret(handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, clientSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return fmt.Errorf("gmtls: 写入clientSecret日志时发生错误: %s", err)
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return fmt.Errorf("gmtls: 写入serverSecret日志时发生错误: %s", err)
	}
	// 根据握手阶段密钥派生新的预主密钥并提取出主密钥
	// tls1.3的密钥协商算法不再需要使用 ClientRadom与ServerRandom
	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(handshakeSecret, "derived", nil))

	return nil
}

// 读取服务端发送的加密扩展信息
func (hs *clientHandshakeStateTLS13) readServerParameters() error {
	c := hs.c
	// 读取服务端发送的加密扩展信息
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(encryptedExtensions, msg)
	}
	hs.transcript.Write(encryptedExtensions.marshal())
	zclog.Debug("===== 客户端读取到 encryptedExtensionsMsg")
	// 检查ALPN协议设置
	if err := checkALPN(hs.hello.alpnProtocols, encryptedExtensions.alpnProtocol); err != nil {
		_ = c.sendAlert(alertUnsupportedExtension)
		return err
	}
	c.clientProtocol = encryptedExtensions.alpnProtocol

	return nil
}

// 读取服务端证书
func (hs *clientHandshakeStateTLS13) readServerCertificate() error {
	c := hs.c

	// Either a PSK or a certificate is always used, but not both.
	// See RFC 8446, Section 4.1.1.
	if hs.usingPSK {
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				_ = c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}
	// 从tls连接读取下一条消息
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	// 检查是否证书请求消息
	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		hs.transcript.Write(certReq.marshal())
		zclog.Debug("===== 客户端读取到 certificateRequestMsgTLS13")
		hs.certReq = certReq
		// 从tls连接读取下一条消息
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}
	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		err := unexpectedMessageError(certMsg, msg)
		_ = c.sendAlert(alertUnexpectedMessage)
		return err
	}
	zclog.Debug("===== 客户端读取到 certificateMsgTLS13")
	if len(certMsg.certificate.Certificate) == 0 {
		_ = c.sendAlert(alertDecodeError)
		return errors.New("gmtls: received empty certificates message")
	}
	hs.transcript.Write(certMsg.marshal())

	c.scts = certMsg.certificate.SignedCertificateTimestamps
	c.ocspResponse = certMsg.certificate.OCSPStaple
	// 验证服务端证书
	if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}
	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certVerify, msg)
	}
	zclog.Debug("===== 客户端读取到 certificateVerifyMsg")

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: certificate used with unsupported signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	zclog.Debugf("sigHash: %s", sigHash.String())
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == x509.SHA1 {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: certificate used with obsolete signature algorithm")
	}
	// 生成签名内容: 握手数据摘要混入一些固定的值
	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	// 对certificateVerifyMsg中的签名进行验签
	// TODO 需要确认sign的处理有没有对ecdsaext做特殊处理
	if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		_ = c.sendAlert(alertDecryptError)
		zclog.ErrorStack("客户端对服务端证书验签失败")
		return errors.New("gmtls: invalid signature by the server certificate: " + err.Error())
	}
	// 将服务端 certVerify 写入握手数据摘要
	hs.transcript.Write(certVerify.marshal())

	return nil
}

// 读取ServerFinished
func (hs *clientHandshakeStateTLS13) readServerFinished() error {
	c := hs.c
	// 读取ServerFinished
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	finished, ok := msg.(*finishedMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}
	zclog.Debug("===== 客户端读取到 ServerFinished")
	// 计算期望的finished散列并与接收的值比较
	expectedMAC := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		_ = c.sendAlert(alertDecryptError)
		return errors.New("gmtls: invalid server finished hash")
	}
	// 将finished消息写入握手数据摘要
	hs.transcript.Write(finished.marshal())

	// Derive secrets that take context through the server Finished.
	// 根据主密钥与最新的握手数据摘要重新派生客户端与服务端会话密钥
	// 注意，此时并没有将重新生成的客户端会话密钥设置到连接通道上，只更新了连接通道上的服务端会话密钥。
	// 新的客户端会话密钥要等到 ClientFinished 发送给服务端之后才能配置到连接通道上。
	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, serverSecret)

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return fmt.Errorf("gmtls: 写入trafficSecret日志时发生错误: %s", err)
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return fmt.Errorf("gmtls: 写入serverSecret日志时发生错误: %s", err)
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	return nil
}

// 根据服务端是否发出证书请求决定是否发出客户端证书
func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:    hs.certReq.certificateAuthorities,
		SignatureSchemes: hs.certReq.supportedSignatureAlgorithms,
		Version:          c.vers,
		ctx:              hs.ctx,
	})
	if err != nil {
		return err
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0
	// 向握手数据摘要写入客户端证书，并向服务端发送客户端证书
	hs.transcript.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 客户端发出 ClientCertificate")

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	// 获取签名算法
	certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert, hs.certReq.supportedSignatureAlgorithms)
	if err != nil {
		// getClientCertificate returned a certificate incompatible with the
		// CertificateRequestInfo supported signature algorithms.
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	// 获取签名算法与散列算法
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
	zclog.Debugf("sigHash: %s", sigHash.String())
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	// 生成签名内容: 当前握手数据摘要混入一些固定值后散列
	signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	//if sigType == signatureRSAPSS {
	//	signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash.HashFunc()}
	//}
	switch sigType {
	case signatureRSAPSS:
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash.HashFunc()}
	case signatureSM2:
		signOpts = sm2.DefaultSM2SignerOption()
	case signatureECDSAEXT:
		signOpts = ecbase.CreateEcSignerOpts(sigHash.HashFunc(), true)
	}
	// 使用证书私钥进行签名
	// TODO 需要确认sign的处理有没有对ecdsaext做特殊处理
	sig, err := cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return errors.New("gmtls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig
	// 向握手数据摘要写入证书认证消息并发送给服务端
	hs.transcript.Write(certVerifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certVerifyMsg.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 客户端发出 ClientCertVerify")

	return nil
}

// 发送 ClientFinished
func (hs *clientHandshakeStateTLS13) sendClientFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}
	// 向握手数据摘要写入 ClientFinished 并向服务端发送
	hs.transcript.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 客户端发出 ClientFinished")
	// 注意，此时才将重新生成的客户端会话密钥设置到连接通道上。
	c.out.setTrafficSecret(hs.suite, hs.trafficSecret)

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret = hs.suite.deriveSecret(hs.masterSecret,
			resumptionLabel, hs.transcript)
	}

	return nil
}

// 处理来自服务端的 newSessionTicketMsgTLS13
func (c *Conn) handleNewSessionTicket(msg *newSessionTicketMsgTLS13) error {
	if !c.isClient {
		_ = c.sendAlert(alertUnexpectedMessage)
		return errors.New("gmtls: received new session ticket from a client")
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {
		_ = c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: received a session ticket with invalid lifetime")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		_ = c.sendAlert(alertInternalError)
		return nil
	}

	// Save the resumption_master_secret and nonce instead of deriving the PSK
	// to do the least amount of work on NewSessionTicket messages before we
	// know if the ticket will be used. Forward secrecy of resumed connections
	// is guaranteed by the requirement for pskModeDHE.
	session := &ClientSessionState{
		sessionTicket:      msg.label, // 这里的label是在服务端经过序列化并加密的sessionStateTLS13
		vers:               c.vers,
		cipherSuite:        c.cipherSuite,
		masterSecret:       c.resumptionSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		nonce:              msg.nonce,
		useBy:              c.config.time().Add(lifetime),
		ageAdd:             msg.ageAdd,
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	cacheKey := clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	c.config.ClientSessionCache.Put(cacheKey, session)

	return nil
}
