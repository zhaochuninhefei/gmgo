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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *ClientSessionState
}

// 生成ClientHello
func (c *Conn) makeClientHello() (*clientHelloMsg, ecdheParameters, error) {
	config := c.config
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		// 如果没有指定 InsecureSkipVerify 那么就必须设置 ServerName
		return nil, nil, errors.New("gmtls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, errors.New("gmtls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, errors.New("gmtls: NextProtos values too large")
	}
	// 获取客户端支持的tls协议版本列表,tls1.3使用该扩展信息
	supportedVersions := config.supportedVersions()
	if len(supportedVersions) == 0 {
		return nil, nil, errors.New("gmtls: no supported versions satisfy MinVersion and MaxVersion")
	}
	// 获取客户端支持的最高版本tls协议,tls1.2及以前的版本使用该属性
	clientHelloVersion := config.maxSupportedVersion()
	// 出于兼容性原因，ClientHello 开头的版本上限为 TLS 1.2。
	// 对于更高的tls1.3版本，使用 supported_versions 扩展。
	// See RFC 8446, Section 4.2.1.
	if clientHelloVersion > VersionTLS12 {
		clientHelloVersion = VersionTLS12
	}

	hello := &clientHelloMsg{
		vers:                         clientHelloVersion,
		compressionMethods:           []uint8{compressionNone}, // tls1.3不再支持压缩
		random:                       make([]byte, 32),
		sessionId:                    make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName), // 服务端域名,使用DNS域名即可
		supportedCurves:              config.curvePreferences(),        // 支持的曲线ID
		supportedPoints:              []uint8{pointFormatUncompressed}, // 曲线上的点坐标序列化时不压缩
		secureRenegotiationSupported: true,                             // 是否支持安全重协商
		alpnProtocols:                config.NextProtos,                // ALPN协议列表
		supportedVersions:            supportedVersions,                // 客户端支持的tls协议版本列表
	}
	// 如果不是第一次握手，将上次握手时客户端发送的Finished消息作为 安全重协商 字段。
	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}
	// 预置的tls1.0-1.2密码学套件列表
	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}
	// 配置要求的tls1.0-1.2密码学套件列表
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))
	// 从预置的tls1.0-1.2密码学套件列表中筛选满足配置的密码套件
	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		// Don't advertise TLS 1.2-only cipher suites unless
		// we're attempting TLS 1.2.
		if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
			continue
		}
		// 将筛选出的密码套件加入hello消息的密码套件列表
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}
	// 填充客户端随机数
	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, errors.New("gmtls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
		return nil, nil, errors.New("gmtls: short read from Rand: " + err.Error())
	}
	// tls1.2以上版本需要传输支持的签名算法
	// GMSSL也需要传输支持的签名算法
	if hello.vers >= VersionTLS12 || hello.vers == VersionGMSSL {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}

	// 对于TLS1.3，需要额外传输一些扩展信息
	var params ecdheParameters
	if hello.supportedVersions[0] == VersionTLS13 || hello.supportedVersions[0] == VersionGMSSL {
		// 在密码套件中加入tls1.3的密码套件
		// tls1.3的密码套件是固定的，不允许客户端自行配置选择
		if hasAESGCMHardwareSupport {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13...)
		} else {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13NoAES...)
		}
		// 设置密钥协商的曲线为配置的首个曲线，目前默认是sm2P256
		curveID := config.curvePreferences()[0]
		// var curve elliptic.Curve
		var curveOk bool
		var curveName string
		if curveName, curveOk = CheckCurveNameById(curveID); !curveOk {
			return nil, nil, errors.New("gmtls: CurvePreferences includes unsupported curve")
		}
		// 生成ecdheParameters
		params, err = generateECDHEParameters(config.rand(), curveID)
		if err != nil {
			return nil, nil, err
		}
		zclog.Debugf("===== 客户端基于曲线 %s 生成密钥交换算法参数\n", curveName)
		// 将曲线ID与客户端公钥设置为ClientHello中的密钥交换算法参数
		hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}
	}

	return hello, params, nil
}

// 客户端握手
func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	zclog.Debug("===== 开始客户端握手过程")
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false
	// 生成ClientHello消息: tls协议版本列表，密码套件列表，客户端密钥交换算法参数等
	hello, ecdheParams, err := c.makeClientHello()
	if err != nil {
		return err
	}
	// 确保连接的serverName与ClientHello中的serverName相同
	c.serverName = hello.serverName
	// 尝试从当前连接中获取会话恢复信息
	cacheKey, session, earlySecret, binderKey := c.loadSession(hello)
	if cacheKey != "" && session != nil {
		// 如果尝试会话恢复，那么在会话恢复发生错误时要删除客户端的该会话缓存
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				c.config.ClientSessionCache.Put(cacheKey, nil)
			}
		}()
	}
	// 向连接写入ClientHello
	zclog.Debug("===== 客户端发出ClientHello")
	if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return err
	}
	// 从连接读取ServerHello
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	zclog.Debug("===== 客户端读取到ServerHello")
	// 协商tls版本
	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}
	// If we are negotiating a protocol version that's lower than what we
	// support, check for the server downgrade canaries.
	// See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion()
	tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
	tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
	if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
		maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
		c.sendAlert(alertIllegalParameter)
		return errors.New("gmtls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox")
	}
	// GMSSL目前采用与tls1.3相同的处理
	if c.vers == VersionTLS13 || c.vers == VersionGMSSL {
		zclog.Debug("===== 客户端执行tls1.3或gmlssl协议的握手过程")
		hs := &clientHandshakeStateTLS13{
			c:           c,
			ctx:         ctx,
			serverHello: serverHello,
			hello:       hello,
			ecdheParams: ecdheParams,
			session:     session,
			earlySecret: earlySecret,
			binderKey:   binderKey,
		}
		// tls1.3的握手过程在收到ServerHello之后与tls1.2不同，这里走不同的分支处理
		// In TLS 1.3, session tickets are delivered after the handshake.
		return hs.handshake()
	}
	zclog.Debug("===== 客户端执行tls1.2或更老版本的握手过程")
	hs := &clientHandshakeState{
		c:           c,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}

	if err := hs.handshake(); err != nil {
		return err
	}

	// If we had a successful handshake and hs.session is different from
	// the one already cached - cache a new one.
	if cacheKey != "" && hs.session != nil && session != hs.session {
		c.config.ClientSessionCache.Put(cacheKey, hs.session)
	}

	return nil
}

// 从连接中获取会话恢复信息。
//  对于tls1.3，如果有可用的缓存会话，则会返回以下字段:
//  - cacheKey 缓存会话key,值是服务端ServerName或ip地址
//  - session 想要恢复的缓存会话
//  - earlySecret 早期密钥,由session的主密钥扩展提炼而来
//  - binderKey 绑定者密钥,由早期密钥派生而来
//  此外，还会在ClientHello中设置以下字段:
//  - ticketSupported true,支持使用会话票据
//  - pskModes 指定使用DHE密钥交换算法模式
//  - pskIdentities 请求恢复的pskID集合,事实上只有一条pskid
//  - pskBinders psk绑定者的散列信息
func (c *Conn) loadSession(hello *clientHelloMsg) (cacheKey string,
	session *ClientSessionState, earlySecret, binderKey []byte) {
	// 检查是否支持会话恢复
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return "", nil, nil, nil
	}
	// 设置支持使用会话票据
	hello.ticketSupported = true
	// 检查tls最高版本是否tls1.3 或 GMSSL
	if hello.supportedVersions[0] == VersionTLS13 || hello.supportedVersions[0] == VersionGMSSL {
		// tls1.3开始，psk使用DHE算法模式。
		// Require DHE on resumption as it guarantees forward secrecy against
		// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
		hello.pskModes = []uint8{pskModeDHE}
	}
	// TODO: 疑惑: 握手次数非0，代表发生过重新协商?允许重新协商就不允许会话恢复?
	// 但首次握手成功后，握手次数就是1了啊，这不会导致永远无法启用会话恢复?
	// 感觉应该是 "c.handshakes > 1" ?
	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if c.handshakes != 0 {
		return "", nil, nil, nil
	}
	// 根据连接的servername或serverAddr获取对应的会话缓存
	// Try to resume a previously negotiated TLS session, if available.
	cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	session, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || session == nil {
		return cacheKey, nil, nil, nil
	}
	// 检查之前缓存的会话与本次ClientHello的tls版本是否匹配
	// Check that version used for the previous session is still valid.
	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.vers {
			versOk = true
			break
		}
	}
	if !versOk {
		return cacheKey, nil, nil, nil
	}
	// 检查缓存会话的服务端子证书的过期时间与域名
	// Check that the cached server certificate is not expired, and that it's
	// valid for the ServerName. This should be ensured by the cache key, but
	// protect the application from a faulty ClientSessionCache implementation.
	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			// The original connection had InsecureSkipVerify, while this doesn't.
			return cacheKey, nil, nil, nil
		}
		serverCert := session.serverCertificates[0]
		if c.config.time().After(serverCert.NotAfter) {
			// Expired certificate, delete the entry.
			c.config.ClientSessionCache.Put(cacheKey, nil)
			return cacheKey, nil, nil, nil
		}
		if err := serverCert.VerifyHostname(c.config.ServerName); err != nil {
			return cacheKey, nil, nil, nil
		}
	}

	if session.vers != VersionTLS13 && session.vers != VersionGMSSL {
		// In TLS 1.2 the cipher suite must match the resumed session. Ensure we
		// are still offering it.
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return cacheKey, nil, nil, nil
		}
		// 对于tls1.2及之前的版本，如果密码套件匹配，则直接将缓存会话票据设置到ClientHello中。
		hello.sessionTicket = session.sessionTicket
		return
	}
	// 检查缓存的会话是否已经过期
	// Check that the session ticket is not expired.
	if c.config.time().After(session.useBy) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return cacheKey, nil, nil, nil
	}
	// 获取缓存会话的密码套件
	// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	// offer at least one cipher suite with that hash.
	cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if cipherSuite == nil {
		return cacheKey, nil, nil, nil
	}
	// 检查缓存会话的密码套件是否与当前ClientHello支持的密码套件匹配
	cipherSuiteOk := false
	for _, offeredID := range hello.cipherSuites {
		offeredSuite := cipherSuiteTLS13ByID(offeredID)
		if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return cacheKey, nil, nil, nil
	}
	// 设置psk扩展信息
	// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	// 票据年龄 : 会话获取时间到当前时间的毫秒数
	ticketAge := uint32(c.config.time().Sub(session.receivedAt) / time.Millisecond)
	// 会话的pskID
	identity := pskIdentity{
		label:               session.sessionTicket,
		obfuscatedTicketAge: ticketAge + session.ageAdd,
	}
	// 设置到ClientHello的 pskIdentities
	hello.pskIdentities = []pskIdentity{identity}
	// 计算pskBinders
	hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}
	// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	// 根据会话的主密钥扩展出psk(pre-shared-key)
	psk := cipherSuite.expandLabel(session.masterSecret, "resumption",
		session.nonce, cipherSuite.hash.Size())
	// 再用psk提炼早期密钥
	earlySecret = cipherSuite.extract(psk, nil)
	// 根据早期密钥派生绑定者密钥
	binderKey = cipherSuite.deriveSecret(earlySecret, resumptionBinderLabel, nil)
	// 声明一个转录散列函数
	transcript := cipherSuite.hash.New()
	// 向转录散列写入不带pskBinders的ClientHello
	transcript.Write(hello.marshalWithoutBinders())
	// 生成pskBinders: 使用绑定者密钥和转录散列生成的Finished消息散列
	pskBinders := [][]byte{cipherSuite.finishedHash(binderKey, transcript)}
	// 将 pskBinders 设置到ClientHello
	hello.updateBinders(pskBinders)

	return
}

// 选取本次tls通信的版本
func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}
	// 按优先顺序匹配协议版本
	vers, ok := c.config.mutualVersion([]uint16{peerVersion})
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("gmtls: server selected unsupported protocol version %x", peerVersion)
	}
	// 将协商好的版本设置到tls连接中
	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers
	zclog.Debugln("===== gmtls/handshake_client.go pickTLSVersion 客户端确认本次tls连接使用的版本是:", ShowTLSVersion(int(c.vers)))

	return nil
}

// tls1.2及更老版本在接收到 ServerHello 之后的握手过程。
// Does the handshake, either a full one or resumes old session. Requires hs.c,
// hs.hello, hs.serverHello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c
	// 处理 ServerHello
	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	c.didResume = isResume
	if isResume {
		// 会话恢复处理
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
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		// 非会话恢复,执行完整的握手过程
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		// 生成会话密钥
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// 发送 ClientFinished
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
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// 客户端确认协商好的密码套件(tls1.2)
func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("gmtls: server chose an unconfigured cipher suite")
	}
	hs.c.cipherSuite = hs.suite.id
	zclog.Debugf("===== 客户端确认协商好的密码套件: %s", CipherSuiteName(hs.suite.id))
	return nil
}

// tls1.2非会话恢复时的完整握手过程
func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c
	// 读取 certificateMsg 服务端证书
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	zclog.Debug("===== 客户端读取到服务端证书 certificateMsg")
	hs.finishedHash.Write(certMsg.marshal())

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		zclog.Debug("===== 客户端读取到 certificateStatusMsg")
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(alertUnexpectedMessage)
			return errors.New("gmtls: received unexpected CertificateStatus message")
		}
		hs.finishedHash.Write(cs.marshal())
		// certificateStatusMsg 返回的是服务端装订的ocsp信息
		c.ocspResponse = cs.response

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	if c.handshakes == 0 {
		// 首次握手时验证服务端证书，成功时会将服务端证书塞到客户端的对方证书字段peerCertificates中
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// 不是首次握手时，只需比较接收到的服务端证书是否还是之前验证过的服务端证书即可。
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("gmtls: server's identity changed during renegotiation")
		}
	}
	// 根据具体的密码套件执行其密钥交换算法，计算密钥交换参数
	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		zclog.Debug("===== 客户端读取到 serverKeyExchangeMsg")
		hs.finishedHash.Write(skx.marshal())
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		zclog.Debug("===== 客户端读取到 certificateRequestMsg")
		certRequested = true
		hs.finishedHash.Write(certReq.marshal())

		cri := certificateRequestInfoFromMsg(hs.ctx, c.vers, certReq)
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		zclog.Debug("===== 客户端读取到 serverHelloDoneMsg")
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
		zclog.Debug("===== 客户端发送 ClientCertificate")
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
		zclog.Debug("===== 客户端发送 clientKeyExchangeMsg")
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("gmtls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		var sigType uint8
		var sigHash x509.Hash
		if c.vers >= VersionTLS12 {
			signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
			if err != nil {
				return c.sendAlert(alertInternalError)
			}
			certVerify.hasSignatureAlgorithm = true
			certVerify.signatureAlgorithm = signatureAlgorithm
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash, hs.masterSecret)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash.HashFunc()}
		}
		certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
		zclog.Debug("===== 客户端发送 ClientCertVerify")
	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("gmtls: failed to write to key log: " + err.Error())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

// 生成会话密钥(tls1.2)
func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

// 处理tls1.2及更老版本的 ServerHello
func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c
	// 选取密码套件
	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("gmtls: server selected unsupported compression format")
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("gmtls: initial handshake had non-empty renegotiation extension")
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("gmtls: incorrect renegotiation extension contents")
		}
	}

	if err := checkALPN(hs.hello.alpnProtocols, hs.serverHello.alpnProtocol); err != nil {
		c.sendAlert(alertUnsupportedExtension)
		return false, err
	}
	c.clientProtocol = hs.serverHello.alpnProtocol

	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("gmtls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("gmtls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret, peerCerts, and ocspResponse from previous state
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	// Let the ServerHello SCTs override the session SCTs from the original
	// connection, if any are provided
	if len(c.scts) == 0 && len(hs.session.scts) != 0 {
		c.scts = hs.session.scts
	}

	return true, nil
}

// checkALPN ensure that the server's choice of ALPN protocol is compatible with
// the protocols that we advertised in the Client Hello.
func checkALPN(clientProtos []string, serverProto string) error {
	if serverProto == "" {
		return nil
	}
	if len(clientProtos) == 0 {
		return errors.New("gmtls: server advertised unrequested ALPN extension")
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return errors.New("gmtls: server selected unadvertised ALPN protocol")
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}
	zclog.Debug("===== 客户端读取到 ChangeCipherSpec")

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}
	zclog.Debug("===== 客户端读取到 ServerFinished")
	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("gmtls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
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
	zclog.Debug("===== 客户端读取到 SessionTicket")
	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	return nil
}

// 发送 ClientFinished (tls1.2)
func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	zclog.Debug("===== 客户端发送 ChangeCipherSpec")
	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	zclog.Debug("===== 客户端发送 ClientFinished")
	copy(out, finished.verifyData)
	return nil
}

// 验证服务端证书
// verifyServerCertificate parses and verifies the provided chain, setting
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("gmtls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			DNSName:       c.config.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		var err error
		// 尝试构建证书信任链, certs[0]是子证书
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	switch certs[0].PublicKey.(type) {
	// 补充sm2条件
	case *sm2.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("gmtls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}
	// 将服务端的证书设置为对方证书
	c.peerCertificates = certs

	if c.config.VerifyPeerCertificate != nil {
		// 执行额外的对方证书验证函数
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil {
		// 执行额外的连接验证函数
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

// certificateRequestInfoFromMsg generates a CertificateRequestInfo from a TLS
// <= 1.2 CertificateRequest, making an effort to fill in missing information.
func certificateRequestInfoFromMsg(ctx context.Context, vers uint16, certReq *certificateRequestMsg) *CertificateRequestInfo {
	cri := &CertificateRequestInfo{
		AcceptableCAs: certReq.certificateAuthorities,
		Version:       vers,
		ctx:           ctx,
	}

	var rsaAvail, ecAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecAvail = true
		}
	}

	if !certReq.hasSignatureAlgorithm {
		// Prior to TLS 1.2, signature schemes did not exist. In this case we
		// make up a list based on the acceptable certificate types, to help
		// GetClientCertificate and SupportsCertificate select the right certificate.
		// The hash part of the SignatureScheme is a lie here, because
		// TLS 1.0 and 1.1 always use MD5+SHA1 for RSA and SHA1 for ECDSA.
		switch {
		case rsaAvail && ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case rsaAvail:
			cri.SignatureSchemes = []SignatureScheme{
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
			}
		}
		return cri
	}

	// Filter the signature schemes based on the certificate types.
	// See RFC 5246, Section 7.4.4 (where it calls this "somewhat complicated").
	cri.SignatureSchemes = make([]SignatureScheme, 0, len(certReq.supportedSignatureAlgorithms))
	for _, sigScheme := range certReq.supportedSignatureAlgorithms {
		sigType, _, err := typeAndHashFromSignatureScheme(sigScheme)
		if err != nil {
			continue
		}
		switch sigType {
		case signatureECDSA, signatureEd25519:
			if ecAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		case signatureRSAPSS, signaturePKCS1v15:
			if rsaAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		}
	}

	return cri
}

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	for _, chain := range c.config.Certificates {
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}
		return &chain, nil
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

// 获取客户端会话缓存key，使用ServerName或serverAddr。
// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

// 将name适配为SNI要求的格式。
//  不支持IPv4或IPv6格式，支持DNS域名。
// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func hostnameInSNI(name string) string {
	host := name
	// 去除首尾的"[]"包裹
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	// 去除"%"以后的内容
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	// 检查host是ip的话是否合法，合法则返回空字符串
	if net.ParseIP(host) != nil {
		return ""
	}
	// 去除末尾的一个或多个"."
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
