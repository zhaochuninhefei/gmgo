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
	"container/list"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecdsa_ext"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
)

//goland:noinspection GoCommentStart
const (
	// 国密SSL版本定义 GM/T 0024-2014
	VersionGMSSL = 0x0101
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// TO Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)

func ShowTLSVersion(version int) string {
	switch version {
	case VersionGMSSL:
		return "VersionGMSSL"
	case VersionTLS10:
		return "VersionTLS10"
	case VersionTLS11:
		return "VersionTLS11"
	case VersionTLS12:
		return "VersionTLS12"
	case VersionTLS13:
		return "VersionTLS13"
	case VersionSSL30:
		return "VersionSSL30"
	default:
		return "unknown"
	}
}

const (
	maxPlaintext       = 16384        // maximum plaintext payload length
	maxCiphertext      = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13 = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen    = 5            // record header length
	maxHandshake       = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxUselessRecords  = 16           // maximum number of consecutive non-advancing records

	// minVersion = VersionGMSSL
	// maxVersion = VersionTLS13
)

// TLS record types.
type recordType uint8

// tls记录类型
const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
//goland:noinspection GoUnusedConst
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeNextProtocol        uint8 = 67  // Not IANA assigned
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionRenegotiationInfo       uint16 = 0xff01
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.3, this type is called NamedGroup, but at this time this library
// only supports Elliptic Curve based groups. See RFC 8446, Section 4.2.7.
type CurveID uint16

// 支持的椭圆曲线ID
const (
	CurveP256   CurveID = 23
	CurveP384   CurveID = 24
	CurveP521   CurveID = 25
	Curve256Sm2 CurveID = 26 // 添加国密SM2曲线ID
	X25519      CurveID = 29
)

// tls1.3的密钥交换算法参数，或者说共享密钥计算用参数。
// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group CurveID // 椭圆曲线ID
	data  []byte  // 公钥
}

// tls1.3的 PSK密钥交换模式
// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
const (
	pskModePlain uint8 = 0 // 平文模式
	pskModeDHE   uint8 = 1 // DHE模式, 动态笛福赫尔曼密钥交换算法
)

// tls1.3支持的psk身份，用作会话票据，或已保存的会话的引用。
// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	// 椭圆曲线上的点坐标的序列化格式
	// 该格式是不压缩存储, 即将x,y坐标完整序列化
	pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // ECDSA or EdDSA keys, see RFC 8422, Section 3.
	// 是否添加SM2Type 用于tls1.2及更老版本，暂时不做国密对应
	// certTypeSM2Sign = 128
)

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
const (
	signaturePKCS1v15 uint8 = iota + 225
	signatureRSAPSS
	signatureECDSA
	signatureEd25519
	signatureSM2
	signatureECDSAEXT
)

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed, and that the input should be signed directly. It is the
// hash function associated with the Ed25519 signature scheme.
var directSigning x509.Hash = 0

// supportedSignatureAlgorithms contains the signature and hash algorithms that
// the code advertises as supported in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
var supportedSignatureAlgorithms = []SignatureScheme{
	PSSWithSHA256,
	ECDSAWithP256AndSHA256,
	SM2WITHSM3,                // 增加SM2WithSM3
	ECDSAEXTWithP256AndSHA256, // 添加ECDSAEXTWithP256AndSHA256
	Ed25519,
	PSSWithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA256,
	PKCS1WithSHA384,
	PKCS1WithSHA512,
	ECDSAWithP384AndSHA384,
	ECDSAWithP521AndSHA512,
	PKCS1WithSHA1,
	ECDSAWithSHA1,
}

// 服务端未能获取到客户端公钥时，会发送HelloRetryRequest,请求客户端重新发送ClientHello。
// 此时需要将HelloRetryRequest中的random字段设置为该字段。
// helloRetryRequestRandom is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
var helloRetryRequestRandom = []byte{ // See RFC 8446, Section 4.1.3.
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const (
	// downgradeCanaryTLS12 or downgradeCanaryTLS11 is embedded in the server
	// random as a downgrade protection if the server would be capable of
	// negotiating a higher version. See RFC 8446, Section 4.1.3.
	downgradeCanaryTLS12 = "DOWNGRD\x01"
	downgradeCanaryTLS11 = "DOWNGRD\x00"
)

// testingOnlyForceDowngradeCanary is set in tests to force the server side to
// include downgrade canaries even if it's using its highers supported version.
var testingOnlyForceDowngradeCanary bool

// ConnectionState TLS握手过程中的连接状态管理用
// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	// Version is the TLS version used by the connection (e.g. VersionTLS12).
	Version uint16

	// HandshakeComplete is true if the handshake has concluded.
	HandshakeComplete bool

	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool

	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	CipherSuite uint16

	// NegotiatedProtocol is the application protocol negotiated with ALPN.
	NegotiatedProtocol string

	// NegotiatedProtocolIsMutual used to indicate a mutual NPN negotiation.
	//
	// ToDeprecated: this value is always true.
	NegotiatedProtocolIsMutual bool

	// ServerName is the value of the Server Name Indication extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string

	// PeerCertificates are the parsed certificates sent by the peer, in the
	// order in which they were sent. The first element is the leaf certificate
	// that the connection is verified against.
	//
	// On the client side, it can't be empty. On the server side, it can be
	// empty if Config.ClientAuth is not RequireAnyClientCert or
	// RequireAndVerifyClientCert.
	PeerCertificates []*x509.Certificate

	// VerifiedChains is a list of one or more chains where the first element is
	// PeerCertificates[0] and the last element is from Config.RootCAs (on the
	// client side) or Config.ClientCAs (on the server side).
	//
	// On the client side, it's set if Config.InsecureSkipVerify is false. On
	// the server side, it's set if Config.ClientAuth is VerifyClientCertIfGiven
	// (and the peer provided a certificate) or RequireAndVerifyClientCert.
	VerifiedChains [][]*x509.Certificate

	// SignedCertificateTimestamps is a list of SCTs provided by the peer
	// through the TLS handshake for the leaf certificate, if any.
	SignedCertificateTimestamps [][]byte

	// OCSPResponse is a stapled Online Certificate Status Protocol (OCSP)
	// response provided by the peer for the leaf certificate, if any.
	OCSPResponse []byte

	// TLSUnique contains the "tls-unique" channel binding value (see RFC 5929,
	// Section 3). This value will be nil for TLS 1.3 connections and for all
	// resumed connections.
	//
	// ToDeprecated: there are conditions in which this value might not be unique
	// to a connection. See the Security Considerations sections of RFC 5705 and
	// RFC 7627, and https://mitls.org/pages/attacks/3SHAKE#channelbindings.
	TLSUnique []byte

	// ekm is a closure exposed via ExportKeyingMaterial.
	ekm func(label string, context []byte, length int) ([]byte, error)
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice as defined in RFC 5705. If context is nil, it is not used as part of
// the seed. If the connection was set to allow renegotiation via
// Config.Renegotiation, this function will return an error.
func (cs *ConnectionState) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	return cs.ekm(label, context, length)
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
	// NoClientCert indicates that no client certificate should be requested
	// during the handshake, and if any certificates are sent they will not
	// be verified.
	NoClientCert ClientAuthType = iota
	// RequestClientCert indicates that a client certificate should be requested
	// during the handshake, but does not require that the client send any
	// certificates.
	RequestClientCert
	// RequireAnyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one certificate is required to be
	// sent by the client, but that certificate is not required to be valid.
	RequireAnyClientCert
	// VerifyClientCertIfGiven indicates that a client certificate should be requested
	// during the handshake, but does not require that the client sends a
	// certificate. If the client does send a certificate it is required to be
	// valid.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one valid certificate is required
	// to be sent by the client.
	RequireAndVerifyClientCert
)

// requiresClientCert reports whether the ClientAuthType requires a client
// certificate to be provided.
func requiresClientCert(c ClientAuthType) bool {
	switch c {
	case RequireAnyClientCert, RequireAndVerifyClientCert:
		return true
	default:
		return false
	}
}

// ClientSessionState contains the state needed by clients to resume TLS
// sessions.
type ClientSessionState struct {
	sessionTicket      []uint8               // Encrypted ticket used for session resumption with server
	vers               uint16                // TLS version negotiated for the session
	cipherSuite        uint16                // Ciphersuite negotiated for the session
	masterSecret       []byte                // Full handshake MasterSecret, or TLS 1.3 resumption_master_secret
	serverCertificates []*x509.Certificate   // Certificate chain presented by the server
	verifiedChains     [][]*x509.Certificate // Certificate chains we built for verification
	receivedAt         time.Time             // When the session ticket was received from the server
	ocspResponse       []byte                // Stapled OCSP response presented by the server
	scts               [][]byte              // SCTs presented by the server

	// TLS 1.3 fields.
	nonce  []byte    // Ticket nonce sent by the server, to derive PSK
	useBy  time.Time // Expiration of the ticket lifetime as set by the server
	ageAdd uint32    // Random obfuscation factor for sending the ticket age
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines. Up to TLS 1.2, only ticket-based resumption is supported, not
// SessionID-based resumption. In TLS 1.3 they were merged into PSK modes, which
// are supported via this interface.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key. It might
	// get called multiple times in a connection if a TLS 1.3 server provides
	// more than one session ticket. If called with a nil *ClientSessionState,
	// it should remove the cache entry.
	Put(sessionKey string, cs *ClientSessionState)
}

//go:generate stringer -type=SignatureScheme,CurveID,ClientAuthType -output=common_string.go

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type SignatureScheme uint16

//goland:noinspection GoCommentStart
const (
	// RSASSA-PKCS1-v1_5 algorithms.
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	// ECDSAEXT algorithms. Only constrained to a specific curve in TLS 1.3.
	ECDSAEXTWithP256AndSHA256 SignatureScheme = 0x0404
	ECDSAEXTWithP384AndSHA384 SignatureScheme = 0x0504
	ECDSAEXTWithP521AndSHA512 SignatureScheme = 0x0604

	// EdDSA algorithms.
	Ed25519 SignatureScheme = 0x0807

	// Legacy signature and hash algorithms for TLS 1.2.
	PKCS1WithSHA1 SignatureScheme = 0x0201
	ECDSAWithSHA1 SignatureScheme = 0x0203

	// 国密签名算法
	SM2WITHSM3 SignatureScheme = 0x0204
)

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate and GetConfigForClient callbacks.
type ClientHelloInfo struct {
	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []uint16

	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	// SupportedCurves lists the elliptic curves supported by the client.
	// SupportedCurves is set only if the Supported Elliptic Curves
	// Extension is being used (see RFC 4492, Section 5.1.1).
	SupportedCurves []CurveID

	// SupportedPoints lists the point formats supported by the client.
	// SupportedPoints is set only if the Supported Point Formats Extension
	// is being used (see RFC 4492, Section 5.1.2).
	SupportedPoints []uint8

	// SignatureSchemes lists the signature and hash schemes that the client
	// is willing to verify. SignatureSchemes is set only if the Signature
	// Algorithms Extension is being used (see RFC 5246, Section 7.4.1.4.1).
	SignatureSchemes []SignatureScheme

	// SupportedProtos lists the application protocols supported by the client.
	// SupportedProtos is set only if the Application-Layer Protocol
	// Negotiation Extension is being used (see RFC 7301, Section 3.1).
	//
	// Servers can select a protocol by setting Config.NextProtos in a
	// GetConfigForClient return value.
	SupportedProtos []string

	// SupportedVersions lists the TLS versions supported by the client.
	// For TLS versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	SupportedVersions []uint16

	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	Conn net.Conn

	// config is embedded by the GetCertificate or GetConfigForClient caller,
	// for use with SupportsCertificate.
	config *Config

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (chi *ClientHelloInfo) Context() context.Context {
	return chi.ctx
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte

	// SignatureSchemes lists the signature schemes that the server is
	// willing to verify.
	SignatureSchemes []SignatureScheme

	// Version is the TLS version that was negotiated for this connection.
	Version uint16

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (cri *CertificateRequestInfo) Context() context.Context {
	return cri.ctx
}

// RenegotiationSupport enumerates the different levels of support for TLS
// renegotiation. TLS renegotiation is the act of performing subsequent
// handshakes on a connection after the first. This significantly complicates
// the state machine and has been the source of numerous, subtle security
// issues. Initiating a renegotiation is not supported, but support for
// accepting renegotiation requests may be enabled.
//
// Even when enabled, the server may not change its identity between handshakes
// (i.e. the leaf certificate must be the same). Additionally, concurrent
// handshake and application data flow is not permitted so renegotiation can
// only be used with protocols that synchronise with the renegotiation, such as
// HTTPS.
//
// Renegotiation is not defined in TLS 1.3.
type RenegotiationSupport int

const (
	// RenegotiateNever disables renegotiation.
	RenegotiateNever RenegotiationSupport = iota

	// RenegotiateOnceAsClient allows a remote server to request
	// renegotiation once per connection.
	RenegotiateOnceAsClient

	// RenegotiateFreelyAsClient allows a remote server to repeatedly
	// request renegotiation.
	RenegotiateFreelyAsClient
)

// Config TLS通信配置
// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {

	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	// 当前时间
	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates 本地证书池，握手时可从这里选取合适的证书发送给对端用于身份验证
	//
	// Certificates contains one or more certificate chains to present to the
	// other side of the connection. The first certificate compatible with the
	// peer's requirements is selected automatically.
	//
	// Server configurations must set one of Certificates, GetCertificate or
	// GetConfigForClient. Clients doing client-authentication may set either
	// Certificates or GetClientCertificate.
	//
	// Note: if there are multiple Certificates, and they don't have the
	// optional field Leaf set, certificate selection will incur a significant
	// per-handshake performance cost.
	Certificates []Certificate

	// NameToCertificate 本地证书map, 握手时可以根据对端传来的ServerName匹配对应证书。目前不推荐使用。
	//
	// NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	//
	// ToDeprecated: NameToCertificate only allows associating a single
	// certificate with a given name. Leave this field nil to let the library
	// select the first compatible chain from Certificates.
	NameToCertificate map[string]*Certificate

	// GetCertificate 根据ClientHelloInfo返回证书的函数，只在客户端提供了SNI或Certificates为空时调用。
	//  该函数只在有特殊的证书选择逻辑时，通过这个自定义的函数来实现。比从Certificates获取更优先。
	//
	// GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// best element of Certificates will be used.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetKECertificate 获取密钥交换证书（加密证书）
	// 这个方法只有在使用Config中Certificates为空或长度小于2时，才会被调用。
	// 如果该方法为空，则默认从证书列表中 Certificates 取出第二个位置的证书，也就是加密证书。
	// 该方法只有GMSSL流程中才会调用。
	// GetKECertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetClientCertificate 当服务端向客户端请求证书时调用，用于获取客户端证书。该函数被设置时比Certificates优先。
	//
	// GetClientCertificate, if not nil, is called when a server requests a
	// certificate from a client. If set, the contents of Certificates will
	// be ignored.
	//
	// If GetClientCertificate returns an error, the handshake will be
	// aborted and that error will be returned. Otherwise
	// GetClientCertificate must return a non-nil Certificate. If
	// Certificate.Certificate is empty then no certificate will be sent to
	// the server. If this is unacceptable to the server then it may abort
	// the handshake.
	//
	// GetClientCertificate may be called multiple times for the same
	// connection if renegotiation occurs or if TLS 1.3 is in use.
	GetClientCertificate func(*CertificateRequestInfo) (*Certificate, error)

	// GetConfigForClient 当服务端收到一个ClientHello后调用，用于获取客户端的TLS通信配置。
	//
	// GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// If SessionTicketKey was explicitly set on the returned Config, or if
	// SetSessionTicketKeys was called on the returned Config, those keys will
	// be used. Otherwise, the original Config keys will be used (and possibly
	// rotated if they are automatically managed).
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// VerifyPeerCertificate 预先定义好的额外的证书验证。
	// 客户端或服务端进行正常的证书验证后调用,接收对方提供的ASN1格式证书或经过验证的证书链。
	//
	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled by
	// setting InsecureSkipVerify, or (for a server) when ClientAuth is
	// RequestClientCert or RequireAnyClientCert, then this callback will
	// be considered but the verifiedChains argument will always be nil.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection 预先定义好的额外的连接验证。
	// 在正常的证书验证以及VerifyPeerCertificate之后调用。
	//
	// VerifyConnection, if not nil, is called after normal certificate
	// verification and after VerifyPeerCertificate by either a TLS client
	// or server. If it returns a non-nil error, the handshake is aborted
	// and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. This callback will run for all connections
	// regardless of InsecureSkipVerify or ClientAuth settings.
	VerifyConnection func(ConnectionState) error

	// RootCAs 客户端用来验证服务端证书的CA根证书池
	//
	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// NextProtos 应用层协议列表
	//  如果双方都支持应用层协议协商（Application-Layer Protocol Negotiation，简称ALPN），
	//  则从该列表中选择。
	//
	// NextProtos is a list of supported application level protocols, in
	// order of preference. If both peers support ALPN, the selected
	// protocol will be one from this list, and the connection will fail
	// if there is no mutually supported protocol. If NextProtos is empty
	// or the peer doesn't support ALPN, the connection will succeed and
	// ConnectionState.NegotiatedProtocol will be empty.
	NextProtos []string

	// ServerName InsecureSkipVerify为设置时，根据ServerName检查收到的证书中的hostname。
	//
	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting unless it is
	// an IP address.
	ServerName string

	// ClientAuth 服务端对客户端认证的策略，默认NoClientCert，不需要客户端证书。
	//
	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// ClientCAs 服务端用来验证客户端证书的CA根证书池, 当服务端需要客户端提供证书时,会使用这些CA证书验证。
	//
	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// InsecureSkipVerify 控制客户端是否验证服务器的证书链和主机名。
	//  如果 InsecureSkipVerify 为真，crypto/tls 接受服务器提供的任何证书以及该证书中的任何主机名。
	//  在这种模式下，除非使用自定义验证，否则 TLS 容易受到中间机攻击。
	//  这应该仅用于测试或与 VerifyConnection 或 VerifyPeerCertificate 结合使用。
	//
	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. If InsecureSkipVerify is true, crypto/tls
	// accepts any certificate presented by the server and any host name in that
	// certificate. In this mode, TLS is susceptible to machine-in-the-middle
	// attacks unless custom verification is used. This should be used only for
	// testing or in combination with VerifyConnection or VerifyPeerCertificate.
	InsecureSkipVerify bool

	// CipherSuites 是启用的 TLS 1.0–1.2 密码套件的列表。 列表的顺序被忽略。
	//  请注意，TLS 1.3 密码套件不可配置。
	//
	// CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
	// the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
	//
	// If CipherSuites is nil, a safe default list is used. The default cipher
	// suites might change over time.
	CipherSuites []uint16

	// PreferCipherSuites 优先密码套件列表, 客户端连接时优先想要使用的密码套件。
	//  tls1.3或gmssl支持。
	//  added by zhaochun
	PreferCipherSuites []uint16

	// PreferServerCipherSuites is a legacy field and has no effect.
	//
	// It used to control whether the server would follow the client's or the
	// server's preference. Servers now select the best mutually supported
	// cipher suite based on logic that takes into account inferred client
	// hardware, server hardware, and security.
	//
	// Deprected: PreferServerCipherSuites is ignored.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled 可以设置为 true 以禁用会话票证和 PSK（恢复）支持。
	// 请注意，在客户端上，如果 ClientSessionCache 为 nil，会话票证支持也会被禁用。
	// SessionTicketsDisabled may be set to true to disable session ticket and
	// PSK (resumption) support. Note that on clients, session ticket support is
	// also disabled if ClientSessionCache is nil.
	SessionTicketsDisabled bool

	// TLS 服务器使用 SessionTicketKey 来提供会话恢复。
	// SessionTicketKey is used by TLS servers to provide session resumption.
	// See RFC 5077 and the PSK mode of RFC 8446. If zero, it will be filled
	// with random data before the first server handshake.
	//
	// ToDeprecated: if this field is left at zero, session ticket keys will be
	// automatically rotated every day and dropped after seven days. For
	// customizing the rotation schedule or synchronizing servers that are
	// terminating connections for the same host, use SetSessionTicketKeys.
	SessionTicketKey [32]byte

	// ClientSessionCache 是用于 TLS 会话恢复的 ClientSessionState 条目的缓存。
	// 它仅供客户使用。
	// ClientSessionCache is a cache of ClientSessionState entries for TLS
	// session resumption. It is only used by clients.
	ClientSessionCache ClientSessionCache

	// 支持的最低的TLS协议版本，默认 TLS 1.0
	// 国密改造后默认是 GMSSL
	// MinVersion contains the minimum TLS version that is acceptable.
	// If zero, TLS 1.0 is currently taken as the minimum.
	MinVersion uint16

	// 支持的最高的TLS协议版本，默认 TLS 1.3
	// MaxVersion contains the maximum TLS version that is acceptable.
	// If zero, the maximum version supported by this package is used,
	// which is currently TLS 1.3.
	MaxVersion uint16

	// CurvePreferences ECDHE握手支持的椭圆曲线ID
	//
	// CurvePreferences contains the elliptic curves that will be used in
	// an ECDHE handshake, in preference order. If empty, the default will
	// be used. The client will use the first preference as the type for
	// its key share in TLS 1.3. This may change in the future.
	CurvePreferences []CurveID

	// SignAlgPrefer 优先选择的签名算法
	//  tls1.3或gmssl支持
	//  added by zhaochun
	SignAlgPrefer []SignatureScheme

	// DynamicRecordSizingDisabled 禁用 TLS 记录的自适应大小。
	// 如果为 true，则始终使用最大可能的 TLS 记录大小。
	// 如果为 false，则可能会调整 TLS 记录的大小以尝试改善延迟。
	// DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	DynamicRecordSizingDisabled bool

	// 重新协商控制支持哪些类型的重新协商。 默认值 none 对于绝大多数应用程序都是正确的。
	// Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	Renegotiation RenegotiationSupport

	// KeyLogWriter 可以选择以 NSS 密钥日志格式指定 TLS 主密钥的存储目标。
	// 该目标可用于允许 Wireshark 等外部程序解密 TLS 连接。
	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of KeyLogWriter compromises security and should only be
	// used for debugging.
	KeyLogWriter io.Writer

	// mutex protects sessionTicketKeys and autoSessionTicketKeys.
	mutex sync.RWMutex
	// sessionTicketKeys contains zero or more ticket keys. If set, it means the
	// the keys were set with SessionTicketKey or SetSessionTicketKeys. The
	// first key is used for new tickets and any subsequent keys can be used to
	// decrypt old tickets. The slice contents are not protected by the mutex
	// and are immutable.
	sessionTicketKeys []ticketKey
	// autoSessionTicketKeys is like sessionTicketKeys but is owned by the
	// auto-rotation logic. See Config.ticketKeys.
	autoSessionTicketKeys []ticketKey
}

const (
	// ticketKeyNameLen is the number of bytes of identifier that is prepended to
	// an encrypted session ticket in order to identify the key used to encrypt it.
	ticketKeyNameLen = 16

	// ticketKeyLifetime is how long a ticket key remains valid and can be used to
	// resume a client connection.
	ticketKeyLifetime = 7 * 24 * time.Hour // 7 days

	// ticketKeyRotation is how often the server should rotate the session ticket key
	// that is used for new tickets.
	ticketKeyRotation = 24 * time.Hour
)

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	// keyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	keyName [ticketKeyNameLen]byte
	// 原先是aesKey，国密改造改为sm4
	sm4Key  [16]byte
	hmacKey [16]byte
	// created is the time at which this ticket key was created. See Config.ticketKeys.
	created time.Time
}

// ticketKeyFromBytes converts from the external representation of a session
// ticket key to a ticketKey. Externally, session ticket keys are 32 random
// bytes and this function expands that into sufficient name and key material.
func (c *Config) ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	// 目前只能继续采用sha512，因为sm3校验和长度只有32个字节，不够用。
	hashed := sha512.Sum512(b[:])
	// 1~16字节作为 keyName
	copy(key.keyName[:], hashed[:ticketKeyNameLen])
	// 17~32字节作为aesKey
	copy(key.sm4Key[:], hashed[ticketKeyNameLen:ticketKeyNameLen+16])
	// 33~64字节作为hmacKey
	copy(key.hmacKey[:], hashed[ticketKeyNameLen+16:ticketKeyNameLen+32])
	key.created = c.time()
	return key
}

// maxSessionTicketLifetime is the maximum allowed lifetime of a TLS 1.3 session
// ticket, and the lifetime we set for tickets we send.
const maxSessionTicketLifetime = 7 * 24 * time.Hour

// Clone returns a shallow clone of c or nil if c is nil. It is safe to clone a Config that is
// being used concurrently by a TLS client or server.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &Config{
		// GMSupport:                   c.GMSupport,
		Rand:              c.Rand,
		Time:              c.Time,
		Certificates:      c.Certificates,
		NameToCertificate: c.NameToCertificate,
		GetCertificate:    c.GetCertificate,
		// GetKECertificate:            c.GetKECertificate,
		GetClientCertificate:        c.GetClientCertificate,
		GetConfigForClient:          c.GetConfigForClient,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
		VerifyConnection:            c.VerifyConnection,
		RootCAs:                     c.RootCAs,
		NextProtos:                  c.NextProtos,
		ServerName:                  c.ServerName,
		ClientAuth:                  c.ClientAuth,
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		PreferServerCipherSuites:    c.PreferServerCipherSuites,
		SessionTicketsDisabled:      c.SessionTicketsDisabled,
		SessionTicketKey:            c.SessionTicketKey,
		ClientSessionCache:          c.ClientSessionCache,
		MinVersion:                  c.MinVersion,
		MaxVersion:                  c.MaxVersion,
		CurvePreferences:            c.CurvePreferences,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		Renegotiation:               c.Renegotiation,
		KeyLogWriter:                c.KeyLogWriter,
		sessionTicketKeys:           c.sessionTicketKeys,
		autoSessionTicketKeys:       c.autoSessionTicketKeys,
		PreferCipherSuites:          c.PreferCipherSuites,
		SignAlgPrefer:               c.SignAlgPrefer,
	}
}

// deprecatedSessionTicketKey is set as the prefix of SessionTicketKey if it was
// randomized for backwards compatibility but is not in use.
var deprecatedSessionTicketKey = []byte("DEPRECATED")

// initLegacySessionTicketKeyRLocked ensures the legacy SessionTicketKey field is
// randomized if empty, and that sessionTicketKeys is populated from it otherwise.
func (c *Config) initLegacySessionTicketKeyRLocked() {
	// Don't write if SessionTicketKey is already defined as our deprecated string,
	// or if it is defined by the user but sessionTicketKeys is already set.
	if c.SessionTicketKey != [32]byte{} &&
		(bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) || len(c.sessionTicketKeys) > 0) {
		return
	}

	// We need to write some data, so get an exclusive lock and re-check any conditions.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.SessionTicketKey == [32]byte{} {
		// 生成一个长度32的随机SessionTicketKey
		if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
			panic(fmt.Sprintf("gmtls: unable to generate random session ticket key: %v", err))
		}
		// Write the deprecated prefix at the beginning so we know we created
		// it. This key with the DEPRECATED prefix isn't used as an actual
		// session ticket key, and is only randomized in case the application
		// reuses it for some reason.
		copy(c.SessionTicketKey[:], deprecatedSessionTicketKey)
	} else if !bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) && len(c.sessionTicketKeys) == 0 {
		c.sessionTicketKeys = []ticketKey{c.ticketKeyFromBytes(c.SessionTicketKey)}
	}

}

// 为当前连接获取ticketKeys。
// ticketKeys returns the ticketKeys for this connection.
// If configForClient has explicitly set keys, those will
// be returned. Otherwise, the keys on c will be used and
// may be rotated if auto-managed.
// During rotation, any expired session ticket keys are deleted from
// c.sessionTicketKeys. If the session ticket key that is currently
// encrypting tickets (ie. the first ticketKey in c.sessionTicketKeys)
// is not fresh, then a new session ticket key will be
// created and prepended to c.sessionTicketKeys.
func (c *Config) ticketKeys(configForClient *Config) []ticketKey {
	// If the ConfigForClient callback returned a Config with explicitly set
	// keys, use those, otherwise just use the original Config.
	if configForClient != nil {
		configForClient.mutex.RLock()
		if configForClient.SessionTicketsDisabled {
			return nil
		}
		configForClient.initLegacySessionTicketKeyRLocked()
		if len(configForClient.sessionTicketKeys) != 0 {
			ret := configForClient.sessionTicketKeys
			configForClient.mutex.RUnlock()
			return ret
		}
		configForClient.mutex.RUnlock()
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.SessionTicketsDisabled {
		return nil
	}
	c.initLegacySessionTicketKeyRLocked()
	if len(c.sessionTicketKeys) != 0 {
		return c.sessionTicketKeys
	}
	// Fast path for the common case where the key is fresh enough.
	if len(c.autoSessionTicketKeys) > 0 && c.time().Sub(c.autoSessionTicketKeys[0].created) < ticketKeyRotation {
		return c.autoSessionTicketKeys
	}

	// autoSessionTicketKeys are managed by auto-rotation.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Re-check the condition in case it changed since obtaining the new lock.
	if len(c.autoSessionTicketKeys) == 0 || c.time().Sub(c.autoSessionTicketKeys[0].created) >= ticketKeyRotation {
		var newKey [32]byte
		if _, err := io.ReadFull(c.rand(), newKey[:]); err != nil {
			panic(fmt.Sprintf("unable to generate random session ticket key: %v", err))
		}
		valid := make([]ticketKey, 0, len(c.autoSessionTicketKeys)+1)
		valid = append(valid, c.ticketKeyFromBytes(newKey))
		for _, k := range c.autoSessionTicketKeys {
			// While rotating the current key, also remove any expired ones.
			if c.time().Sub(k.created) < ticketKeyLifetime {
				valid = append(valid, k)
			}
		}
		c.autoSessionTicketKeys = valid
	}
	return c.autoSessionTicketKeys
}

// SetSessionTicketKeys updates the session ticket keys for a server.
//
// The first key will be used when creating new tickets, while all keys can be
// used for decrypting tickets. It is safe to call this function while the
// server is running in order to rotate the session ticket keys. The function
// will panic if keys is empty.
//
// Calling this function will turn off automatic session ticket key rotation.
//
// If multiple servers are terminating connections for the same host they should
// all have the same session ticket keys. If the session ticket keys leaks,
// previously recorded and future TLS connections using those keys might be
// compromised.
func (c *Config) SetSessionTicketKeys(keys [][32]byte) {
	if len(keys) == 0 {
		panic("gmtls: keys must have at least one key")
	}

	newKeys := make([]ticketKey, len(keys))
	for i, key := range keys {
		newKeys[i] = c.ticketKeyFromBytes(key)
	}

	c.mutex.Lock()
	c.sessionTicketKeys = newKeys
	c.mutex.Unlock()
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites != nil {
		return c.CipherSuites
	}
	return defaultCipherSuites
}

// TODO: 可能需要调整 VersionGMSSL 的位置
var supportedVersions = []uint16{
	VersionTLS13,
	VersionTLS12,
	VersionTLS11,
	VersionTLS10,
	VersionGMSSL,
}

// 获取目标Config支持的TLS协议
//  协议版本需要位于[c.MinVersion, c.MaxVersion]之间
func (c *Config) supportedVersions() []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

// 获取支持的最高TLS协议版本
func (c *Config) maxSupportedVersion() uint16 {
	supportedVersions := c.supportedVersions()
	if len(supportedVersions) == 0 {
		return 0
	}
	// supportedVersions列表中，越高的版本越靠前
	return supportedVersions[0]
}

// supportedVersionsFromMax returns a list of supported versions derived from a
// legacy maximum version value. Note that only versions supported by this
// library are returned. Any newer peer will use supportedVersions anyway.
func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

// 将sm2p256列为默认曲线首位
var defaultCurvePreferences = []CurveID{Curve256Sm2, X25519, CurveP256, CurveP384, CurveP521}

func (c *Config) curvePreferences() []CurveID {
	if c == nil || len(c.CurvePreferences) == 0 {
		return defaultCurvePreferences
	}
	return c.CurvePreferences
}

func (c *Config) supportsCurve(curve CurveID) bool {
	for _, cc := range c.curvePreferences() {
		if cc == curve {
			return true
		}
	}
	return false
}

// 协商tls协议
//  根据对方传来的tls版本信息，从己方支持的版本列表中从前往后选取第一个匹配的版本。
//  目前优先匹配顺序是 tls1.3 -> gmssl -> tls1.2 ...
// mutualVersion returns the protocol version to use given the advertised
// versions of the peer. Priority is given to the peer preference order.
func (c *Config) mutualVersion(peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions()
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				return v, true
			}
		}
	}
	return 0, false
}

// getCertificate 返回密钥交换使用的证书及密钥
// 该方法只有GMSSL会调用
// 如果 Certificates 长度大于等于2时，默认返回第2个证书密钥
// 如果 Certificates 为空或不足2时，调用 GetEKCertificate 方法获取。
// func (c *Config) getEKCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
// 	if c.GetKECertificate != nil && (len(c.Certificates) < 2) {
// 		cert, err := c.GetKECertificate(clientHello)
// 		if cert != nil || err != nil {
// 			return cert, err
// 		}
// 	}
// 	if len(c.Certificates) >= 2 {
// 		return &c.Certificates[1], nil
// 	}
// 	return nil, errors.New("gmtls: no key exchange (encrypt) certificate configured")
// }

var errNoCertificates = errors.New("gmtls: no certificates configured")

// getCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	// 优先使用在config中设置的GetCertificate函数
	//  需要config配置GetCertificate且没有配置Certificates, 或config配置了GetCertificate且ClientHello中写入了ServerName
	if c.GetCertificate != nil &&
		(len(c.Certificates) == 0 || len(clientHello.ServerName) > 0) {
		cert, err := c.GetCertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoCertificates
	}

	if len(c.Certificates) == 1 {
		// There's only one choice, so no point doing any work.
		return &c.Certificates[0], nil
	}

	// 次优先使用config中设置的NameToCertificate, 这是一个map，尝试用clientHello.ServerName为key获取对应证书
	if c.NameToCertificate != nil {
		name := strings.ToLower(clientHello.ServerName)
		if cert, ok := c.NameToCertificate[name]; ok {
			return cert, nil
		}
		if len(name) > 0 {
			labels := strings.Split(name, ".")
			labels[0] = "*"
			wildcardName := strings.Join(labels, ".")
			if cert, ok := c.NameToCertificate[wildcardName]; ok {
				return cert, nil
			}
		}
	}

	for _, cert := range c.Certificates {
		if err := clientHello.SupportsCertificate(&cert); err == nil {
			return &cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &c.Certificates[0], nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the client that sent the ClientHello. Otherwise, it returns an error
// describing the reason for the incompatibility.
//
// If this ClientHelloInfo was passed to a GetConfigForClient or GetCertificate
// callback, this method will take into account the associated Config. Note that
// if GetConfigForClient returns a different Config, the change can't be
// accounted for by this method.
//
// This function will call x509.ParseCertificate unless c.Leaf is set, which can
// incur a significant performance cost.
func (chi *ClientHelloInfo) SupportsCertificate(c *Certificate) error {
	// Note we don't currently support certificate_authorities nor
	// signature_algorithms_cert, and don't check the algorithms of the
	// signatures on the chain (which anyway are a SHOULD, see RFC 8446,
	// Section 4.4.2.2).

	config := chi.config
	if config == nil {
		config = &Config{}
	}
	vers, ok := config.mutualVersion(chi.SupportedVersions)
	if !ok {
		return errors.New("no mutually supported protocol versions")
	}

	// If the client specified the name they are trying to connect to, the
	// certificate needs to be valid for it.
	if chi.ServerName != "" {
		x509Cert, err := c.leaf()
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		if err := x509Cert.VerifyHostname(chi.ServerName); err != nil {
			return fmt.Errorf("certificate is not valid for requested server name: %w", err)
		}
	}

	// supportsRSAFallback returns nil if the certificate and connection support
	// the static RSA key exchange, and unsupported otherwise. The logic for
	// supporting static RSA is completely disjoint from the logic for
	// supporting signed key exchanges, so we just check it as a fallback.
	supportsRSAFallback := func(unsupported error) error {
		// TLS 1.3 dropped support for the static RSA key exchange.
		if vers == VersionTLS13 || vers == VersionGMSSL {
			return unsupported
		}
		// The static RSA key exchange works by decrypting a challenge with the
		// RSA private key, not by signing, so check the PrivateKey implements
		// crypto.Decrypter, like *rsa.PrivateKey does.
		if priv, ok := c.PrivateKey.(crypto.Decrypter); ok {
			if _, ok := priv.Public().(*rsa.PublicKey); !ok {
				return unsupported
			}
		} else {
			return unsupported
		}
		// Finally, there needs to be a mutual cipher suite that uses the static
		// RSA key exchange instead of ECDHE.
		rsaCipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
			if c.flags&suiteECDHE != 0 {
				return false
			}
			if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
				return false
			}
			return true
		})
		if rsaCipherSuite == nil {
			return unsupported
		}
		return nil
	}

	// If the client sent the signature_algorithms extension, ensure it supports
	// schemes we can use with this certificate and TLS version.
	if len(chi.SignatureSchemes) > 0 {
		if _, err := selectSignatureScheme(vers, c, chi.SignatureSchemes); err != nil {
			return supportsRSAFallback(err)
		}
	}

	// In TLS 1.3 we are done because supported_groups is only relevant to the
	// ECDHE computation, point format negotiation is removed, cipher suites are
	// only relevant to the AEAD choice, and static RSA does not exist.
	//if vers == VersionTLS13 || vers == VersionGMSSL {
	//	// TODO 需要添加
	//	return nil
	//}

	// The only signed key exchange we support is ECDHE.
	if !supportsECDHE(config, chi.SupportedCurves, chi.SupportedPoints) {
		return supportsRSAFallback(errors.New("client doesn't support ECDHE, can only use legacy RSA key exchange"))
	}

	var ecdsaCipherSuite bool
	if priv, ok := c.PrivateKey.(crypto.Signer); ok {
		switch pub := priv.Public().(type) {
		// 添加sm2分支
		case *sm2.PublicKey:
			var curve CurveID
			switch pub.Curve {
			case sm2.P256Sm2():
				curve = Curve256Sm2
			default:
				return supportsRSAFallback(unsupportedCertificateError(c))
			}
			var curveOk bool
			for _, c := range chi.SupportedCurves {
				if c == curve && config.supportsCurve(c) {
					curveOk = true
					break
				}
			}
			if !curveOk {
				return errors.New("client doesn't support certificate curve")
			}
			ecdsaCipherSuite = true
		case *ecdsa.PublicKey:
			var curve CurveID
			switch pub.Curve {
			case elliptic.P256():
				curve = CurveP256
			case elliptic.P384():
				curve = CurveP384
			case elliptic.P521():
				curve = CurveP521
			default:
				return supportsRSAFallback(unsupportedCertificateError(c))
			}
			var curveOk bool
			for _, c := range chi.SupportedCurves {
				if c == curve && config.supportsCurve(c) {
					curveOk = true
					break
				}
			}
			if !curveOk {
				return errors.New("client doesn't support certificate curve")
			}
			if config.SignAlgPrefer != nil &&
				len(config.SignAlgPrefer) > 0 {
				var sigAlgOk bool
				for _, signatureAlgorithm := range config.SignAlgPrefer {
					if signatureAlgorithm == ECDSAWithP256AndSHA256 ||
						signatureAlgorithm == ECDSAWithP384AndSHA384 ||
						signatureAlgorithm == ECDSAWithP521AndSHA512 {
						sigAlgOk = true
						break
					}
				}
				if !sigAlgOk {
					return errors.New("client doesn't support certificate signatureAlgorithm")
				}
			}

			ecdsaCipherSuite = true
		case *ecdsa_ext.PublicKey:
			var curve CurveID
			switch pub.Curve {
			case elliptic.P256():
				curve = CurveP256
			case elliptic.P384():
				curve = CurveP384
			case elliptic.P521():
				curve = CurveP521
			default:
				return supportsRSAFallback(unsupportedCertificateError(c))
			}
			var curveOk bool
			for _, c := range chi.SupportedCurves {
				if c == curve && config.supportsCurve(c) {
					curveOk = true
					break
				}
			}
			if !curveOk {
				return errors.New("client doesn't support certificate curve")
			}
			if config.SignAlgPrefer != nil &&
				len(config.SignAlgPrefer) > 0 {
				var sigAlgOk bool
				for _, signatureAlgorithm := range config.SignAlgPrefer {
					if signatureAlgorithm == ECDSAEXTWithP256AndSHA256 ||
						signatureAlgorithm == ECDSAEXTWithP384AndSHA384 ||
						signatureAlgorithm == ECDSAEXTWithP521AndSHA512 {
						sigAlgOk = true
						break
					}
				}
				if !sigAlgOk {
					return errors.New("client doesn't support certificate signatureAlgorithm")
				}
			}
			ecdsaCipherSuite = true
		case ed25519.PublicKey:
			if vers < VersionTLS12 || len(chi.SignatureSchemes) == 0 {
				return errors.New("connection doesn't support Ed25519")
			}
			ecdsaCipherSuite = true
		case *rsa.PublicKey:
		default:
			return supportsRSAFallback(unsupportedCertificateError(c))
		}
	} else {
		return supportsRSAFallback(unsupportedCertificateError(c))
	}

	// Make sure that there is a mutually supported cipher suite that works with
	// this certificate. Cipher suite selection will then apply the logic in
	// reverse to pick it. See also serverHandshakeState.cipherSuiteOk.
	cipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
		if c.flags&suiteECDHE == 0 {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !ecdsaCipherSuite {
				return false
			}
		} else {
			if ecdsaCipherSuite {
				return false
			}
		}
		if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
			return false
		}
		return true
	})
	if cipherSuite == nil {
		return supportsRSAFallback(errors.New("client doesn't support any cipher suites compatible with the certificate"))
	}

	return nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the server that sent the CertificateRequest. Otherwise, it returns an error
// describing the reason for the incompatibility.
func (cri *CertificateRequestInfo) SupportsCertificate(c *Certificate) error {
	if _, err := selectSignatureScheme(cri.Version, c, cri.SignatureSchemes); err != nil {
		return err
	}

	if len(cri.AcceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		// Parse the certificate if this isn't the leaf node, or if
		// chain.Leaf was nil.
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}
	return errors.New("chain is not signed by an acceptable CA")
}

// BuildNameToCertificate parses c.Certificates and builds c.NameToCertificate
// from the CommonName and SubjectAlternateName fields of each of the leaf
// certificates.
//
// ToDeprecated: NameToCertificate only allows associating a single certificate
// with a given name. Leave that field nil to let the library select the first
// compatible chain from Certificates.
func (c *Config) BuildNameToCertificate() {
	c.NameToCertificate = make(map[string]*Certificate)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		x509Cert, err := cert.leaf()
		if err != nil {
			continue
		}
		// If SANs are *not* present, some clients will consider the certificate
		// valid for the name in the Common Name.
		if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
			c.NameToCertificate[x509Cert.Subject.CommonName] = cert
		}
		for _, san := range x509Cert.DNSNames {
			c.NameToCertificate[san] = cert
		}
	}
}

const (
	keyLogLabelTLS12           = "CLIENT_RANDOM"
	keyLogLabelClientHandshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic   = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic   = "SERVER_TRAFFIC_SECRET_0"
)

func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c.KeyLogWriter == nil {
		return nil
	}

	logLine := []byte(fmt.Sprintf("%s %x %x\n", label, clientRandom, secret))

	writerMutex.Lock()
	_, err := c.KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	return err
}

// writerMutex protects all KeyLogWriters globally. It is rarely enabled,
// and is only for debugging, so a global mutex saves space.
var writerMutex sync.Mutex

// Certificate 证书链, 子证书在前
// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	// 证书列表
	Certificate [][]byte
	// 子证书公钥对应的私钥
	// PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	PrivateKey crypto.PrivateKey
	// 子证书私钥支持的签名算法列表
	// SupportedSignatureAlgorithms is an optional list restricting what
	// signature algorithms the PrivateKey can be used for.
	SupportedSignatureAlgorithms []SignatureScheme
	// 供客户端请求的OCSP响应
	// OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	OCSPStaple []byte
	// 供客户端请求的证书签名时间列表
	// SignedCertificateTimestamps contains an optional list of Signed
	// Certificate Timestamps which will be served to clients that request it.
	SignedCertificateTimestamps [][]byte
	// 子证书
	// Leaf is the parsed form of the leaf certificate, which may be initialized
	// using x509.ParseCertificate to reduce per-handshake processing. If nil,
	// the leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

// leaf returns the parsed leaf certificate, either from c.Leaf or by parsing
// the corresponding c.Certificate[0].
func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

// 使用LRU(近期最少使用)算法实现的客户端会话缓存。
// lruSessionCache is a ClientSessionCache implementation that uses an LRU
// caching strategy.
type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *ClientSessionState
}

// NewLRUClientSessionCache returns a ClientSessionCache with the given
// capacity that uses an LRU strategy. If capacity is < 1, a default capacity
// is used instead.
func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

// Put 存储会话到缓存, 实现了 ClientSessionCache 接口
// Put adds the provided (sessionKey, cs) pair to the cache. If cs is nil, the entry
// corresponding to sessionKey is removed from the cache instead.
func (c *lruSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		if cs == nil {
			c.q.Remove(elem)
			delete(c.m, sessionKey)
		} else {
			entry := elem.Value.(*lruSessionCacheEntry)
			entry.state = cs
			c.q.MoveToFront(elem)
		}
		return
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	entry := elem.Value.(*lruSessionCacheEntry)
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

// Get 从缓存获取会话, 实现了 ClientSessionCache 接口
// Get returns the ClientSessionState value associated with a given key. It
// returns (nil, false) if no value is found.
func (c *lruSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		return elem.Value.(*lruSessionCacheEntry).state, true
	}
	return nil, false
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("gmtls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

// 判断是否支持目标签名算法
//  - sigAlg : 目标签名算法
//  - supportedSignatureAlgorithms : 支持的签名算法集合
func isSupportedSignatureAlgorithm(sigAlg SignatureScheme, supportedSignatureAlgorithms []SignatureScheme) bool {
	for _, s := range supportedSignatureAlgorithms {
		if s == sigAlg {
			return true
		}
	}
	return false
}
