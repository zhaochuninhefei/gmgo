package x509

import (
	"encoding/asn1"
	"fmt"
)

// sct.go 此处仅为`certinfo.go`的`CertificateText`函数提供对其他包含SCT扩展信息的x509证书解析对应的SCT情报，
//  并不是为`x509`包提供完整的SCT扩展信息功能。
//
// x509证书中的扩展信息 `1.3.6.1.4.1.11129.2.4.2`是用来存储证书透明度（Certificate Transparency，CT）的签名证书时间戳（Signed Certificate Timestamp，SCT）的列表。
// 证书透明度是一种机制，用于检测和防止错误或恶意的证书颁发。
// 签名证书时间戳是一种证明，表明一个证书已经被提交到一个公开的、可审计的CT日志服务器。
// 这样，浏览器可以验证一个证书是否在CT日志中存在，从而增加了证书的可信度。
//
// SCT的使用场景主要是在TLS协议中，它可以让客户端检查服务器证书是否被记录在公开的CT日志中。
// golang的`x509`包的主要目标是提供与公共信任的TLS证书生态系统和其策略和约束的兼容性，而不是支持所有可能的X509扩展。
//
// x509证书中的扩展信息 `1.3.6.1.4.1.11129.2.4.2`的格式是由RFC 6962第3.3节定义的。它是一个ASN.1结构，包含一个或多个SCT结构。每个SCT结构包含以下字段¹：
//  - 版本：一个字节，表示SCT的版本号。
//  - 日志ID：一个32字节的哈希值，表示CT日志服务器的公钥。
//  - 时间戳：一个64位的整数，表示SCT的生成时间。
//  - 扩展：一个可选的字段，表示SCT的额外信息。
//  - 签名：一个ECDSA或RSA签名，表示CT日志服务器对SCT的认可。
//
// RFC 6962第3.3节: `https://datatracker.ietf.org/doc/html/rfc6962#page-13`

// 扩展信息 Signed Certificate Timestamps 证书签名时间戳 : 1.3.6.1.4.1.11129.2.4.2
var oidExtensionSCT = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// SerializedSCT is a struct type for storing the SCT list in the extension info
type SerializedSCT struct {
	SCTs []SCT `asn1:"tag:4"` // SCT slice
}

// SCT is a struct type for storing a single SCT
type SCT struct {
	Version    int
	LogID      []byte
	Timestamp  int64
	Extensions []byte
	Signature  asn1.BitString
}

// String returns a string representation of the SCT.
func (s SCT) String() string {
	return fmt.Sprintf("Version: %d\nLogID: %x\nTimestamp: %d\nExtensions: %x\nSignature: %x\n",
		s.Version,
		s.LogID,
		s.Timestamp,
		s.Extensions,
		s.Signature)
}
