x509 待开发
=====

# x509扩展信息:SCT
x509证书中的扩展信息 `1.3.6.1.4.1.11129.2.4.2`是用来存储证书透明度（Certificate Transparency，CT）的签名证书时间戳（Signed Certificate Timestamp，SCT）的列表。证书透明度是一种机制，用于检测和防止错误或恶意的证书颁发。签名证书时间戳是一种证明，表明一个证书已经被提交到一个公开的、可审计的CT日志服务器。这样，浏览器可以验证一个证书是否在CT日志中存在，从而增加了证书的可信度。

x509证书中的扩展信息 `1.3.6.1.4.1.11129.2.4.2`的格式是由RFC 6962第3.3节定义的。它是一个ASN.1结构，包含一个或多个SCT结构。每个SCT结构包含以下字段¹：
- 版本：一个字节，表示SCT的版本号。
- 日志ID：一个32字节的哈希值，表示CT日志服务器的公钥。
- 时间戳：一个64位的整数，表示SCT的生成时间。
- 扩展：一个可选的字段，表示SCT的额外信息。
- 签名：一个ECDSA或RSA签名，表示CT日志服务器对SCT的认可。

> RFC 6962第3.3节: `https://datatracker.ietf.org/doc/html/rfc6962#page-13`

解码代码示例:
```
// 扩展信息 Signed Certificate Timestamps 证书签名时间戳 : 1.3.6.1.4.1.11129.2.4.2
oidExtensionSCT = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// SerializedSCT is a struct type for storing the SCT list in the extension info
type SerializedSCT struct {
    SCTs []SCT // SCT slice
}

// SCT is a struct type for storing a single SCT
type SCT struct {
    Version byte // one byte
    LogID [32]byte // 32-byte array
    Timestamp uint64 // 64-bit unsigned integer
    Extensions []byte // byte slice
    Signature []byte // byte slice
}

// certData is a byte slice containing the x509 certificate data
certData := ...

// parse the certificate
cert, err := x509.ParseCertificate(certData)
if err != nil {
    // handle error
}

// find the extension with OID 1.3.6.1.4.1.11129.2.4.2
var extData []byte
for _, ext := range cert.Extensions {
    if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) {
        extData = ext.Value
        break
    }
}

// unmarshal the extension data into a struct variable
var extInfo ExtensionInfo
rest, err := asn1.Unmarshal(extData, &extInfo)
if err != nil {
    // handle error
}

// now extInfo contains the decoded SCT list

```