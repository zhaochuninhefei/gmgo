x509 待开发
=====

# x509扩展信息:SCT
解码代码示例:
```
// 扩展信息 Signed Certificate Timestamps 证书签名时间戳 : 1.3.6.1.4.1.11129.2.4.2
oidExtensionSCT = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// ExtensionInfo is a struct type for storing the SCT list in the extension info
type ExtensionInfo struct {
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