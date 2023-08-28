package x509

// sct.go 此处仅为`certinfo.go`的`CertificateText`函数提供对其他包含SCT扩展信息的x509证书解析对应的SCT情报，
//  并不是为`x509`包提供完整的SCT扩展信息功能。

// 扩展信息 Signed Certificate Timestamps 证书签名时间戳 : 1.3.6.1.4.1.11129.2.4.2
var oidExtensionSCT = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
