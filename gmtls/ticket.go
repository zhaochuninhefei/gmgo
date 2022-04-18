// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gmtls

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"io"

	"gitee.com/zhaochuninhefei/gmgo/sm3"
	"gitee.com/zhaochuninhefei/gmgo/sm4"
	"golang.org/x/crypto/cryptobyte"
)

// sessionState contains the information that is serialized into a session
// ticket in order to later resume a connection.
type sessionState struct {
	vers         uint16
	cipherSuite  uint16
	createdAt    uint64
	masterSecret []byte // opaque master_secret<1..2^16-1>;
	// struct { opaque certificate<1..2^24-1> } Certificate;
	certificates [][]byte // Certificate certificate_list<0..2^24-1>;

	// usedOldKey is true if the ticket from which this session came from
	// was encrypted with an older key and thus should be refreshed.
	usedOldKey bool
}

func (m *sessionState) marshal() []byte {
	var b cryptobyte.Builder
	b.AddUint16(m.vers)
	b.AddUint16(m.cipherSuite)
	addUint64(&b, m.createdAt)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.masterSecret)
	})
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, cert := range m.certificates {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(cert)
			})
		}
	})
	return b.BytesOrPanic()
}

func (m *sessionState) unmarshal(data []byte) bool {
	*m = sessionState{usedOldKey: m.usedOldKey}
	s := cryptobyte.String(data)
	if ok := s.ReadUint16(&m.vers) &&
		s.ReadUint16(&m.cipherSuite) &&
		readUint64(&s, &m.createdAt) &&
		readUint16LengthPrefixed(&s, &m.masterSecret) &&
		len(m.masterSecret) != 0; !ok {
		return false
	}
	var certList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certList) {
		return false
	}
	for !certList.Empty() {
		var cert []byte
		if !readUint24LengthPrefixed(&certList, &cert) {
			return false
		}
		m.certificates = append(m.certificates, cert)
	}
	return s.Empty()
}

// sessionStateTLS13 is the content of a TLS 1.3 session ticket. Its first
// version (revision = 0) doesn't carry any of the information needed for 0-RTT
// validation and the nonce is always empty.
type sessionStateTLS13 struct {
	// uint8 version  = 0x0304;
	// uint8 revision = 0;
	cipherSuite      uint16
	createdAt        uint64
	resumptionSecret []byte      // opaque resumption_master_secret<1..2^8-1>;
	certificate      Certificate // CertificateEntry certificate_list<0..2^24-1>;
}

func (m *sessionStateTLS13) marshal() []byte {
	var b cryptobyte.Builder
	b.AddUint16(VersionTLS13)
	b.AddUint8(0) // revision
	b.AddUint16(m.cipherSuite)
	addUint64(&b, m.createdAt)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.resumptionSecret)
	})
	marshalCertificate(&b, m.certificate)
	return b.BytesOrPanic()
}

func (m *sessionStateTLS13) unmarshal(data []byte) bool {
	*m = sessionStateTLS13{}
	s := cryptobyte.String(data)
	var version uint16
	var revision uint8
	return s.ReadUint16(&version) &&
		version == VersionTLS13 &&
		s.ReadUint8(&revision) &&
		revision == 0 &&
		s.ReadUint16(&m.cipherSuite) &&
		readUint64(&s, &m.createdAt) &&
		readUint8LengthPrefixed(&s, &m.resumptionSecret) &&
		len(m.resumptionSecret) != 0 &&
		unmarshalCertificate(&s, &m.certificate) &&
		s.Empty()
}

// 会话票据加密
//  golang原来的实现是用aes加密，sha256散列，国密改造改为 sm4 + sm3
func (c *Conn) encryptTicket(state []byte) ([]byte, error) {
	if len(c.ticketKeys) == 0 {
		return nil, errors.New("gmtls: internal error: session ticket keys unavailable")
	}
	// encrypted : ticketKeyName(16) + iv(16) + state对称加密结果 + 散列(32)
	// encrypted := make([]byte, ticketKeyNameLen+aes.BlockSize+len(state)+sha256.Size)
	encrypted := make([]byte, ticketKeyNameLen+sm4.BlockSize+len(state)+sm3.Size)
	// 前16个字节放ticketKeyName
	keyName := encrypted[:ticketKeyNameLen]
	// 16~32 放iv
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+sm4.BlockSize]
	// 最后32个字节放mac认证码
	macBytes := encrypted[len(encrypted)-sm3.Size:]
	// 生成随机字节数组填入iv
	if _, err := io.ReadFull(c.config.rand(), iv); err != nil {
		return nil, err
	}
	// 当前连接的ticketKeys在前面读取ClientHello之后的处理中已经初始化。
	// 这里拿到第一个ticketKey。
	key := c.ticketKeys[0]
	// 填入keyname
	copy(keyName, key.keyName[:])
	block, err := sm4.NewCipher(key.sm4Key[:])
	if err != nil {
		return nil, errors.New("gmtls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	// encrypted的 32 ~ 倒数32 填入state对称加密结果
	cipher.NewCTR(block, iv).XORKeyStream(encrypted[ticketKeyNameLen+sm4.BlockSize:], state)
	// 使用sm3作为mac认证码函数
	mac := hmac.New(sm3.New, key.hmacKey[:])
	// 写入 encrypted 前三部分内容: ticketKeyName(16) + iv(16) + state对称加密结果
	mac.Write(encrypted[:len(encrypted)-sm3.Size])
	// 生成认证码填入macBytes
	mac.Sum(macBytes[:0])

	return encrypted, nil
}

// 会话票据解密
//  golang原来的实现是用aes加密，sha256散列，国密改造改为 sm4 + sm3
func (c *Conn) decryptTicket(encrypted []byte) (plaintext []byte, usedOldKey bool) {
	if len(encrypted) < ticketKeyNameLen+sm4.BlockSize+sm3.Size {
		return nil, false
	}
	// 获取keyname
	keyName := encrypted[:ticketKeyNameLen]
	// 获取iv
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+sm4.BlockSize]
	// 获取认证码
	macBytes := encrypted[len(encrypted)-sm3.Size:]
	// 获取秘文
	ciphertext := encrypted[ticketKeyNameLen+sm4.BlockSize : len(encrypted)-sm3.Size]
	// 根据keyname获取key
	keyIndex := -1
	for i, candidateKey := range c.ticketKeys {
		if bytes.Equal(keyName, candidateKey.keyName[:]) {
			keyIndex = i
			break
		}
	}
	if keyIndex == -1 {
		return nil, false
	}
	key := &c.ticketKeys[keyIndex]
	// 重新生成认证码
	mac := hmac.New(sm3.New, key.hmacKey[:])
	mac.Write(encrypted[:len(encrypted)-sm3.Size])
	expected := mac.Sum(nil)
	// 比较认证码
	if subtle.ConstantTimeCompare(macBytes, expected) != 1 {
		return nil, false
	}
	// 对称解密
	block, err := sm4.NewCipher(key.sm4Key[:])
	if err != nil {
		return nil, false
	}
	plaintext = make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)

	return plaintext, keyIndex > 0
}
