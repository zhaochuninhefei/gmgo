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

/*
gmtls/key_schedule.go TLS1.3密钥调度相关函数，已补充国密SM2曲线相关处理。
*/

import (
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

const (
	resumptionBinderLabel         = "res binder"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
	trafficUpdateLabel            = "traffic upd"
)

// expandLabel 标签扩展方法，实现 HKDF-Expand-Label。
//  - secret 基础密钥
//  - label 标签
//  - context 消息转录散列
//  - length 散列长度
// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(c.hash.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("gmtls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// deriveSecret 机密派生方法，实现 Derive-Secret。
//  - secret 基础密钥
//  - label 标签
//  - transcript 转录散列函数
// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		// transcript默认使用tls1.3密码套件的散列函数
		transcript = c.hash.New()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash.Size())
}

// extract 机密提炼方法，实现 HKDF-Extract。
// extract implements HKDF-Extract with the cipher suite hash.
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, c.hash.Size())
	}
	// 从输入密钥newSecret和可选的独立盐currentSecret生成一个伪随机密钥，用于Expand
	return hkdf.Extract(c.hash.New, newSecret, currentSecret)
}

// 根据当前的通信机密派生一个新的通信机密。
// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, trafficUpdateLabel, nil, c.hash.Size())
}

// 根据通信机密派生会话密钥与初始偏移量(对称加密用的key,iv)
// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// 生成Finished消息散列。
// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := c.expandLabel(baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret := c.deriveSecret(masterSecret, exporterLabel, transcript)
	return func(label string, context []byte, length int) ([]byte, error) {
		secret := c.deriveSecret(expMasterSecret, label, nil)
		h := c.hash.New()
		h.Write(context)
		return c.expandLabel(secret, "exporter", h.Sum(nil), length), nil
	}
}

// ECDHE接口
//  Elliptic Curve Diffie-Hellman Ephemeral,基于椭圆曲线的，动态的，笛福赫尔曼算法。
// ecdheParameters implements Diffie-Hellman with either NIST curves or X25519,
// according to RFC 8446, Section 4.2.8.2.
type ecdheParameters interface {
	// 曲线ID
	CurveID() CurveID
	// 获取公钥
	PublicKey() []byte
	// 计算共享密钥 : 己方私钥 * 对方公钥peerPublicKey
	SharedKey(peerPublicKey []byte) []byte
}

// 基于给定的椭圆曲线ID，获取椭圆曲线并生成ecdhe参数，已支持SM2-P-256曲线。
//  ecdhe : Elliptic Curve Diffie-Hellman Ephemeral, 临时的基于椭圆曲线的笛福赫尔曼密钥交换算法。
//  ecdheParameters是一个接口，实际对象需要实现该接口的SharedKey等方法,其内部包含曲线ID与对应的公私钥。
func generateECDHEParameters(rand io.Reader, curveID CurveID) (ecdheParameters, error) {
	if curveID == X25519 {
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		return &x25519Parameters{privateKey: privateKey, publicKey: publicKey}, nil
	}
	// 椭圆曲线获取，已支持p256sm2
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("gmtls: internal error: unsupported curve")
	}
	// 生成密钥交换算法参数
	p := &nistParameters{curveID: curveID}
	var err error
	// 利用曲线生成公私钥
	p.privateKey, p.x, p.y, err = elliptic.GenerateKey(curve, rand)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// 根据曲线ID获取对应曲线
func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
	switch id {
	// 添加国密SM2曲线
	case Curve256Sm2:
		return sm2.P256Sm2(), true
	case CurveP256:
		return elliptic.P256(), true
	case CurveP384:
		return elliptic.P384(), true
	case CurveP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

func CheckCurveNameById(id CurveID) (string, bool) {
	switch id {
	case Curve256Sm2:
		return sm2.P256Sm2().Params().Name, true
	case CurveP256:
		return elliptic.P256().Params().Name, true
	case CurveP384:
		return elliptic.P384().Params().Name, true
	case CurveP521:
		return elliptic.P521().Params().Name, true
	case X25519:
		return "Curve25519", true
	default:
		return fmt.Sprintf("unknown CurveID: %d", id), false
	}
}

func CurveNameById(id CurveID) string {
	switch id {
	// 添加国密SM2曲线
	case Curve256Sm2:
		return sm2.P256Sm2().Params().Name
	case CurveP256:
		return elliptic.P256().Params().Name
	case CurveP384:
		return elliptic.P384().Params().Name
	case CurveP521:
		return elliptic.P521().Params().Name
	case X25519:
		return "Curve25519"
	default:
		return fmt.Sprintf("unknown CurveID: %d", id)
	}
}

type nistParameters struct {
	privateKey []byte
	x, y       *big.Int // public key
	curveID    CurveID
}

func (p *nistParameters) CurveID() CurveID {
	return p.curveID
}

func (p *nistParameters) PublicKey() []byte {
	curve, _ := curveForCurveID(p.curveID)
	return elliptic.Marshal(curve, p.x, p.y)
}

func (p *nistParameters) SharedKey(peerPublicKey []byte) []byte {
	curve, _ := curveForCurveID(p.curveID)
	// 将 peerPublicKey 的座标位置解析出来，同时验证该座标是否在曲线上。
	// Unmarshal also checks whether the given point is on the curve.
	x, y := elliptic.Unmarshal(curve, peerPublicKey)
	if x == nil {
		return nil
	}
	// peerPublicKey * 私钥 获取共享密钥
	xShared, _ := curve.ScalarMult(x, y, p.privateKey)
	sharedKey := make([]byte, (curve.Params().BitSize+7)/8)
	zclog.Debugf("===== 使用曲线 %s 与对方公钥计算共享密钥", curve.Params().Name)
	return xShared.FillBytes(sharedKey)
}

type x25519Parameters struct {
	privateKey []byte
	publicKey  []byte
}

func (p *x25519Parameters) CurveID() CurveID {
	return X25519
}

func (p *x25519Parameters) PublicKey() []byte {
	return p.publicKey[:]
}

func (p *x25519Parameters) SharedKey(peerPublicKey []byte) []byte {
	sharedKey, err := curve25519.X25519(p.privateKey, peerPublicKey)
	if err != nil {
		return nil
	}
	return sharedKey
}
