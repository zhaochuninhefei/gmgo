// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm4

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/utils"
	"io"
)

// Sm4EncryptCbc sm4加密，CBC模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4EncryptCbc(plainData, key []byte) (iv, encryptData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	paddedData := utils.PKCS7Padding(plainData, BlockSize)
	encryptData = make([]byte, len(paddedData))
	iv = make([]byte, BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptData, paddedData)
	return
}

// Sm4EncryptCbcWithIV sm4加密，CBC模式，指定IV
//goland:noinspection GoNameStartsWithPackageName
func Sm4EncryptCbcWithIV(plainData, key, iv []byte) (encryptData []byte, err error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("sm4.Sm4EncryptCbcWithIV: iv长度不正确,不是Block字节数的长度. Block字节数: [%d]", BlockSize)
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	paddedData := utils.PKCS7Padding(plainData, BlockSize)
	encryptData = make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptData, paddedData)
	return
}

// Sm4DecryptCbc sm4解密，CBC模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4DecryptCbc(encryptData, key, iv []byte) (plainData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 长度检查
	length := len(encryptData)
	if length < BlockSize || length%BlockSize != 0 {
		return nil, fmt.Errorf("sm4.Sm4DecryptCbc: 密文长度不正确,不是Block字节数的整数倍. Block字节数: [%d]", BlockSize)
	}
	paddedData := make([]byte, len(encryptData))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(paddedData, encryptData)
	plainData, err = utils.PKCS7UnPadding(paddedData, BlockSize)
	if err != nil {
		return nil, err
	}
	return
}

// Sm4EncryptCfb sm4加密，CFB模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4EncryptCfb(plainData, key []byte) (iv, encryptData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	encryptData = make([]byte, len(plainData))
	iv = make([]byte, BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(encryptData, plainData)
	return
}

// Sm4DecryptCfb sm4解密，CFB模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4DecryptCfb(encryptData, key, iv []byte) (plainData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainData = make([]byte, len(encryptData))
	mode := cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(plainData, encryptData)
	return
}

// Sm4EncryptOfb sm4加密，OFB模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4EncryptOfb(plainData, key []byte) (iv, encryptData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	encryptData = make([]byte, len(plainData))
	iv = make([]byte, BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewOFB(block, iv)
	mode.XORKeyStream(encryptData, plainData)
	return
}

// Sm4DecryptOfb sm4解密，OFB模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4DecryptOfb(encryptData, key, iv []byte) (plainData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainData = make([]byte, len(encryptData))
	mode := cipher.NewOFB(block, iv)
	mode.XORKeyStream(plainData, encryptData)
	return
}

// Sm4EncryptGcm sm4加密，GCM模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4EncryptGcm(plainData, key []byte) (nonce, encryptData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, sm4gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, nil, err
	}
	encryptData = sm4gcm.Seal(nil, nonce, plainData, nil)
	return
}

// Sm4DecryptGcm sm4解密，GCM模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4DecryptGcm(encryptData, key, nonce []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// nonce, ciphertext := data[:sm4gcm.NonceSize()], data[sm4gcm.NonceSize():]
	out, err := sm4gcm.Open(nil, nonce, encryptData, nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Sm4EncryptGcmWithNonce sm4加密，GCM模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4EncryptGcmWithNonce(plainData, key, nonce, dst []byte) (encryptData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := sm4gcm.Seal(dst, nonce, plainData, dst)
	encryptData = out[len(dst):]
	return
}

// Sm4DecryptGcmWithNonce sm4解密，GCM模式
//goland:noinspection GoNameStartsWithPackageName
func Sm4DecryptGcmWithNonce(encryptData, key, nonce, dst []byte) ([]byte, error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out, err := sm4gcm.Open(encryptData[:0], nonce, encryptData, dst)
	if err != nil {
		return nil, err
	}
	return out, nil
}
