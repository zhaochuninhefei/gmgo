// Copyright (c) 2022 zhaochun
// gmingo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm4

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// 根据pkcs7标准填充明文
func PKCS7Padding(src []byte) []byte {
	padding := BlockSize - len(src)%BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// 根据pkcs7标准去除填充
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("invalid pkcs7 padding (len(padtext) == 0)")
	}
	unpadding := int(src[length-1])
	if unpadding > BlockSize || unpadding == 0 {
		return nil, errors.New("invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func Sm4EncryptCbc(plainData, key []byte) (iv, encryptData []byte, err error) {
	block, err := NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	paddedData := PKCS7Padding(plainData)
	encryptData = make([]byte, len(paddedData))
	iv = make([]byte, BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptData, paddedData)
	return
}

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
	plainData, err = PKCS7UnPadding(paddedData)
	if err != nil {
		return nil, err
	}
	return
}

func Sm4EncryptGcm(plainData, key []byte) (nonce, encryptData []byte, err error) {
	block, err := NewCipher([]byte(key))
	if err != nil {
		return nil, nil, err
	}
	sm4gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, sm4gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	out := sm4gcm.Seal(nonce, nonce, plainData, nil)
	encryptData = out[sm4gcm.NonceSize():]
	// nonce = out[:sm4gcm.NonceSize()]
	return
}

func Sm4DecryptGcm(encryptData, key, nonce []byte) ([]byte, error) {
	block, err := NewCipher([]byte(key))
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
