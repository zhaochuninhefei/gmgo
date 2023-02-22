package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
)

// ZeroByteSlice 0组成的32byte切片
func ZeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

// PKCS7Padding 根据pkcs7标准填充明文
func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS7UnPadding 根据pkcs7标准去除填充
func PKCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("invalid pkcs7 padding (len(padtext) == 0)")
	}
	unpadding := int(src[length-1])
	if unpadding > blockSize || unpadding == 0 {
		return nil, fmt.Errorf("invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0). unpadding: %d, BlockSize: %d", unpadding, blockSize)
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("len must be larger than 0")
	}
	buffer := make([]byte, len)
	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("buffer not filled. Requested [%d], got [%d]", len, n)
	}
	return buffer, nil
}

// GetRandBigInt 随机生成序列号
//
//  @return *big.Int
func GetRandBigInt() *big.Int {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return sn
}

// ReadPemFromFile 从文件读取pem字节数组
//  @param filePath 文件路径
//  @return pemBytes pem字节数组
//  @return err
//goland:noinspection GoUnusedExportedFunction
func ReadPemFromFile(filePath string) (pemBytes []byte, err error) {
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read file [%s], error: %s", filePath, err)
	}
	b, _ := pem.Decode(fileBytes)
	if b == nil {
		return nil, fmt.Errorf("no pem content for file [%s]", filePath)
	}
	return fileBytes, nil
}

// ECSignature 椭圆曲线签名
type ECSignature struct {
	R, S *big.Int
}

// MarshalECSignature 序列化椭圆曲线签名
func MarshalECSignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECSignature{r, s})
}

// UnmarshalECSignature 反序列化椭圆曲线签名
func UnmarshalECSignature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(ECSignature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature, R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, S must be larger than zero")
	}

	return sig.R, sig.S, nil
}
