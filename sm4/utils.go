package sm4

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/ioutil"

	gmx509 "gitee.com/zhaochuninhefei/gmgo/x509"
)

// ReadKeyFromPem will return SM4Key from PEM format data.
func ReadKeyFromPem(data []byte, pwd []byte) (SM4Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("SM4: pem decode failed")
	}
	if gmx509.IsEncryptedPEMBlock(block) {
		if block.Type != "SM4 ENCRYPTED KEY" {
			return nil, errors.New("SM4: unknown type")
		}
		if len(pwd) == 0 {
			return nil, errors.New("SM4: need passwd")
		}
		data, err := gmx509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if block.Type != "SM4 KEY" {
		return nil, errors.New("SM4: unknown type")
	}
	return block.Bytes, nil
}

// ReadKeyFromPemFile will return SM4Key from filename that saved PEM format data.
func ReadKeyFromPemFile(FileName string, pwd []byte) (SM4Key, error) {
	data, err := ioutil.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	return ReadKeyFromPem(data, pwd)
}

// WriteKeyToPem will convert SM4Key to PEM format data and return it.
func WriteKeyToPem(key SM4Key, pwd []byte) ([]byte, error) {
	if pwd != nil {
		block, err := gmx509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, gmx509.PEMCipherAES256) //Use AES256  algorithms to encrypt SM4KEY
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	} else {
		block := &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
		return pem.EncodeToMemory(block), nil
	}
}

// WriteKeyToPemFile will convert SM4Key to PEM format data, then write it
// into the input filename.
func WriteKeyToPemFile(FileName string, key SM4Key, pwd []byte) error {
	var block *pem.Block
	var err error
	if pwd != nil {
		block, err = gmx509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, gmx509.PEMCipherAES256)
		if err != nil {
			return err
		}
	} else {
		block = &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
	}
	pemBytes := pem.EncodeToMemory(block)
	err = ioutil.WriteFile(FileName, pemBytes, 0666)
	if err != nil {
		return err
	}
	return nil
}

// sm4密钥转为pem字节流
func WriteKeytoMem(key SM4Key, pwd []byte) ([]byte, error) {
	if pwd != nil {
		block, err := gmx509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, gmx509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	} else {
		block := &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
		return pem.EncodeToMemory(block), nil
	}
}

// 将pem字节流转为sm4密钥
func ReadKeyFromMem(data []byte, pwd []byte) (SM4Key, error) {
	block, _ := pem.Decode(data)
	if gmx509.IsEncryptedPEMBlock(block) {
		if block.Type != "SM4 ENCRYPTED KEY" {
			return nil, errors.New("SM4: unknown type")
		}
		if len(pwd) == 0 {
			return nil, errors.New("SM4: need passwd")
		}
		data, err := gmx509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if block.Type != "SM4 KEY" {
		return nil, errors.New("SM4: unknown type")
	}
	return block.Bytes, nil
}
