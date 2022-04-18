// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/*
sm4soft 是sm4的纯软实现，基于tjfoc国密算法库`tjfoc/gmsm`做了少量修改。
对应版权声明: thrid_licenses/github.com/tjfoc/gmsm/版权声明
*/

package sm4soft

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSM4(t *testing.T) {
	// 定义密钥，16字节
	key := []byte("abcdef1234567890")
	fmt.Printf("key字节数组 : %v\n", key)
	fmt.Printf("key字符串 : %s\n", key)

	// 将key写入key.pem
	err := WriteKeyToPemFile("testdata/key.pem", key, nil)
	if err != nil {
		t.Fatalf("WriteKeyToPem error")
	}
	// 读取key.pem
	key, err = ReadKeyFromPemFile("testdata/key.pem", nil)
	fmt.Printf("读取到的key字节数组 : %v\n", key)
	fmt.Printf("读取到的key字符串 : %s\n", key)
	if err != nil {
		t.Fatal(err)
	}

	// 定义数据
	// data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	data := []byte("天行健君子以自强不息")
	fmt.Printf("data字节数组 : %v\n", data)
	fmt.Printf("data十六进制 : %x\n", data)
	fmt.Printf("data字符串 : %s\n", data)

	// ECB模式加密
	ecbMsg, err := Sm4Ecb(key, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
		return
	}
	fmt.Printf("ecbMsg 16进制 : %x\n", ecbMsg)
	// ECB模式解密
	ecbDec, err := Sm4Ecb(key, ecbMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("ecbDec : %s\n", ecbDec)
	if !testCompare(data, ecbDec) {
		t.Errorf("sm4 self enc and dec failed")
	}

	// 定义初始化向量，16字节
	// iv := []byte("0000000000000000")
	iv := []byte("1234def567890abc")
	// err = SetIVDefault(iv)
	fmt.Printf("err = %v\n", err)
	fmt.Printf("iv字节数组 : %v\n", iv)
	fmt.Printf("iv16进制 : %x\n", iv)
	fmt.Printf("iv字符串 : %s\n", iv)

	// CBC模式加密
	cbcMsg, err := Sm4Cbc(key, iv, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cbcMsg 16进制 : %x\n", cbcMsg)
	// CBC模式解密
	cbcDec, err := Sm4Cbc(key, iv, cbcMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcDec : %s\n", cbcDec)
	if !testCompare(data, cbcDec) {
		t.Errorf("sm4 self enc and dec failed")
	}

	// CFB模式加密
	cfbMsg, err := Sm4CFB(key, iv, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cfbMsg 16进制 : %x\n", cfbMsg)
	// CFB模式解密
	cfbDec, err := Sm4CFB(key, iv, cfbMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cfbDec : %s\n", cfbDec)

	// OFB模式加密
	ofbMsg, err := Sm4OFB(key, iv, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("ofbMsg 16进制 : %x\n", ofbMsg)
	// OFB模式解密
	ofbDec, err := Sm4OFB(key, iv, ofbMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("ofbDec : %s\n", ofbDec)
}

func TestNewCipher(t *testing.T) {
	key := []byte("1234567890abcdef")
	// 直接用NewCipher只能对16字节的数据加密
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	// data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	d0 := make([]byte, 16)
	c.Encrypt(d0, data)
	d1 := make([]byte, 16)
	c.Decrypt(d1, d0)
}

func BenchmarkSM4(t *testing.B) {
	t.ReportAllocs()
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	err := WriteKeyToPemFile("key.pem", key, nil)
	if err != nil {
		t.Fatalf("WriteKeyToPem error")
	}
	key, err = ReadKeyFromPemFile("key.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < t.N; i++ {
		d0 := make([]byte, 16)
		c.Encrypt(d0, data)
		d1 := make([]byte, 16)
		c.Decrypt(d1, d0)
	}
}

func TestErrKeyLen(t *testing.T) {
	fmt.Printf("\n--------------test key len------------------")
	key := []byte("1234567890abcdefg")
	_, err := NewCipher(key)
	if err != nil {
		fmt.Println("\nError key len !")
	}
	key = []byte("1234")
	_, err = NewCipher(key)
	if err != nil {
		fmt.Println("Error key len !")
	}
	fmt.Println("------------------end----------------------")
}

func testCompare(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i, v := range key1 {
		if i == 1 {
			fmt.Println("type of v", reflect.TypeOf(v))
		}
		a := key2[i]
		if a != v {
			return false
		}
	}
	return true
}
