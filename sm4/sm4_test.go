// Copyright (c) 2022 zhaochun
// gmingo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm4

import (
	"fmt"
	"testing"
)

func TestSm4(t *testing.T) {
	key := []byte("1234567890abcdef")
	data := []byte("天行健君子以自强不息")

	fmt.Println("---------------- testCBC ----------------")
	err := testCBC(key, data)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("---------------- testCFB ----------------")
	err = testCFB(key, data)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("---------------- testOFB ----------------")
	err = testOFB(key, data)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("---------------- testGCM ----------------")
	err = testGCM(key, data)
	if err != nil {
		t.Fatal(err)
	}
}

func testCBC(key, data []byte) error {
	iv, encryptData, err := Sm4EncryptCbc(data, key)
	if err != nil {
		return err
	}
	fmt.Printf("CBC iv 16进制 : %x\n", iv)
	fmt.Printf("CBC encryptData 16进制 : %x\n", encryptData)

	plainData, err := Sm4DecryptCbc(encryptData, key, iv)
	if err != nil {
		return err
	}
	fmt.Printf("CBC plainData : %s\n", plainData)
	return nil
}

func testCFB(key, data []byte) error {
	iv, encryptData, err := Sm4EncryptCfb(data, key)
	if err != nil {
		return err
	}
	fmt.Printf("CFB iv 16进制 : %x\n", iv)
	fmt.Printf("CFB encryptData 16进制 : %x\n", encryptData)

	plainData, err := Sm4DecryptCfb(encryptData, key, iv)
	if err != nil {
		return err
	}
	fmt.Printf("CFB plainData : %s\n", plainData)
	return nil
}

func testOFB(key, data []byte) error {
	iv, encryptData, err := Sm4EncryptOfb(data, key)
	if err != nil {
		return err
	}
	fmt.Printf("OFB iv 16进制 : %x\n", iv)
	fmt.Printf("OFB encryptData 16进制 : %x\n", encryptData)

	plainData, err := Sm4DecryptOfb(encryptData, key, iv)
	if err != nil {
		return err
	}
	fmt.Printf("OFB plainData : %s\n", plainData)
	return nil
}

func testGCM(key, data []byte) error {
	nonce, encryptData, err := Sm4EncryptGcm(data, key)
	if err != nil {
		return err
	}
	fmt.Printf("GCM nonce 16进制 : %x\n", nonce)
	fmt.Printf("GCM encryptData 16进制 : %x\n", encryptData)

	plainData, err := Sm4DecryptGcm(encryptData, key, nonce)
	if err != nil {
		return err
	}
	fmt.Printf("GCM plainData : %s\n", plainData)
	return nil
}
