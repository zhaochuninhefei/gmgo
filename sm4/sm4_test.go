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

func TestCBC(t *testing.T) {
	key := []byte("1234567890abcdef")
	data := []byte("天行健君子以自强不息")

	iv, encryptData, err := Sm4EncryptCbc(data, key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("iv 16进制 : %x\n", iv)
	fmt.Printf("encryptData 16进制 : %x\n", encryptData)

	plainData, err := Sm4DecryptCbc(encryptData, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("plainData : %s\n", plainData)
}

func TestGCM(t *testing.T) {
	key := []byte("1234567890abcdef")
	data := []byte("天行健君子以自强不息")

	nonce, encryptData, err := Sm4EncryptGcm(data, key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("nonce 16进制 : %x\n", nonce)
	fmt.Printf("encryptData 16进制 : %x\n", encryptData)

	plainData, err := Sm4DecryptGcm(encryptData, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("plainData : %s\n", plainData)
}
