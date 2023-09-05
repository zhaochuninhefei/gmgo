// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm4

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/utils"
	"runtime"
	"testing"

	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"golang.org/x/sys/cpu"
)

func TestSm4(t *testing.T) {
	//key := []byte("1234567890abcdef")
	key, err := utils.GetRandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("密钥转为hex: %s\n", hex.EncodeToString(key))
	data := []byte("天行健君子以自强不息")

	fmt.Println("---------------- testCBC ----------------")
	err = testCBC(key, data)
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

func TestAesGCM1(t *testing.T) {
	key, _ := hex.DecodeString("c64b7140c02e9cbe38626ea772794f57")
	iv, _ := hex.DecodeString("11b413b9f5757aa64a803152")
	ciphertext, _ := hex.DecodeString("863286881f10c94e642c7694ac605aa3427a14a84f6a681c056b21770f1b9abe241a2ecee0b8c369ffe16ad42b50ced2abd0bc90a161979b0f793371ebd53e97")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("plaintext: %s\n", plaintext)
}

func TestGcmAsmWithNonce(t *testing.T) {
	zclog.Level = zclog.LOG_LEVEL_DEBUG
	zclog.Debug("supportSM4:", supportSM4)
	zclog.Debug("supportsAES:", supportsAES)
	zclog.Debug("supportsGFMUL:", supportsGFMUL)
	zclog.Debug("useAVX2:", useAVX2)

	key := []byte{251, 160, 47, 88, 53, 110, 220, 7, 229, 174, 145, 250, 40, 34, 188, 237}
	nonce := []byte{182, 244, 44, 22, 113, 249, 246, 127, 114, 94, 115, 60}
	dst := []byte{23, 3, 3, 2, 191}
	data := []byte{11, 0, 2, 170, 0, 0, 2, 166, 0, 2, 161, 48, 130, 2, 157, 48, 130, 2, 67, 160, 3, 2, 1, 2, 2, 17, 0, 179, 19, 43, 244, 221, 102, 20, 101, 125, 96, 139, 186, 249, 198, 195, 128, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 48, 74, 49, 15, 48, 13, 6, 3, 85, 4, 10, 19, 6, 99, 97, 116, 101, 115, 116, 49, 20, 48, 18, 6, 3, 85, 4, 3, 19, 11, 99, 97, 46, 116, 101, 115, 116, 46, 99, 111, 109, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 78, 49, 20, 48, 18, 6, 3, 85, 4, 8, 19, 11, 65, 110, 104, 117, 105, 32, 72, 101, 102, 101, 105, 48, 30, 23, 13, 50, 50, 48, 52, 49, 50, 48, 56, 53, 50, 48, 51, 90, 23, 13, 51, 50, 48, 52, 48, 57, 48, 57, 53, 50, 48, 51, 90, 48, 83, 49, 20, 48, 18, 6, 3, 85, 4, 10, 12, 11, 115, 101, 114, 118, 101, 114, 95, 116, 101, 115, 116, 49, 24, 48, 22, 6, 3, 85, 4, 3, 19, 15, 115, 101, 114, 118, 101, 114, 46, 116, 101, 115, 116, 46, 99, 111, 109, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 67, 78, 49, 20, 48, 18, 6, 3, 85, 4, 8, 19, 11, 65, 110, 104, 117, 105, 32, 72, 101, 102, 101, 105, 48, 90, 48, 20, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66, 0, 4, 208, 246, 86, 87, 22, 133, 125, 168, 54, 91, 20, 197, 65, 195, 72, 121, 155, 195, 153, 47, 205, 174, 4, 237, 184, 164, 199, 171, 193, 125, 196, 244, 152, 160, 152, 212, 105, 20, 101, 74, 231, 154, 254, 71, 47, 116, 38, 82, 17, 16, 177, 44, 237, 56, 187, 48, 26, 125, 243, 220, 27, 128, 205, 173, 163, 129, 255, 48, 129, 252, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 6, 192, 48, 29, 6, 3, 85, 29, 37, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 41, 6, 3, 85, 29, 14, 4, 34, 4, 32, 211, 20, 37, 161, 114, 121, 43, 88, 162, 253, 161, 74, 105, 189, 203, 192, 67, 227, 69, 174, 129, 131, 172, 208, 91, 24, 210, 108, 207, 72, 20, 121, 48, 43, 6, 3, 85, 29, 35, 4, 36, 48, 34, 128, 32, 72, 47, 170, 202, 171, 110, 250, 70, 1, 121, 23, 136, 94, 115, 82, 88, 94, 97, 91, 98, 5, 106, 154, 74, 111, 55, 129, 6, 143, 58, 220, 191, 48, 115, 6, 3, 85, 29, 17, 4, 108, 48, 106, 130, 15, 115, 101, 114, 118, 101, 114, 46, 116, 101, 115, 116, 46, 99, 111, 109, 130, 16, 116, 101, 115, 116, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 129, 17, 103, 111, 112, 104, 101, 114, 64, 103, 111, 108, 97, 110, 103, 46, 111, 114, 103, 135, 4, 127, 0, 0, 1, 135, 16, 32, 1, 72, 96, 0, 0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 104, 134, 26, 104, 116, 116, 112, 115, 58, 47, 47, 102, 111, 111, 46, 99, 111, 109, 47, 119, 105, 98, 98, 108, 101, 35, 102, 111, 111, 48, 10, 6, 8, 42, 129, 28, 207, 85, 1, 131, 117, 3, 72, 0, 48, 69, 2, 32, 118, 163, 224, 17, 60, 183, 70, 62, 5, 158, 223, 251, 62, 186, 40, 120, 53, 145, 196, 225, 9, 235, 5, 251, 224, 133, 172, 205, 181, 237, 2, 51, 2, 33, 0, 215, 113, 160, 193, 183, 1, 187, 104, 101, 175, 88, 66, 195, 191, 53, 200, 235, 175, 0, 33, 224, 189, 75, 215, 130, 219, 162, 54, 11, 183, 170, 216, 0, 0, 22}
	err := testGCMWithNonce(key, data, nonce, dst)
	if err != nil {
		t.Fatal(err)
	}
}

func testGCMWithNonce(key, data, nonce, dst []byte) error {
	encryptData, err := Sm4EncryptGcmWithNonce(data, key, nonce, dst)
	if err != nil {
		return err
	}
	fmt.Printf("GCM encryptData : %v\n", encryptData)

	plainData, err := Sm4DecryptGcmWithNonce(encryptData, key, nonce, dst)
	if err != nil {
		return err
	}
	fmt.Printf("GCM plainData : %v\n", plainData)
	return nil
}

func testCBC(key, data []byte) error {
	iv, encryptData, err := Sm4EncryptCbc(data, key)
	if err != nil {
		return err
	}
	fmt.Printf("CBC iv 16进制 : %x\n", iv)
	fmt.Printf("CBC encryptData 16进制 : %x\n", encryptData)
	fmt.Printf("CBC encryptData 长度 : %d\n", len(encryptData))

	plainData, err := Sm4DecryptCbc(encryptData, key, iv)
	if err != nil {
		return err
	}
	fmt.Printf("CBC plainData : %s\n", plainData)

	encryptDataWithIV, err := Sm4EncryptCbcWithIV(data, key, iv)
	if err != nil {
		return err
	}
	fmt.Printf("CBC encryptDataWithIV 16进制 : %x\n", encryptDataWithIV)
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

func BenchmarkSm4(t *testing.B) {
	key := []byte("1234567890abcdef")
	data := []byte("天行健君子以自强不息")
	t.ReportAllocs()
	for i := 0; i < t.N; i++ {
		nonce, encryptData, _ := Sm4EncryptGcm(data, key)
		_, err := Sm4DecryptGcm(encryptData, key, nonce)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckArch(t *testing.T) {
	zclog.Level = zclog.LOG_LEVEL_DEBUG
	zclog.Debug("supportSM4:", supportSM4)
	zclog.Debug("supportsAES:", supportsAES)
	zclog.Debug("supportsGFMUL:", supportsGFMUL)
	zclog.Debug("useAVX2:", useAVX2)
	zclog.Debug("arch:", runtime.GOARCH)
	zclog.Debug("cpu.X86.HasAVX2:", cpu.X86.HasAVX2)
	zclog.Debug("cpu.X86.HasBMI2:", cpu.X86.HasBMI2)
}
