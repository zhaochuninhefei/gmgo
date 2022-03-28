/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm3

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/sha3"
)

func byteToString(b []byte) string {
	ret := ""
	for i := 0; i < len(b); i++ {
		ret += fmt.Sprintf("%02x", b[i])
	}
	// fmt.Println("ret = ", ret)
	return ret
}
func TestSm3(t *testing.T) {
	msg := []byte("天行健君子以自强不息")
	// 生成msg文件
	err := ioutil.WriteFile("testdata/msg", msg, os.FileMode(0644))
	if err != nil {
		t.Fatal(err)
	}
	// 读取msg文件
	msg, err = ioutil.ReadFile("testdata/msg")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("读取到的文件内容: %s\n", msg)
	// sm3.New()
	hw := New()
	// 添加散列内容
	hw.Write(msg)
	// 散列计算
	hash := hw.Sum(nil)
	fmt.Println("hash值: ", hash)
	fmt.Printf("hash长度 : %d\n", len(hash))
	fmt.Printf("hash字符串 : %s\n", byteToString(hash))
	// 直接sm3计算
	hash1 := Sm3Sum(msg)
	fmt.Println("hash1值: ", hash1)
	fmt.Printf("hash1长度 : %d\n", len(hash1))
	fmt.Printf("hash1字符串 : %s\n", byteToString(hash1))
}

func TestSm3AndSHA256(t *testing.T) {
	msg, err := ioutil.ReadFile("testdata/longMsg")
	if err != nil {
		t.Fatal(err)
	}
	// sm3计算
	hashSm3 := Sm3Sum(msg)
	fmt.Println("hashSm3值: ", hashSm3)
	fmt.Printf("hashSm3长度 : %d\n", len(hashSm3))
	fmt.Printf("hashSm3字符串 : %s\n", byteToString(hashSm3))

	// hashFuncSha256 := sha256.New()
	hashFuncSha256 := sha3.New256()
	// 添加散列内容
	hashFuncSha256.Write(msg)
	// 散列计算
	hashSha256 := hashFuncSha256.Sum(nil)
	fmt.Println("hashSha256值: ", hashSha256)
	fmt.Printf("hashSha256长度 : %d\n", len(hashSha256))
	fmt.Printf("hashSha256字符串 : %s\n", byteToString(hashSha256))

	// hashFuncSha384 := sha512.New384()
	hashFuncSha384 := sha3.New384()
	// 添加散列内容
	hashFuncSha384.Write(msg)
	// 散列计算
	hashSha384 := hashFuncSha384.Sum(nil)
	fmt.Println("hashSha384值: ", hashSha384)
	fmt.Printf("hashSha384长度 : %d\n", len(hashSha384))
	fmt.Printf("hashSha384字符串 : %s\n", byteToString(hashSha384))
}

func BenchmarkSm3(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	hw := New()
	for i := 0; i < t.N; i++ {

		hw.Sum(nil)
		Sm3Sum(msg)
	}
}
