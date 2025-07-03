// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/*
sm3soft 是sm3的纯软实现，基于tjfoc国密算法库`tjfoc/gmsm`做了少量修改。
对应版权声明: thrid_licenses/github.com/tjfoc/gmsm/版权声明
*/

package sm3soft

import (
	"crypto/sha512"
	"fmt"
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
	err := os.WriteFile("testdata/msg", msg, os.FileMode(0644))
	if err != nil {
		t.Fatal(err)
	}
	// 读取msg文件
	msg, err = os.ReadFile("testdata/msg")
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
	msg, err := os.ReadFile("testdata/msg")
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

	// 散列计算
	hashSha512 := sha512.Sum512(msg)
	fmt.Println("hashSha512 值: ", hashSha512)
	fmt.Printf("hashSha512 长度 : %d\n", len(hashSha512))
	fmt.Printf("hashSha512 字符串 : %s\n", byteToString(hashSha512[:]))
}

func BenchmarkSm3(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("天行健君子以自强不息")
	hw := New()
	for i := 0; i < t.N; i++ {
		hw.Reset()
		hw.Write(msg)
		hw.Sum(nil)
	}
}
