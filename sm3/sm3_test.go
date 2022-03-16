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

func BenchmarkSm3(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	hw := New()
	for i := 0; i < t.N; i++ {

		hw.Sum(nil)
		Sm3Sum(msg)
	}
}
