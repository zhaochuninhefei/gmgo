// Copyright (c) 2022 zhaochun
// gmingo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm4soft

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSM4GCM(t *testing.T) {
	// 定义key，16字节
	key := []byte("1234567890abcdef")
	fmt.Printf("key字节数组 : %v\n", key)
	fmt.Printf("key字符串 : %s\n", key)
	// 定义IV，16字节
	IV := []byte("1234def567890abc")
	// IV := make([]byte, BlockSize)
	fmt.Printf("iv字节数组 : %v\n", IV)
	fmt.Printf("iv16进制 : %x\n", IV)
	fmt.Printf("iv字符串 : %s\n", IV)

	// 定义数据，长度必须是16字节的倍数
	// data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	data := []byte("天行健君子以自强不息12")
	fmt.Printf("data字节数组 : %v\n", data)
	fmt.Printf("data十六进制 : %x\n", data)
	fmt.Printf("data字符串 : %s\n", data)

	testA := [][]byte{ // the length of the A can be random
		{},
		{0x01, 0x23, 0x45, 0x67, 0x89},
		{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	}
	for _, A := range testA {
		fmt.Printf("====== 附加鉴别数据 A : %x\n", A)
		// gcm模式加密
		gcmMsg, T, err := Sm4GCM(key, IV, data, A, true)
		if err != nil {
			t.Errorf("sm4 enc error:%s", err)
		}
		fmt.Printf("gcmMsg 16进制 : %x\n", gcmMsg)
		// gcm模式解密
		gcmDec, T_, err := Sm4GCM(key, IV, gcmMsg, A, false)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
		}
		fmt.Printf("gcmDec : %s\n", gcmDec)

		if bytes.Equal(T, T_) {
			fmt.Println("鉴别成功")
		}

		//Failed Test : if we input the different A , that will be a falied result.
		A = []byte{0x01, 0x32, 0x45, 0x67, 0xba, 0xab, 0xcd}
		gcmDec, T_, err = Sm4GCM(key, IV, gcmMsg, A, false)
		if err != nil {
			t.Errorf("使用不同的附加鉴别数据后，Sm4GCM 解密失败 : %s", err)
		} else {
			fmt.Printf("使用不同的附加鉴别数据后，gcmDec : %s\n", gcmDec)
		}
		if !bytes.Equal(T, T_) {
			fmt.Println("鉴别失败")
		}
	}

}
