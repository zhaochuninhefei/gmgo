// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//go:build amd64 || arm64
// +build amd64 arm64

package sm3

/*
sm3/sm3block_hard.go cpu是amd64或arm64架构时声明block函数(由汇编实现)
*/

import (
	"runtime"
)

func init() {
	cpuType = runtime.GOARCH
	// fmt.Printf("该平台CPU架构: %s\n", cpuType)
}

//go:noescape
func block(dig *digest, p []byte)
