// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//go:build arm64
// +build arm64

package sm3

/*
sm3/sm3block_arm64.go 平台CPU是arm64架构时SM3的块处理。
具体实现 : sm3/sm3block_arm64.s
*/

import (
	"fmt"

	"golang.org/x/sys/cpu"
)

var useSM3NI = cpu.ARM64.HasSM3

func init() {
	if false {
		fmt.Printf("该平台CPU架构为arm64, 对SM3指令集的支持: %v\n", useSM3NI)
	}
}
