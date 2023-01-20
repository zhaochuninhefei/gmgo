//go:build amd64
// +build amd64

package sm3

/*
sm3/sm3block_amd64.go 平台CPU是amd64架构时SM3的块处理。
具体实现 : sm3/sm3block_amd64.s
*/

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/cpu"
)

var useAVX2 = cpu.X86.HasAVX2 && cpu.X86.HasBMI2

func init() {
	cpuType = runtime.GOARCH
	if false {
		fmt.Printf("该平台CPU架构为amd64, 对AVX2和BMI2指令集的支持: %v\n", useAVX2)
	}
}

//go:noescape
//goland:noinspection GoUnusedParameter
func block(dig *digest, p []byte)
