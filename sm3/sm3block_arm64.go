//go:build arm64
// +build arm64

package sm3

/*
sm3/sm3block_arm64.go 平台CPU是arm64架构时SM3的块处理。
具体实现 : sm3/sm3block_arm64.s
*/

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/cpu"
)

var useSM3NI = cpu.ARM64.HasSM3

func init() {
	cpuType = runtime.GOARCH
	if false {
		fmt.Printf("该平台CPU架构为arm64, 对SM3指令集的支持: %v\n", useSM3NI)
	}
}

var t = []uint32{
	0x79cc4519,
	0x9d8a7a87,
}

//go:noescape
func blockARM64(dig *digest, p []byte)

//go:noescape
func blockSM3NI(h []uint32, p []byte, t []uint32)

func block(dig *digest, p []byte) {
	if !useSM3NI {
		blockARM64(dig, p)
	} else {
		h := dig.h[:]
		blockSM3NI(h, p, t)
	}
}
