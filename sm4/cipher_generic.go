// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//go:build !amd64 && !arm64
// +build !amd64,!arm64

package sm4

import "crypto/cipher"

// newCipher calls the newCipherGeneric function
// directly. Platforms with hardware accelerated
// implementations of SM4 should implement their
// own version of newCipher (which may then call
// newCipherGeneric if needed).
func newCipher(key []byte) (cipher.Block, error) {
	fmt.Println("sm4.newCipher in sm4/cipher_generic.go")
	return newCipherGeneric(key)
}

// expandKey is used by BenchmarkExpand and should
// call an assembly implementation if one is available.
func expandKey(key []byte, enc, dec []uint32) {
	expandKeyGo(key, enc, dec)
}
