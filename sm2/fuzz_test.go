// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//go:build amd64 || arm64 || ppc64le
// +build amd64 arm64 ppc64le

package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

var _ = elliptic.P256()

func TestFuzz(t *testing.T) {
	p256 := P256Sm2()
	p256Generic := p256.Params()

	var scalar1 [32]byte
	var scalar2 [32]byte
	var timeout *time.Timer

	if testing.Short() {
		timeout = time.NewTimer(10 * time.Millisecond)
	} else {
		timeout = time.NewTimer(2 * time.Second)
	}

	for {
		select {
		case <-timeout.C:
			return
		default:
		}

		io.ReadFull(rand.Reader, scalar1[:])
		io.ReadFull(rand.Reader, scalar2[:])

		x, y := p256.ScalarBaseMult(scalar1[:])
		x2, y2 := p256Generic.ScalarBaseMult(scalar1[:])

		xx, yy := p256.ScalarMult(x, y, scalar2[:])
		xx2, yy2 := p256Generic.ScalarMult(x2, y2, scalar2[:])

		if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
			t.Fatalf("ScalarBaseMult does not match reference result with scalar: %x, please report this error to https://gitee.com/zhaochuninhefei/gmgo/issues", scalar1)
		}

		if xx.Cmp(xx2) != 0 || yy.Cmp(yy2) != 0 {
			t.Fatalf("ScalarMult does not match reference result with scalars: %x and %x, please report this error to https://gitee.com/zhaochuninhefei/gmgo/issues", scalar1, scalar2)
		}
	}
}
