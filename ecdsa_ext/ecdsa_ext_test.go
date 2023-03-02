// Copyright (c) 2023 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package ecdsa_ext

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gitee.com/zhaochuninhefei/zcgolog/zclog"
	"testing"
)

func TestPrivateKey_Sign(t *testing.T) {
	zclog.Level = zclog.LOG_LEVEL_DEBUG

	privateKey, err := GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := "花有重开日, 人无再少年"
	digest := sha256.Sum256([]byte(msg))
	fmt.Printf("msg: %s\n", msg)
	fmt.Printf("digest hex: %s\n", hex.EncodeToString(digest[:]))

	sign, err := privateKey.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sign hex: %s\n", hex.EncodeToString(sign))

	pubKey, ok := privateKey.Public().(*PublicKey)
	if !ok {
		t.Fatal("PublicKey类型强转失败")
	}
	valied, err := pubKey.EcVerify(digest[:], sign, nil)
	if !valied {
		t.Fatal("验签失败")
	}
	fmt.Println("验签成功")
}
