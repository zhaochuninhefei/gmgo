package ecdsa_ext

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecbase"
	"testing"
)

func TestPrivateKey_Sign(t *testing.T) {
	privateKey, err := GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	msg := "花有重开日, 人无再少年"
	digest := sha256.Sum256([]byte(msg))
	fmt.Printf("msg: %s\n", msg)
	fmt.Printf("digest hex: %s\n", hex.EncodeToString(digest[:]))

	sign, err := privateKey.Sign(rand.Reader, digest[:], ecbase.CreateDefaultEcSignerOpts())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sign hex: %s\n", hex.EncodeToString(sign))

	pubKey, ok := privateKey.Public().(*PublicKey)
	if !ok {
		t.Fatal("PublicKey类型强转失败")
	}
	valied := pubKey.Verify(digest[:], sign)
	if !valied {
		t.Fatal("验签失败")
	}
	fmt.Println("验签成功")
}