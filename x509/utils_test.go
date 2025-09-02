package x509

import (
	"encoding/hex"
	"fmt"
	"testing"

	"gitee.com/zhaochuninhefei/gmgo/utils"
	"github.com/stretchr/testify/assert"
)

func TestWriteKeyToPemFile(t *testing.T) {
	key, err := utils.GetRandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("key in hex: %s\n", hex.EncodeToString(key))

	pwd, err := utils.GetRandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}

	err = WriteKeyToPemFile("testdata/key_16.pem", key, pwd)
	if err != nil {
		t.Fatal(err)
	}

	keyFromPemFile, err := ReadKeyFromPemFile("testdata/key_16.pem", pwd)
	if err != nil {
		return
	}
	fmt.Printf("keyFromPemFile in hex: %s\n", hex.EncodeToString(keyFromPemFile))

	assert.Equal(t, key, keyFromPemFile)
}

func Test001(t *testing.T) {
	num := 1 << 16
	fmt.Println(num)
	fmt.Println(num / 1024)
}
