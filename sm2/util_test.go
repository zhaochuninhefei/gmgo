// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func Test_toBytes(t *testing.T) {
	type args struct {
		value string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{"less than 32", args{"d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "00d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
		{"equals 32", args{"58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := new(big.Int).SetString(tt.args.value, 16)
			if got := toBytes(elliptic.P256(), v); !reflect.DeepEqual(hex.EncodeToString(got), tt.want) {
				t.Errorf("toBytes() = %v, want %v", hex.EncodeToString(got), tt.want)
			}
		})
	}
}

func Test_getLastBitOfY(t *testing.T) {
	type args struct {
		y string
	}
	tests := []struct {
		name string
		args args
		want uint
	}{
		// TODO: Add test cases.
		{"0", args{"d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, 0},
		{"1", args{"d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865ff"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y, _ := new(big.Int).SetString(tt.args.y, 16)
			if got := getLastBitOfY(y, y); got != tt.want {
				t.Errorf("getLastBitOfY() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toPointXY(t *testing.T) {
	type args struct {
		bytes string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{"has zero padding", args{"00d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
		{"no zero padding", args{"58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes, _ := hex.DecodeString(tt.args.bytes)
			expectedInt, _ := new(big.Int).SetString(tt.want, 16)
			if got := toPointXY(bytes); !reflect.DeepEqual(got, expectedInt) {
				t.Errorf("toPointXY() = %v, want %v", got, expectedInt)
			}
		})
	}
}

func TestSm2KeyHex(t *testing.T) {
	priKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &priKey.PublicKey

	priKeyStr := WriteSm2PrivToHex(priKey)
	fmt.Printf("priKeyStr : %s\n", priKeyStr)

	pubKeyStr := WriteSm2PubToHex(pubKey)
	fmt.Printf("pubKeyStr : %s\n", pubKeyStr)

	priKeyA, err := ReadSm2PrivFromHex(priKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(priKey, priKeyA) {
		fmt.Println("ReadSm2PrivFromHex OK")
	} else {
		fmt.Println("ReadSm2PrivFromHex NG")
	}

	pubKeyA, err := ReadSm2PubFromHex(pubKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(pubKey, pubKeyA) {
		fmt.Println("ReadSm2PubFromHex OK")
	} else {
		fmt.Println("ReadSm2PubFromHex NG")
	}
}
