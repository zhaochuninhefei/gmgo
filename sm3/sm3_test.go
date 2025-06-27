// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package sm3

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"hash"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/cpu"
)

type sm3Test struct {
	out       string
	in        string
	halfState string // marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []sm3Test{
	{"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNabcdabcdabcdabcdabcdabcdabcdabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 "},
	{"952eb84cacee9c10bde4d6882d29d63140ba72af6fe485085095dccd5b872453", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNabcdabcdabcdabcdabcdabcdabcdabcda\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!"},
	{"90d52a2e85631a8d6035262626941fa11b85ce570cec1e3e991e2dd7ed258148", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "sm3\x03YPށF\x86d\xebB\xfdL\x86\x1e|\xa0\n\xc0\xa5\x91\v\xae\x9aU\xea\x1aۍ\x17v<\xa2\"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@"},
	{"e1c53f367a9c5d19ab6ddd30248a7dafcc607e74e6bcfa52b00e0ba35e470421", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc", "sm3\x03YPށF\x86d\xebB\xfdL\x86\x1e|\xa0\n\xc0\xa5\x91\v\xae\x9aU\xea\x1aۍ\x17v<\xa2\"a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00A"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		h := Sm3Sum([]byte(g.in))
		s := fmt.Sprintf("%x", h)
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(h[:]))
		if s != g.out {
			t.Fatalf("SM3 function: sm3(%s) = %s want %s", g.in, s, g.out)
		}
		c := New()
		for j := 0; j < 3; j++ {
			if j < 2 {
				_, err := io.WriteString(c, g.in)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				_, err := io.WriteString(c, g.in[0:len(g.in)/2])
				if err != nil {
					t.Fatal(err)
				}
				c.Sum(nil)
				_, err = io.WriteString(c, g.in[len(g.in)/2:])
				if err != nil {
					t.Fatal(err)
				}
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sm3[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestGoldenMarshal(t *testing.T) {
	tests := []struct {
		name    string
		newHash func() hash.Hash
		gold    []sm3Test
	}{
		{"", New, golden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, g := range tt.gold {
				h := tt.newHash()
				h2 := tt.newHash()

				_, err := io.WriteString(h, g.in[:len(g.in)/2])
				if err != nil {
					t.Fatal(err)
				}

				state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
				if err != nil {
					t.Errorf("could not marshal: %v", err)
					continue
				}

				if string(state) != g.halfState {
					t.Errorf("sm3%s(%q) state = %q, want %q", tt.name, g.in, state, g.halfState)
					continue
				}

				if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
					t.Errorf("could not unmarshal: %v", err)
					continue
				}

				_, err = io.WriteString(h, g.in[len(g.in)/2:])
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.WriteString(h2, g.in[len(g.in)/2:])
				if err != nil {
					t.Fatal(err)
				}

				if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
					t.Errorf("sm3%s(%q) = 0x%x != marshaled 0x%x", tt.name, g.in, actual, actual2)
				}
			}
		})
	}
}

func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d want %d", got, BlockSize)
	}
	switch cpuType {
	case "arm64":
		fmt.Printf("arm64 has sm3 %v, has sm4 %v, has aes %v\n", cpu.ARM64.HasSM3, cpu.ARM64.HasSM4, cpu.ARM64.HasAES)
	case "amd64":
		fmt.Printf("amd64 has AVX2 %v, has BMI2 %v\n", cpu.X86.HasAVX2, cpu.X86.HasBMI2)
	}
}

var bench = New()
var benchSH256 = sha256.New()
var buf = make([]byte, 8192)

func benchmarkSize(hash hash.Hash, b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		hash.Reset()
		hash.Write(buf[:size])
		hash.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(bench, b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(bench, b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(bench, b, 8192)
}

func BenchmarkHash8K_SH256(b *testing.B) {
	benchmarkSize(benchSH256, b, 8192)
}

func TestSm3(t *testing.T) {
	msg := []byte("先天下之忧而忧，后天下之乐而乐！")
	// 生成msg文件
	err := os.WriteFile("testdata/msg", msg, os.FileMode(0644))
	if err != nil {
		t.Fatal(err)
	}
	// 读取msg文件
	msg, err = os.ReadFile("testdata/msg")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("读取到的文件内容: %s\n", string(msg))

	// 散列计算方式1:sm3.New(),Write,Sum
	//
	hw := New()
	// 添加散列内容
	hw.Write(msg)
	// 散列计算
	sum := hw.Sum(nil)
	fmt.Println("sum值: ", sum)
	fmt.Printf("sum长度 : %d\n", len(sum))
	fmt.Printf("sum字符串 : %s\n", hex.EncodeToString(sum))

	// 散列计算方式2:直接sm3计算
	hash1 := Sm3Sum(msg)
	fmt.Println("hash1值: ", hash1)
	fmt.Printf("hash1长度 : %d\n", len(hash1))
	fmt.Printf("hash1字符串 : %s\n", hex.EncodeToString(hash1))
	assert.Equal(t, sum, hash1)

	// 散列计算方式3:hw.reset,Write,Sum
	hw.Reset()
	hw.Write(msg)
	sum2 := hw.Sum(nil)
	fmt.Println("sum2值: ", sum2)
	fmt.Printf("sum2长度 : %d\n", len(sum2))
	fmt.Printf("sum2字符串 : %s\n", hex.EncodeToString(sum2))
	assert.Equal(t, sum, sum2)
}

func BenchmarkSm3(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("天行健君子以自强不息")
	hw := New()
	for i := 0; i < t.N; i++ {
		hw.Reset()
		hw.Write(msg)
		hw.Sum(nil)
	}
}

func BenchmarkSha256(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("天行健君子以自强不息")
	hw := sha256.New()
	for i := 0; i < t.N; i++ {
		hw.Reset()
		hw.Write(msg)
		hw.Sum(nil)
	}
}
