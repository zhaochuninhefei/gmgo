package sm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"

	"gitee.com/zhaochuninhefei/gmgo/sm3"
)

func Test_kdf(t *testing.T) {
	x2, _ := new(big.Int).SetString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE", 16)
	y2, _ := new(big.Int).SetString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78", 16)

	expected := "006e30dae231b071dfad8aa379e90264491603"

	result, success := kdf(append(x2.Bytes(), y2.Bytes()...), 19)
	if !success {
		t.Fatalf("failed")
	}

	resultStr := hex.EncodeToString(result)

	if expected != resultStr {
		t.Fatalf("expected %s, real value %s", expected, resultStr)
	}
}

func Test_SplicingOrder(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
		from      ciphertextSplicingOrder
		to        ciphertextSplicingOrder
	}{
		// TODO: Add test cases.
		{"less than 32 1", "encryption standard", C1C2C3, C1C3C2},
		{"less than 32 2", "encryption standard", C1C3C2, C1C2C3},
		{"equals 32 1", "encryption standard encryption ", C1C2C3, C1C3C2},
		{"equals 32 2", "encryption standard encryption ", C1C3C2, C1C2C3},
		{"long than 32 1", "encryption standard encryption standard", C1C2C3, C1C3C2},
		{"long than 32 2", "encryption standard encryption standard", C1C3C2, C1C2C3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(&priv.PublicKey, []byte(tt.plainText), rand.Reader, NewPlainEncrypterOpts(MarshalUncompressed, tt.from))
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, NewPlainDecrypterOpts(tt.from))
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}

			//Adjust splicing order
			ciphertext, err = AdjustCiphertextSplicingOrder(ciphertext, tt.from, tt.to)
			if err != nil {
				t.Fatalf("adjust splicing order failed %v", err)
			}
			plaintext, err = priv.Decrypt(rand.Reader, ciphertext, NewPlainDecrypterOpts(tt.to))
			if err != nil {
				t.Fatalf("decrypt failed after adjust splicing order %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_encryptDecrypt_ASN1(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypterOpts := ASN1EncrypterOpts
			ciphertext, err := Encrypt(&priv.PublicKey, []byte(tt.plainText), rand.Reader, encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, ASN1DecrypterOpts)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_Ciphertext2ASN1(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(&priv.PublicKey, []byte(tt.plainText), rand.Reader, nil)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			ciphertext, err = PlainCiphertext2ASN1(ciphertext, C1C3C2)
			if err != nil {
				t.Fatalf("convert to ASN.1 failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, ASN1DecrypterOpts)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_ASN1Ciphertext2Plain(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := EncryptAsn1(&priv.PublicKey, []byte(tt.plainText), rand.Reader)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			ciphertext, err = ASN1Ciphertext2Plain(ciphertext, nil)
			if err != nil {
				t.Fatalf("convert to plain failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, nil)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_encryptDecrypt(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(&priv.PublicKey, []byte(tt.plainText), rand.Reader, nil)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err := Decrypt(priv, ciphertext, nil)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
			// compress mode
			encrypterOpts := NewPlainEncrypterOpts(MarshalCompressed, C1C3C2)
			ciphertext, err = Encrypt(&priv.PublicKey, []byte(tt.plainText), rand.Reader, encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err = Decrypt(priv, ciphertext, nil)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}

			// mixed mode
			encrypterOpts = NewPlainEncrypterOpts(MarshalMixed, C1C3C2)
			ciphertext, err = Encrypt(&priv.PublicKey, []byte(tt.plainText), rand.Reader, encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err = Decrypt(priv, ciphertext, nil)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_signVerify(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := sm3.Sm3Sum([]byte(tt.plainText))
			signature, err := priv.Sign(rand.Reader, hash[:], nil)
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}
			result := VerifyASN1(&priv.PublicKey, hash[:], signature)
			if !result {
				t.Fatal("verify failed")
			}
		})
	}
}

// Check that signatures are safe even with a broken entropy source.
func TestNonceSafety(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := SignAfterZA(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	hashed = []byte("testing...")
	r1, s1, err := SignAfterZA(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	if s0.Cmp(s1) == 0 {
		// This should never happen.
		t.Error("SM2: the signatures on two different messages were the same")
	}

	if r0.Cmp(r1) == 0 {
		t.Error("SM2: the nonce used for two diferent messages was the same")
	}
}

// Check that signatures remain non-deterministic with a functional entropy source.
func TestINDCCA(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := SignAfterZA(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	r1, s1, err := SignAfterZA(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	if s0.Cmp(s1) == 0 {
		t.Error("SM2: two signatures of the same message produced the same result")
	}

	if r0.Cmp(r1) == 0 {
		t.Error("SM2: two signatures of the same message produced the same nonce")
	}
}

func TestEqual(t *testing.T) {
	private, _ := GenerateKey(rand.Reader)
	public := &private.PublicKey

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %q", public)
	}
	if !public.Equal(crypto.Signer(private).Public()) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself: %q", private)
	}

	otherPriv, _ := GenerateKey(rand.Reader)
	otherPub := &otherPriv.PublicKey
	if public.Equal(otherPub) {
		t.Errorf("different public keys are Equal")
	}
	if private.Equal(otherPriv) {
		t.Errorf("different private keys are Equal")
	}
}

func BenchmarkGenerateKey_SM2(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateKey_P256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_SM2(b *testing.B) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := SignASN1(rand.Reader, priv, hashed)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		hashed[0] = sig[0]
	}
}

func BenchmarkSign_P256(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := ecdsa.SignASN1(rand.Reader, priv, hashed)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		hashed[0] = sig[0]
	}
}

func BenchmarkVerify_P256(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkVerify_SM2(b *testing.B) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := SignAfterZA(rand.Reader, priv, hashed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !verifyGeneric(&priv.PublicKey, hashed, r, s) {
			b.Fatal("verify failed")
		}
	}
}

// func benchmarkEncrypt(b *testing.B, curve elliptic.Curve, plaintext string) {
// 	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
// 	if err != nil {
// 		b.Fatal(err)
// 	}
// 	b.ReportAllocs()
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		Encrypt(&priv.PublicKey, []byte(plaintext), rand.Reader, nil)
// 	}
// }

// func BenchmarkLessThan32_P256(b *testing.B) {
// 	benchmarkEncrypt(b, elliptic.P256(), "encryption standard")
// }

// func BenchmarkLessThan32_SM2(b *testing.B) {
// 	benchmarkEncrypt(b, P256(), "encryption standard")
// }

// func BenchmarkMoreThan32_P256(b *testing.B) {
// 	benchmarkEncrypt(b, elliptic.P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
// }

// func BenchmarkMoreThan32_SM2(b *testing.B) {
// 	benchmarkEncrypt(b, P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
// }
