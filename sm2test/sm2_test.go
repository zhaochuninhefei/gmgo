package sm2test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/sm2soft"
)

func TestSm2Sign(t *testing.T) {
	privSoft, err := sm2soft.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 验证生成的公钥是否在自己的椭圆曲线上
	fmt.Printf("Soft公钥是否在Soft的椭圆曲线上: %v\n", privSoft.Curve.IsOnCurve(privSoft.X, privSoft.Y))
	privHard, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 验证生成的公钥是否在自己的椭圆曲线上
	fmt.Printf("Hard公钥是否在Hard的椭圆曲线上: %v\n", privHard.Curve.IsOnCurve(privHard.X, privHard.Y))

	// 验证生成的公钥是否在对方的椭圆曲线上
	fmt.Printf("Hard公钥是否在Soft的椭圆曲线上: %v\n", privSoft.Curve.IsOnCurve(privHard.X, privHard.Y))
	fmt.Printf("Soft公钥是否在Hard的椭圆曲线上: %v\n", privHard.Curve.IsOnCurve(privSoft.X, privSoft.Y))

	// soft私钥转为hard私钥
	privHardFromSoft := convertPrivFromSoft2Hard(privSoft)
	// hard私钥转为soft私钥
	privSoftFromHard := convertPrivFromHard2Soft(privHard)

	// 定义明文
	msg := []byte("12345,上山打老虎")
	fmt.Printf("明文: %s\n", msg)

	fmt.Println("========== sm2soft使用soft公私钥签名及验签 ==========")
	softSignBySoftPriv, err := privSoft.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok1 := privSoft.PublicKey.Verify(msg, softSignBySoftPriv)
	fmt.Printf("验签结果: %v\n", ok1)

	fmt.Println("========== sm2hard使用hard公私钥签名及验签 ==========")
	hardSignByHardPriv, err := privHard.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok2 := privHard.PublicKey.Verify(msg, hardSignByHardPriv)
	fmt.Printf("验签结果: %v\n", ok2)

	fmt.Println("========== sm2soft使用hard公私钥签名及验签 ==========")
	softSignByHardPriv, err := privSoftFromHard.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok3 := privSoftFromHard.PublicKey.Verify(msg, softSignByHardPriv)
	fmt.Printf("验签结果: %v\n", ok3)

	fmt.Println("========== sm2hard使用soft公私钥签名及验签 ==========")
	hardSignBySoftPriv, err := privHardFromSoft.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok4 := privHardFromSoft.PublicKey.Verify(msg, hardSignBySoftPriv)
	fmt.Printf("验签结果: %v\n", ok4)

	fmt.Println("========== sm2soft使用soft私钥签名, sm2hard使用soft公钥验签 ==========")
	softSignBySoftPriv2, err := privSoft.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok5 := privHardFromSoft.PublicKey.Verify(msg, softSignBySoftPriv2)
	fmt.Printf("验签结果: %v\n", ok5)

	fmt.Println("========== sm2soft使用hard私钥签名, sm2hard使用hard公钥验签 ==========")
	softSignByHardPriv2, err := privSoftFromHard.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok6 := privHard.PublicKey.Verify(msg, softSignByHardPriv2)
	fmt.Printf("验签结果: %v\n", ok6)

	fmt.Println("========== sm2hard使用soft私钥签名, sm2soft使用soft公钥验签 ==========")
	hardSignBySoftPriv2, err := privHardFromSoft.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok7 := privSoft.PublicKey.Verify(msg, hardSignBySoftPriv2)
	fmt.Printf("验签结果: %v\n", ok7)

	fmt.Println("========== sm2hard使用hard私钥签名, sm2soft使用hard公钥验签 ==========")
	hardSignByHardPriv2, err := privHard.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok8 := privSoftFromHard.PublicKey.Verify(msg, hardSignByHardPriv2)
	fmt.Printf("验签结果: %v\n", ok8)

}

func TestSm2Encrypt(t *testing.T) {
	privSoft, _ := sm2soft.GenerateKey(rand.Reader)
	// 验证生成的公钥是否在自己的椭圆曲线上
	fmt.Printf("Soft公钥是否在Soft的椭圆曲线上: %v\n", privSoft.Curve.IsOnCurve(privSoft.X, privSoft.Y))
	privHard, _ := sm2.GenerateKey(rand.Reader)
	// 验证生成的公钥是否在自己的椭圆曲线上
	fmt.Printf("Hard公钥是否在Hard的椭圆曲线上: %v\n", privHard.Curve.IsOnCurve(privHard.X, privHard.Y))
	// 验证生成的公钥是否在对方的椭圆曲线上
	fmt.Printf("Hard公钥是否在Soft的椭圆曲线上: %v\n", privSoft.Curve.IsOnCurve(privHard.X, privHard.Y))
	fmt.Printf("Soft公钥是否在Hard的椭圆曲线上: %v\n", privHard.Curve.IsOnCurve(privSoft.X, privSoft.Y))
	// soft私钥转为hard私钥
	privHardFromSoft := convertPrivFromSoft2Hard(privSoft)
	// hard私钥转为soft私钥
	privSoftFromHard := convertPrivFromHard2Soft(privHard)
	// 定义明文
	msg := []byte("12345,上山打老虎")
	fmt.Printf("明文: %s\n", msg)

	fmt.Println("========== sm2Soft使用soft公钥加密, soft私钥解密 ==========")
	softEncBySoft, err := privSoft.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	softDecBySoft, err := privSoft.DecryptAsn1(softEncBySoft)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", softDecBySoft)

	fmt.Println("========== sm2Hard使用hard公钥加密, hard私钥解密 ==========")
	hardEncByHard, err := privHard.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hardDecByHard, err := privHard.DecryptAsn1(hardEncByHard)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", hardDecByHard)

	fmt.Println("========== sm2Soft使用hard公钥加密, hard私钥解密 ==========")
	softEncByHard, err := privSoftFromHard.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	softDecByHard, err := privSoftFromHard.DecryptAsn1(softEncByHard)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", softDecByHard)

	fmt.Println("========== sm2Hard使用soft公钥加密, soft私钥解密 ==========")
	hardEncBySoft, err := privHardFromSoft.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hardDecBySoft, err := privHardFromSoft.DecryptAsn1(hardEncBySoft)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", hardDecBySoft)

	fmt.Println("========== sm2Soft使用hard公钥加密, sm2Hard使用hard私钥解密 ==========")
	softEncByHard1, err := privSoftFromHard.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hardDecByHard1, err := privHard.DecryptAsn1(softEncByHard1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", hardDecByHard1)

	fmt.Println("========== sm2Soft使用soft公钥加密, sm2Hard使用soft私钥解密 ==========")
	softEncBySoft1, err := privSoft.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hardDecBySoft1, err := privHardFromSoft.DecryptAsn1(softEncBySoft1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", hardDecBySoft1)

	fmt.Println("========== sm2Hard使用hard公钥加密, sm2Soft使用hard私钥解密 ==========")
	hardEncByHard1, err := privHard.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	softDecByHard1, err := privSoftFromHard.DecryptAsn1(hardEncByHard1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", softDecByHard1)

	fmt.Println("========== sm2Hard使用soft公钥加密, sm2Soft使用soft私钥解密 ==========")
	hardEncBySoft1, err := privHardFromSoft.PublicKey.EncryptAsn1(msg, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	softDecBySoft1, err := privSoft.DecryptAsn1(hardEncBySoft1)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("解密结果: %s\n", softDecBySoft1)
}

func convertPrivFromSoft2Hard(privSoft *sm2soft.PrivateKey) *sm2.PrivateKey {
	privHard := &sm2.PrivateKey{}
	privHard.D = privSoft.D
	privHard.X = privSoft.X
	privHard.Y = privSoft.Y
	privHard.Curve = privSoft.Curve
	return privHard
}

func convertPrivFromHard2Soft(privHard *sm2.PrivateKey) *sm2soft.PrivateKey {
	privSoft := &sm2soft.PrivateKey{}
	privSoft.D = privHard.D
	privSoft.X = privHard.X
	privSoft.Y = privHard.Y
	privSoft.Curve = privHard.Curve
	return privSoft
}
