//go:build amd64 || arm64 || ppc64le

package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
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

		_, err := io.ReadFull(rand.Reader, scalar1[:])
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadFull(rand.Reader, scalar2[:])
		if err != nil {
			t.Fatal(err)
		}

		x, y := p256.ScalarBaseMult(scalar1[:])
		//x2, y2 := p256Generic.ScalarBaseMult(scalar1[:])
		x2, y2 := ScalarBaseMult(p256Generic, scalar1[:])

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

func ScalarBaseMult(curve *elliptic.CurveParams, k []byte) (*big.Int, *big.Int) {
	// If there is a dedicated constant-time implementation for this curve operation,
	// use that instead of the generic one.
	if specific, ok := matchesSpecificCurve(curve); ok {
		return specific.ScalarBaseMult(k)
	}

	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func matchesSpecificCurve(params *elliptic.CurveParams) (elliptic.Curve, bool) {
	for _, c := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		if params == c.Params() {
			return c, true
		}
	}
	return nil, false
}
