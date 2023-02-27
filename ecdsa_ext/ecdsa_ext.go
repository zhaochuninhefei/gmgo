package ecdsa_ext

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"gitee.com/zhaochuninhefei/gmgo/ecbase"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"io"
	"math/big"
)

type PrivateKey struct {
	ecdsa.PrivateKey
}

func ConvFromOrigin(oriKey *ecdsa.PrivateKey) *PrivateKey {
	privKey := &PrivateKey{
		PrivateKey: *oriKey,
	}
	return privKey
}

func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	oriKey, err := ecdsa.GenerateKey(c, rand)
	if err != nil {
		return nil, err
	}
	return ConvFromOrigin(oriKey), nil
}

//func (priv *PrivateKey) ToOrigin() *ecdsa.PrivateKey {
//	return &priv.PrivateKey
//}

//func (priv *PrivateKey) Public() crypto.PublicKey {
//	return &priv.PublicKey
//}
//
//func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
//	xx, ok := x.(*PrivateKey)
//	if !ok {
//		return false
//	}
//	return priv.PublicKey.Equal(&xx.PublicKey) && priv.D.Cmp(xx.D) == 0
//}

func (priv *PrivateKey) EcSign(rand io.Reader, digest []byte, opts ecbase.EcSignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, &priv.PrivateKey, digest)
	if err != nil {
		return nil, err
	}
	if opts.NeedLowS() {
		s, err = toLowS(&priv.PublicKey, s)
		if err != nil {
			return nil, err
		}
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

// IsLowS checks that s is a low-S
func isLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}

	return s.Cmp(halfOrder) != 1, nil

}

func toLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, error) {
	lowS, err := isLowS(k, s)
	if err != nil {
		return nil, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Params().N, s)

		return s, nil
	}

	return s, nil
}

type PublicKey struct {
	ecdsa.PublicKey
}

func (pub *PublicKey) Verify(digest []byte, sig []byte) bool {
	return ecdsa.VerifyASN1(&pub.PublicKey, digest, sig)
}
