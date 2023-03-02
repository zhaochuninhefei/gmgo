// Copyright (c) 2023 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package ecbase

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

//==============================================
// EcVerifier 椭圆曲线验签接口
//==============================================

type EcVerifier interface {
	EcVerify(digest []byte, sig []byte, opts EcSignerOpts) (bool, error)
}

//==============================================
// EcSignerOpts 椭圆曲线签名参数接口
//==============================================

type EcSignerOpts interface {
	crypto.SignerOpts
	NeedLowS() bool
	ResetHasher(hasher crypto.Hash)
}

type ecSignerOpts struct {
	hasher   crypto.Hash
	needLowS bool
}

func (eso ecSignerOpts) HashFunc() crypto.Hash {
	return eso.hasher
}

func (eso ecSignerOpts) NeedLowS() bool {
	return eso.needLowS
}

func (eso ecSignerOpts) ResetHasher(hasher crypto.Hash) {
	eso.hasher = hasher
}

func CreateEcSignerOpts(hasher crypto.Hash, needLowS bool) EcSignerOpts {
	return &ecSignerOpts{
		hasher:   hasher,
		needLowS: needLowS,
	}
}

func CreateDefaultEcSignerOpts() EcSignerOpts {
	return &ecSignerOpts{
		hasher:   0,
		needLowS: true,
	}
}

//==============================================
// ECSignature 椭圆曲线签名
//==============================================

// ECSignature 椭圆曲线签名
type ECSignature struct {
	R, S *big.Int
}

// MarshalECSignature 序列化椭圆曲线签名
func MarshalECSignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECSignature{r, s})
}

// UnmarshalECSignature 反序列化椭圆曲线签名
func UnmarshalECSignature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(ECSignature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature, R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, S must be larger than zero")
	}

	return sig.R, sig.S, nil
}
