// Copyright (c) 2022 zhaochun
// gmgo is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

/*
sm4soft 是sm4的纯软实现，基于tjfoc国密算法库`tjfoc/gmsm`做了少量修改。
对应版权声明: thrid_licenses/github.com/tjfoc/gmsm/版权声明
*/

package padding

import (
	"crypto/cipher"
	"io"
)

// P7BlockDecrypt 解密密文，并去除PKCS#7填充
// decrypter: 块解密器
// in: 密文输入流
// out: 明文输出流
func P7BlockDecrypt(decrypter cipher.BlockMode, in io.Reader, out io.Writer) error {
	bufIn := make([]byte, 1024)
	bufOut := make([]byte, 1024)
	p7Out := NewPKCS7PaddingWriter(out, decrypter.BlockSize())
	for {
		n, err := in.Read(bufIn)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		decrypter.CryptBlocks(bufOut, bufIn[:n])
		_, err = p7Out.Write(bufOut[:n])
		if err != nil {
			return err
		}
	}
	return p7Out.Final()
}

// P7BlockEnc 以PKCS#7填充模式填充原文，并加密输出
// encrypter: 块加密器
// in: 明文输入流
// out: 密文输出流
func P7BlockEnc(encrypter cipher.BlockMode, in io.Reader, out io.Writer) error {
	bufIn := make([]byte, 1024)
	bufOut := make([]byte, 1024)
	p7In := NewPKCS7PaddingReader(in, encrypter.BlockSize())
	for {
		n, err := p7In.Read(bufIn)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		encrypter.CryptBlocks(bufOut, bufIn[:n])
		_, err = out.Write(bufOut[:n])
		if err != nil {
			return err
		}
	}
	return nil
}
