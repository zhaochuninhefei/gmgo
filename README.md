gmgo
================
基于tjfoc国密算法库`tjfoc/gmsm`的`2.0`版本实现部分扩展。

- go package： `gitee.com/zhaochuninhefei/gmgo`

# 国密标准参考
本项目涉及到的国密有SM2、SM3和SM4，相关国密标准如下：

- GMT 0002-2012 SM4分组密码算法.pdf
- GMT 0003.1-2012 SM2椭圆曲线公钥密码算法第1部分：总则.pdf
- GMT 0003.2-2012 SM2椭圆曲线公钥密码算法第2部分：数字签名算法.pdf
- GMT 0003.3-2012 SM2椭圆曲线公钥密码算法第3部分：密钥交换协议.pdf
- GMT 0003.4-2012 SM2椭圆曲线公钥密码算法第4部分：公钥加密算法.pdf
- GMT 0003.5-2012 SM2椭圆曲线公钥密码算法第5部分：参数定义.pdf
- GMT 0004-2012 SM3密码杂凑算法.pdf
- GMT 0006-2012 密码应用标识规范.pdf
- GMT 0009-2012 SM2密码算法使用规范 .pdf
- GMT 0010-2012 SM2密码算法加密签名消息语法规范.pdf
- GMT 0015-2012 基于SM2密码算法的数字证书格式.pdf
- GMT 0034-2014 基于SM2密码算法的证书认证系统密码及其相关安全技术规范.PDF


下方是tjfoc国密算法库`tjfoc/gmsm`的说明
===============

# gmsm
GM SM2/3/4 library based on Golang
=======

[![Build Status](https://travis-ci.com/tjfoc/gmsm.svg?branch=master)](https://travis-ci.com/github/tjfoc/gmsm)


## Feature
 gmsm包含以下主要功能

    SM2: 国密椭圆曲线算法库
        . 支持Generate Key, Sign, Verify基础操作
        . 支持加密和不加密的pem文件格式(加密方法参见RFC5958, 具体实现参加代码)
        . 支持证书的生成，证书的读写(接口兼容rsa和ecdsa的证书)
        . 支持证书链的操作(接口兼容rsa和ecdsa)
        . 支持crypto.Signer接口

    SM3: 国密hash算法库
       . 支持基础的sm3Sum操作
       . 支持hash.Hash接口

    SM4: 国密分组密码算法库
        . 支持Generate Key, Encrypt, Decrypt基础操作
        . 提供Cipher.Block接口
        . 支持加密和不加密的pem文件格式(加密方法为pem block加密, 具体函数为x509.EncryptPEMBlock)

## [Usage 使用说明](./API使用说明.md)

## Communication
tjfoc国密交流 
   
[![Join the chat at https://gitter.im/tjfoc/gmsm](https://badges.gitter.im/tjfoc/gmsm.svg)](https://gitter.im/tjfoc/gmsm?utm_source=badge&utm_medium=badge&utm_campaign=-badge&utm_content=badge)


- 如果你对国密算法开源技术及应用感兴趣，欢迎添加“苏州同济区块链研究院·小助手“微信，回复“国密算法进群”，加入“同济区块链国密算法交流群”。微信二维码如下:  
     ![微信二维码](https://github.com/tjfoc/wutongchian-public/blob/master/wutongchain.png)

- 发送邮件到tj@wutongchain.com
 
 
 ## License
 版权所有 苏州同济区块链研究院有限公司(http://www.wutongchain.com/)
 ```
 Copyright 2017- Suzhou Tongji Fintech Research Institute. All Rights Reserved.
 Licensed under the Apache License, Version 2.0 (the "License");
 
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 
 See the License for the specific language governing permissions and limitations under the License.
```
