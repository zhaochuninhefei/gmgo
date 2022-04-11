gmgo
================
基于`go1.17.5`实现的国密算法库，包括:
- sm2 : 基于tjfoc国密算法库`tjfoc/gmsm`的`2.0`版本的sm2部分实现部分扩展。
- sm3 : 基于`emmansun/gmsm`的sm3部分实现部分扩展。
- sm4 : 基于`emmansun/gmsm`的sm4部分实现部分扩展。
- x509 : 整理实现中。。。
- gmtls : 整理实现中。。。
- gmhttp : 整理实现中。。。

# gmgo的包路径
go package： `gitee.com/zhaochuninhefei/gmgo`

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

# 测试案例
从测试案例入手快速了解gmgo的使用。

## sm2
测试案例代码: `sm2/sm2_test.go`
```sh
cd sm2
go test

```

## sm3
测试案例代码: `sm3/sm3_test.go`
```sh
cd sm3
go test

```

## sm4
测试案例代码: `sm4/sm4_test.go`、`sm4/sm4_gcm_test.go`
```sh
cd sm4
go test

```

## x509
测试案例代码: `x509/x509_test.go`
```sh
cd x509
go test

```

注意，`x509_test`的`TestCreateCertFromCA`测试函数生成的sm2系列密钥文件与证书将会用于`gmtls`的测试案例。


## gmtls
gmtls的测试案例主要是 `tls + http` 通信测试以及 `tls + grpc` 通信测试。

### websvr
测试案例代码: `gmtls/websvr/websvr_test.go`
```sh
cd gmtls/websvr
go test

```

执行之前请确认`certs`目录下的sm2系列文件是否最新。可以在该目录下执行`copyCerts.sh`直接从x509的对应目录下拷贝。

### gmcredentials
测试案例代码: `gmtls/gmcredentials/credentials_test.go`
```sh
cd gmtls/gmcredentials
go test

```

执行之前请确认`testdata`目录下的文件是否最新。可以在该目录下执行`copyCerts.sh`直接从x509的对应目录下拷贝。

# 关于版权声明
本项目依赖的其他开源项目有:
- `https://github.com/emmansun/gmsm`
- `https://github.com/tjfoc/gmsm`

对应的版权声明参见目录`thrid_licenses`。
