gmgo
================
基于`go1.17.5`实现的国密算法库，包括:
- sm2 : 基于`emmansun/gmsm`的sm2部分实现部分扩展。
- sm2soft : 基于`tjfoc/gmsm`的sm2部分的纯软实现,仅作验证与参考用。
- sm3 : 基于`emmansun/gmsm`的sm3部分实现部分扩展。
- sm3soft : 基于`tjfoc/gmsm`的sm3部分的纯软实现,仅作验证与参考用。
- sm4 : 基于`emmansun/gmsm`的sm4部分实现部分扩展。
- sm4soft : 基于`tjfoc/gmsm`的sm4部分的纯软实现,仅作验证与参考用。
- x509 : 基于`go1.17.5`的x509包与本项目的sm2/sm3/sm4包实现国密改造。
- gmtls : 基于`go1.17.5`的tls包与本项目的sm2/sm3/sm4包实现国密改造，其中，`gmcredentials`包是对`google.golang.org/grpc/credentials`的国密改造，基于`tjfoc/gmsm`中的`gmcredentials`包做了少量修改。
- gmhttp : 整理中。。。

> 在x509/gmtls/gmhttp的实现中，国密算法采用的是基于`emmansun/gmsm`的国密实现，该开源项目已实现利用amd64与arm64架构CPU实现对应国密算法的硬件加速。sm2soft/sm3soft/sm4soft是对应国密算法的纯软实现，仅用作验证与参考。

# gmgo的包路径
go package： `gitee.com/zhaochuninhefei/gmgo`

# 国密标准参考
本项目涉及到的国密有SM2、SM3和SM4，相关国密标准如下：

- GB/T 33560-2017 密码应用标识规范
- GB/T 32918.1-2016 SM2椭圆曲线公钥密码算法 第1部分：总则
- GB/T 32918.2-2016 SM2椭圆曲线公钥密码算法 第2部分：数字签名算法
- GB/T 32918.3-2016 SM2椭圆曲线公钥密码算法 第3部分：密钥交换协议
- GB/T 32918.4-2016 SM2椭圆曲线公钥密码算法 第4部分：公钥加密算法
- GB/T 32918.5-2017 SM2椭圆曲线公钥密码算法 第5部分：参数定义
- GB/T 35275-2017 SM2密码算法加密签名消息语法规范
- GB/T 35276-2017 SM2密码算法使用规范
- GB/T 32905-2016 SM3密码杂凑算法
- GB/T 32907-2016 SM4分组密码算法

# 测试案例
从测试案例入手快速了解gmgo的使用。

## sm2
测试案例代码: `sm2test/sm2_test.go`
```sh
cd sm2test
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

### tls + http
测试案例代码: `gmtls/tls_test/tls_test.go`
```sh
cd gmtls/tls_test
go test

```

执行之前请确认`certs`目录下的sm2系列文件是否最新。可以在该目录下执行`copyCerts.sh`直接从x509的对应目录下拷贝。

### tls + grpc
测试案例代码: `gmtls/gmcredentials/credentials_test.go`
```sh
cd gmtls/gmcredentials
go test

```

执行之前请确认`testdata`目录下的文件是否最新。可以在该目录下执行`copyCerts.sh`直接从x509的对应目录下拷贝。

# 关于版权声明
本项目自身采用木兰宽松许可证(第2版)，具体参考`LICENSE`文件。

本项目的国密算法部分参考了以下其他开源项目，向对应的开源作者表示感谢!
- `https://github.com/golang/go`
- `https://github.com/emmansun/gmsm`
- `https://github.com/tjfoc/gmsm`

对应的版权声明参见目录`thrid_licenses`。
