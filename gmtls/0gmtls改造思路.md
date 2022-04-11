# 基本思路

## 思路１：
在tls1.2和tls1.3的实现中添加国密套件的实现。

## 思路２：
单独添加一个GMTLS的握手过程。


# 与crypto/tls的代码比对

依赖关系：

gmtls/auth.go -> gmtls/common.go -> gmtls/cipher_suites.go -> gmtls/key_agreement.go -> gmtls/key_schedule.go

