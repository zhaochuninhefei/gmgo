#!/bin/bash
# 执行各个包的测试用例

# sm2
echo "sm2测试用例"
cd sm2test || exit
go test
cd ../

# 等待控制台输入任意字符继续
echo
read -rp "sm2测试用例 结束，按下任意按键继续..." -n 1
echo

# sm3
echo "sm3测试用例"
cd sm3 || exit
go test
cd ../

# 等待控制台输入任意字符继续
echo
read -rp "sm3测试用例 结束，按下任意按键继续..." -n 1
echo

# sm4
echo "sm4测试用例"
cd sm4 || exit
go test
cd ../

# 等待控制台输入任意字符继续
echo
read -rp "sm4测试用例 结束，按下任意按键继续..." -n 1
echo

# x509
echo "x509测试用例"
cd x509 || exit
go test
cd ../

# 等待控制台输入任意字符继续
echo
read -rp "x509测试用例 结束，按下任意按键继续..." -n 1
echo

# x509test
echo "x509test测试用例"
cd x509test || exit
go test
cd ../

# 等待控制台输入任意字符继续
echo
read -rp "x509test测试用例 结束，按下任意按键继续..." -n 1
echo

# gmtls
echo "gmtls测试用例"
cd gmtls/tls_test || exit
go test
cd ../../

# 等待控制台输入任意字符继续
echo
read -rp "gmtls测试用例 结束，按下任意按键继续..." -n 1
echo

# gmgrpc
echo "gmgrpc测试用例"
cd grpc/grpc_test || exit
go test
cd ../../
echo "gmgrpc测试用例 结束"

echo "全部测试用例 结束"
echo