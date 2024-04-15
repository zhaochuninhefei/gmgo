#!/bin/bash

set -e

# 读取.buildignore文件中的每一行，组合成一个大的正则表达式
# shellcheck disable=SC2002
exclude_patterns=$(cat .buildignore | paste -sd '|' -)

echo
echo '编译范围 :'
go list ./... | grep -vE "$exclude_patterns"
echo

echo '===== 开始编译 ====='
# 使用go list获取所有包的列表，排除.buildignore中列出的包，然后构建剩余的包
go list ./... | grep -vE "$exclude_patterns" | xargs go build

echo '===== 编译结束 ====='
echo
