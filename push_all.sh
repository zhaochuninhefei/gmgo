#!/bin/bash

# 获取本地提交的最后一个版本
commit_last_version=$(git log -1 --format="%H")
# 获取远程仓库上的最后一个版本
pushed_last_version=$(git ls-remote origin HEAD | cut -f 1)
# 获取远程仓库上的标签列表，并根据版本号进行排序
tag_list=$(git ls-remote --tags --sort='v:refname')
# 获取远程仓库上的最后一个标签
tag_last=$(echo "${tag_list}" | tail -n 1 | cut -f 2)
# 获取远程仓库上的最后一个标签的版本号
tag_last_version=$(echo "${tag_list}" | tail -n 1 | cut -f 1)

echo "本地最新提交版本: $commit_last_version"
echo "仓库最新推送版本: $pushed_last_version"
echo "仓库最新标签版本: $tag_last_version ($tag_last)"

echo "请选择要执行的操作:(1:推送代码到远程仓库, 2:创建新标签并推送到远程仓库, 其他:退出)"
read -r op_mode

if [ "$op_mode" = "1" ]; then
  echo "----- 查看所有远程仓库:"
  git remote -v
  echo "----- 推送到所有远程仓库:"
  git push origin --all
  echo "----- 推送结束"
elif [ "$op_mode" = "2" ]; then
  echo "----- 创建新标签并推送到远程仓库"
  echo "请输入新标签的版本号:"
  read -r tag_version
  echo "请输入新标签的描述信息:"
  read -r tag_message
  git tag -a "$tag_version" -m "$tag_message"
  git push origin "$tag_version"
else
  echo "----- 退出"
fi
