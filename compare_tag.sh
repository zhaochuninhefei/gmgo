#!/bin/bash

## 获取本地最后一个提交的版本
#last_commit=$(git log -1 --pretty=format:"%H")
#
## 获取远程仓库上的标签列表，并根据版本号进行排序
#tag_list=$(git ls-remote --tags | awk '{print $2" "$1}' | sed 's#refs/tags/##' | sort -V)
#
## 获取远程仓库上最后一个标签的版本号
#last_tag=$(echo "${tag_list}" | tail -n1 | awk '{print $2}')
#
#echo $last_commit
#echo $last_tag
#
## 比较最后一个标签的版本与本地最后一个提交的版本是否一致
#if [[ ${last_tag} == ${last_commit} ]]; then
#  echo "The latest tag in the remote repository is the same as the latest commit in the local repository."
#else
#  echo "The latest tag in the remote repository is different from the latest commit in the local repository."
#fi

# 获取本地提交的最后一个版本
commit=$(git log -1 --format="%H")
# 获取远程仓库上的最后一个标签
tag=$(git ls-remote --tags --sort='v:refname' | tail -n 1 | cut -f 1)
echo "本地最新提交版本: $commit"
echo "仓库最新标签版本: $tag"
# 比较两个版本是否一致
if [ "$tag" = "$commit" ]; then
  echo "Yes"
else
  echo "No"
fi