#!/bin/bash

set -e

registry_origin=origin
registry_gitee=gitee
#remote_url_gitee=git@gitee.com:zhaochuninhefei/gmgo.git
#remote_url_github=git@github.com:zhaochuninhefei/gmgo.git

echo
echo "当前远程仓库地址:"
git remote -v

echo
read -r -p "请选择准备拉取的远程仓库(默认: ${registry_origin}):" remote_sel
if [ "${remote_sel}" == "" ]
then
  remote_sel=${registry_origin}
fi
echo
echo "目标远程仓库分支:"
git branch -r | grep "${remote_sel}"
echo
read -r -p "请选择准备拉取的远程仓库分支(默认: master, 不要携带仓库名):" registry_branch
if [ "${registry_branch}" == "" ]
then
  registry_branch=master
fi
echo
echo "=========="
echo "您选择拉取: ${remote_sel} ${registry_branch}"
echo
read -r -p "请确定是否无误，是否继续?(y/n) " goon
if [ ! "$goon" == "y" ]
then
  exit 1
fi
echo
echo "开始拉取(git pull ${remote_sel} ${registry_branch})..."
git pull "${remote_sel}" "${registry_branch}"
echo
echo "拉取结束."
echo
