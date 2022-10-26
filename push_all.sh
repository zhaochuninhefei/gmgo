#!/bin/bash

echo "----- 所有远程仓库:"
git remote -v

echo "----- 向所有远程仓库推送..."
git push origin --all

echo "----- 结束"