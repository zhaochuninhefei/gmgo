#!/bin/bash

set -e

echo '===== go mod tidy ====='
go mod tidy

echo
echo '===== make ====='
make

echo '===== build success ====='
echo