# 环境
确认已安装:
- protoc
- protoc-gen-go
- protoc-gen-go-grpc

确认命令:
```shell
protoc --version
# libprotoc 25.2

protoc-gen-go --version
# protoc-gen-go v1.32.0

protoc-gen-go-grpc --version
# protoc-gen-go-grpc 1.3.0
```

# 编译
```sh
cd <当前目录,如 gitee.com/zhaochuninhefei/gmgo/grpc/grpc_test/echo>

protoc --proto_path=./ --go_out=./ --go_opt=paths=source_relative --go-grpc_out=./ --go-grpc_opt=paths=source_relative echo.proto
```

# 一些修改
修改一下编译生成的`echo_grpc.pb.go`，防止`grpc_test`编译错误:

1. grpc模块依赖修改: `grpc "google.golang.org/grpc"`替换为`grpc "gitee.com/zhaochuninhefei/gmgo/grpc"`
2. `type EchoServer interface`接口定义中，注释掉`mustEmbedUnimplementedEchoServer()`

