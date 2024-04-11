`testv3.go` was generated with an older version of codegen, to test reflection
behavior with `grpc.SupportPackageIsVersion3`. DO NOT REGENERATE!

`testv3.go` was then manually edited to replace `"golang.org/x/net/context"`
with `"context"`.

`dynamic.go` was generated with a newer protoc and manually edited to remove
everything except the descriptor bytes var, which is renamed and exported.

> 2024/04/11 zhaochun: 为了将已废弃的"github.com/golang/protobuf/proto"替换为"google.golang.org/protobuf/proto"，这里重新生成了`testv3.proto`的golang代码`testv3.pb.go`，并将原来的`testv3.go`重命名为`testv3.go.bk`。
> 
> 编译命令:在当前目录下执行`protoc --proto_path=./ --go_out=./ --go_opt=paths=source_relative testv3.proto`