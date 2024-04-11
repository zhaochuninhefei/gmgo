# 拉取最新代码
从`https://github.com/envoyproxy/go-control-plane`拉取main分支最新版本(bdba4bba15fc81508ab24d1239a607d6b7cbabb2):
```
$ git rev-parse HEAD
bdba4bba15fc81508ab24d1239a607d6b7cbabb2
```

# 替换import包路径
替换:
```
"github.com/envoyproxy/go-control-plane  -> "gitee.com/zhaochuninhefei/gmgo/go-control-plane

```

# 删除不需要的文件
删除非代码目录与文件。

# 删除不需要的代码
删除了目录`examples`及其下的所有代码。
