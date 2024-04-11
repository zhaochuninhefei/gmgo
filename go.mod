module gitee.com/zhaochuninhefei/gmgo

go 1.22

require (
	gitee.com/zhaochuninhefei/zcgolog v0.0.23
	github.com/census-instrumentation/opencensus-proto v0.4.1
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/cncf/xds/go v0.0.0-20240329184929-0c46c01016dc
	github.com/envoyproxy/protoc-gen-validate v1.0.4
	github.com/golang/glog v1.2.1
	github.com/google/go-cmp v0.6.0
	github.com/google/uuid v1.6.0
	github.com/matttproud/golang_protobuf_extensions v1.0.3 // 这里不要将v1.0.3升级到v1.0.4，否则会间接依赖`github.com/golang/protobuf`(老版的protobuf,与新版`google.golang.org/protobuf`互不兼容)
	github.com/opentracing/opentracing-go v1.2.0
	github.com/planetscale/vtprotobuf v0.6.0
	github.com/prometheus/client_golang v1.19.0
	github.com/prometheus/client_model v0.6.1
	github.com/prometheus/common v0.52.3
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	go.opentelemetry.io/proto/otlp v1.2.0
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.22.0
	golang.org/x/net v0.24.0
	golang.org/x/oauth2 v0.19.0
	golang.org/x/sync v0.6.0
	golang.org/x/sys v0.19.0
	golang.org/x/term v0.19.0
	golang.org/x/text v0.14.0
	google.golang.org/genproto/googleapis/api v0.0.0-20240401170217-c3f982113cda
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240401170217-c3f982113cda
	google.golang.org/grpc v1.63.2
	google.golang.org/protobuf v1.33.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	cel.dev/expr v0.15.0 // indirect
	cloud.google.com/go/compute v1.25.1 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.13.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
