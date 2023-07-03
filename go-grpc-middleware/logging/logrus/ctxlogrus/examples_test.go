package ctxlogrus_test

import (
	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus/ctxlogrus"
	grpcctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"github.com/sirupsen/logrus"
)

//goland:noinspection GoUnusedGlobalVariable
var logrusLogger *logrus.Logger

// Simple unary handler that adds custom fields to the requests's context. These will be used for all log statements.
func ExampleExtract_unary() {
	ctx := context.Background()
	// setting tags will be added to the logger as log fields
	grpcctxtags.Extract(ctx).Set("custom_tags.string", "something").Set("custom_tags.int", 1337)
	// Extract a single request-scoped logrus.Logger and log messages.
	l := ctxlogrus.Extract(ctx)
	l.Info("some ping")
	l.Info("another ping")
}
