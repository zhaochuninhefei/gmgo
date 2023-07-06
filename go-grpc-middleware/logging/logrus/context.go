package grpc_logrus

import (
	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus/ctxlogrus"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"github.com/sirupsen/logrus"
)

// AddFields adds logrus fields to the logger.
// Deprecated: should use the ctxlogrus.Extract instead
//goland:noinspection GoUnusedExportedFunction
func AddFields(ctx context.Context, fields logrus.Fields) {
	ctxlogrus.AddFields(ctx, fields)
}

// Extract takes the call-scoped logrus.Entry from grpc_logrus middleware.
// Deprecated: should use the ctxlogrus.Extract instead
//goland:noinspection GoUnusedExportedFunction
func Extract(ctx context.Context) *logrus.Entry {
	return ctxlogrus.Extract(ctx)
}
