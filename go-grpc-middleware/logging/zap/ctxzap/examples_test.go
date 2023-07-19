package ctxzap_test

import (
	"context"

	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/zap/ctxzap"
	grpcctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	pbtestproto "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing/testproto"
	"go.uber.org/zap"
)

//goland:noinspection GoUnusedGlobalVariable
var zapLogger *zap.Logger

// Simple unary handler that adds custom fields to the requests's context. These will be used for all log statements.
func ExampleExtract_unary() {
	_ = func(ctx context.Context, ping *pbtestproto.PingRequest) (*pbtestproto.PingResponse, error) {
		// Add fields the ctxtags of the request which will be added to all extracted loggers.
		grpcctxtags.Extract(ctx).Set("custom_tags.string", "something").Set("custom_tags.int", 1337)

		// Extract a single request-scoped zap.Logger and log messages.
		l := ctxzap.Extract(ctx)
		l.Info("some ping")
		l.Info("another ping")
		return &pbtestproto.PingResponse{Value: ping.Value}, nil
	}
}
