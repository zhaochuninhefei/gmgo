package grpc_zap_test

import (
	"context"
	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/zap/ctxzap"
	"time"

	grpcmiddleware "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware"
	grpczap "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/zap"
	grpcctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	pbtestproto "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing/testproto"
	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	zapLogger  *zap.Logger
	customFunc grpczap.CodeToLevel
)

// Initialization shows a relatively complex initialization sequence.
func Example_initialization() {
	// Shared options for the logger, with a custom gRPC code to log level function.
	opts := []grpczap.Option{
		grpczap.WithLevels(customFunc),
	}
	// Make sure that log statements internal to gRPC library are logged using the zapLogger as well.
	grpczap.ReplaceGrpcLogger(zapLogger)
	// Create a server, make sure we put the grpc_ctxtags context before everything else.
	_ = grpc.NewServer(
		grpcmiddleware.WithUnaryServerChain(
			grpcctxtags.UnaryServerInterceptor(grpcctxtags.WithFieldExtractor(grpcctxtags.CodeGenRequestFieldExtractor)),
			grpczap.UnaryServerInterceptor(zapLogger, opts...),
		),
		grpcmiddleware.WithStreamServerChain(
			grpcctxtags.StreamServerInterceptor(grpcctxtags.WithFieldExtractor(grpcctxtags.CodeGenRequestFieldExtractor)),
			grpczap.StreamServerInterceptor(zapLogger, opts...),
		),
	)
}

// Initialization shows an initialization sequence with the duration field generation overridden.
func Example_initializationWithDurationFieldOverride() {
	opts := []grpczap.Option{
		grpczap.WithDurationField(func(duration time.Duration) zapcore.Field {
			return zap.Int64("grpc.time_ns", duration.Nanoseconds())
		}),
	}

	_ = grpc.NewServer(
		grpcmiddleware.WithUnaryServerChain(
			grpcctxtags.UnaryServerInterceptor(),
			grpczap.UnaryServerInterceptor(zapLogger, opts...),
		),
		grpcmiddleware.WithStreamServerChain(
			grpcctxtags.StreamServerInterceptor(),
			grpczap.StreamServerInterceptor(zapLogger, opts...),
		),
	)
}

// Simple unary handler that adds custom fields to the requests's context. These will be used for all log statements.
func ExampleExtract_unary() {
	_ = func(ctx context.Context, ping *pbtestproto.PingRequest) (*pbtestproto.PingResponse, error) {
		// Add fields the ctxtags of the request which will be added to all extracted loggers.
		grpcctxtags.Extract(ctx).Set("custom_tags.string", "something").Set("custom_tags.int", 1337)

		// Extract a single request-scoped zap.Logger and log messages. (containing the grpc.xxx tags)
		// ctx_zap.Extract is deprecated, use ctxzap.Extract instead.
		//l := ctx_zap.Extract(ctx)
		l := ctxzap.Extract(ctx)
		l.Info("some ping")
		l.Info("another ping")
		return &pbtestproto.PingResponse{Value: ping.Value}, nil
	}
}

func Example_initializationWithDecider() {
	opts := []grpczap.Option{
		grpczap.WithDecider(func(fullMethodName string, err error) bool {
			// will not log gRPC calls if it was a call to healthcheck and no error was raised
			if err == nil && fullMethodName == "foo.bar.healthcheck" {
				return false
			}

			// by default everything will be logged
			return true
		}),
	}

	_ = []grpc.ServerOption{
		grpcmiddleware.WithStreamServerChain(
			grpcctxtags.StreamServerInterceptor(),
			grpczap.StreamServerInterceptor(zap.NewNop(), opts...)),
		grpcmiddleware.WithUnaryServerChain(
			grpcctxtags.UnaryServerInterceptor(),
			grpczap.UnaryServerInterceptor(zap.NewNop(), opts...)),
	}
}
