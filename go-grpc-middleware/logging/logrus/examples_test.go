package grpc_logrus_test

import (
	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus/ctxlogrus"
	"time"

	grpcmiddleware "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware"
	grpclogrus "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus"
	grpcctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	pbtestproto "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing/testproto"
	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"github.com/sirupsen/logrus"
)

var (
	logrusLogger *logrus.Logger
	customFunc   grpclogrus.CodeToLevel
)

// Initialization shows a relatively complex initialization sequence.
func Example_initialization() {
	// Logrus entry is used, allowing pre-definition of certain fields by the user.
	logrusEntry := logrus.NewEntry(logrusLogger)
	// Shared options for the logger, with a custom gRPC code to log level function.
	opts := []grpclogrus.Option{
		grpclogrus.WithLevels(customFunc),
	}
	// Make sure that log statements internal to gRPC library are logged using the logrus Logger as well.
	grpclogrus.ReplaceGrpcLogger(logrusEntry)
	// Create a server, make sure we put the grpc_ctxtags context before everything else.
	_ = grpc.NewServer(
		grpcmiddleware.WithUnaryServerChain(
			grpcctxtags.UnaryServerInterceptor(grpcctxtags.WithFieldExtractor(grpcctxtags.CodeGenRequestFieldExtractor)),
			grpclogrus.UnaryServerInterceptor(logrusEntry, opts...),
		),
		grpcmiddleware.WithStreamServerChain(
			grpcctxtags.StreamServerInterceptor(grpcctxtags.WithFieldExtractor(grpcctxtags.CodeGenRequestFieldExtractor)),
			grpclogrus.StreamServerInterceptor(logrusEntry, opts...),
		),
	)
}

func Example_initializationWithDurationFieldOverride() {
	// Logrus entry is used, allowing pre-definition of certain fields by the user.
	logrusEntry := logrus.NewEntry(logrusLogger)
	// Shared options for the logger, with a custom duration to log field function.
	opts := []grpclogrus.Option{
		grpclogrus.WithDurationField(func(duration time.Duration) (key string, value interface{}) {
			return "grpc.time_ns", duration.Nanoseconds()
		}),
	}
	_ = grpc.NewServer(
		grpcmiddleware.WithUnaryServerChain(
			grpcctxtags.UnaryServerInterceptor(),
			grpclogrus.UnaryServerInterceptor(logrusEntry, opts...),
		),
		grpcmiddleware.WithStreamServerChain(
			grpcctxtags.StreamServerInterceptor(),
			grpclogrus.StreamServerInterceptor(logrusEntry, opts...),
		),
	)
}

// Simple unary handler that adds custom fields to the requests's context. These will be used for all log statements.
func ExampleExtract_unary() {
	_ = func(ctx context.Context, ping *pbtestproto.PingRequest) (*pbtestproto.PingResponse, error) {
		// Add fields the ctxtags of the request which will be added to all extracted loggers.
		grpcctxtags.Extract(ctx).Set("custom_tags.string", "something").Set("custom_tags.int", 1337)
		// Extract a single request-scoped logrus.Logger and log messages.
		// ctx_logrus.Extract is deprecated, use the ctxlogrus.Extract instead.
		//l := ctx_logrus.Extract(ctx)
		l := ctxlogrus.Extract(ctx)
		l.Info("some ping")
		l.Info("another ping")
		return &pbtestproto.PingResponse{Value: ping.Value}, nil
	}
}

func ExampleWithDecider() {
	opts := []grpclogrus.Option{
		grpclogrus.WithDecider(func(methodFullName string, err error) bool {
			// will not log gRPC calls if it was a call to healthcheck and no error was raised
			if err == nil && methodFullName == "blah.foo.healthcheck" {
				return false
			}

			// by default you will log all calls
			return true
		}),
	}

	_ = []grpc.ServerOption{
		grpcmiddleware.WithStreamServerChain(
			grpcctxtags.StreamServerInterceptor(),
			grpclogrus.StreamServerInterceptor(logrus.NewEntry(logrus.New()), opts...)),
		grpcmiddleware.WithUnaryServerChain(
			grpcctxtags.UnaryServerInterceptor(),
			grpclogrus.UnaryServerInterceptor(logrus.NewEntry(logrus.New()), opts...)),
	}
}
