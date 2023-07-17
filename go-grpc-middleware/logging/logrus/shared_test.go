package grpc_logrus_test

import (
	"bytes"
	"encoding/json"
	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus/ctxlogrus"
	"io"
	"testing"

	grpclogrus "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus"
	grpcctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	grpctesting "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing"
	pbtestproto "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing/testproto"
	"gitee.com/zhaochuninhefei/gmgo/grpc/codes"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"github.com/sirupsen/logrus"
)

var (
	goodPing = &pbtestproto.PingRequest{Value: "something", SleepTimeMs: 9999}
)

type loggingPingService struct {
	pbtestproto.TestServiceServer
}

func customCodeToLevel(c codes.Code) logrus.Level {
	if c == codes.Unauthenticated {
		// Make this a special case for tests, and an error.
		return logrus.ErrorLevel
	}
	level := grpclogrus.DefaultCodeToLevel(c)
	return level
}

func (s *loggingPingService) Ping(ctx context.Context, ping *pbtestproto.PingRequest) (*pbtestproto.PingResponse, error) {
	grpcctxtags.Extract(ctx).Set("custom_tags.string", "something").Set("custom_tags.int", 1337)
	// ctx_logrus.AddFields is deprecated, use the ctxlogrus.Extract instead.
	//ctx_logrus.AddFields(ctx, logrus.Fields{"custom_field": "custom_value"})
	ctxlogrus.AddFields(ctx, logrus.Fields{"custom_field": "custom_value"})
	// ctx_logrus.Extract is deprecated, use the ctxlogrus.Extract instead.
	//ctx_logrus.Extract(ctx).Info("some ping")
	ctxlogrus.Extract(ctx).Info("some ping")
	return s.TestServiceServer.Ping(ctx, ping)
}

func (s *loggingPingService) PingError(ctx context.Context, ping *pbtestproto.PingRequest) (*pbtestproto.Empty, error) {
	return s.TestServiceServer.PingError(ctx, ping)
}

func (s *loggingPingService) PingList(ping *pbtestproto.PingRequest, stream pbtestproto.TestService_PingListServer) error {
	grpcctxtags.Extract(stream.Context()).Set("custom_tags.string", "something").Set("custom_tags.int", 1337)
	// ctx_logrus.AddFields is deprecated, use the ctxlogrus.Extract instead.
	//ctx_logrus.AddFields(stream.Context(), logrus.Fields{"custom_field": "custom_value"})
	ctxlogrus.AddFields(stream.Context(), logrus.Fields{"custom_field": "custom_value"})
	// ctx_logrus.Extract is deprecated, use the ctxlogrus.Extract instead.
	//ctx_logrus.Extract(stream.Context()).Info("some pinglist")
	ctxlogrus.Extract(stream.Context()).Info("some pinglist")
	return s.TestServiceServer.PingList(ping, stream)
}

func (s *loggingPingService) PingEmpty(ctx context.Context, empty *pbtestproto.Empty) (*pbtestproto.PingResponse, error) {
	return s.TestServiceServer.PingEmpty(ctx, empty)
}

type logrusBaseSuite struct {
	*grpctesting.InterceptorTestSuite
	mutexBuffer *grpctesting.MutexReadWriter
	buffer      *bytes.Buffer
	logger      *logrus.Logger
}

func newLogrusBaseSuite(t *testing.T) *logrusBaseSuite {
	b := &bytes.Buffer{}
	muB := grpctesting.NewMutexReadWriter(b)
	logger := logrus.New()
	logger.Out = muB
	logger.Formatter = &logrus.JSONFormatter{DisableTimestamp: true}
	return &logrusBaseSuite{
		logger:      logger,
		buffer:      b,
		mutexBuffer: muB,
		InterceptorTestSuite: &grpctesting.InterceptorTestSuite{
			TestService: &loggingPingService{&grpctesting.TestPingService{T: t}},
		},
	}
}

func (s *logrusBaseSuite) SetupTest() {
	s.mutexBuffer.Lock()
	s.buffer.Reset()
	s.mutexBuffer.Unlock()
}

func (s *logrusBaseSuite) getOutputJSONs() []map[string]interface{} {
	ret := make([]map[string]interface{}, 0)
	dec := json.NewDecoder(s.mutexBuffer)

	for {
		var val map[string]interface{}
		err := dec.Decode(&val)
		if err == io.EOF {
			break
		}
		if err != nil {
			s.T().Fatalf("failed decoding output from Logrus JSON: %v", err)
		}

		ret = append(ret, val)
	}

	return ret
}
