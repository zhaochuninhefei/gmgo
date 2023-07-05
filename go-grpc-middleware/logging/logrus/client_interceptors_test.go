package grpc_logrus_test

import (
	"io"
	"runtime"
	"strings"
	"testing"

	grpclogrus "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus"
	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"gitee.com/zhaochuninhefei/gmgo/grpc/codes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	pbtestproto "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing/testproto"
)

func customClientCodeToLevel(c codes.Code) logrus.Level {
	if c == codes.Unauthenticated {
		// Make this a special case for tests, and an error.
		return logrus.ErrorLevel
	}
	level := grpclogrus.DefaultClientCodeToLevel(c)
	return level
}

func TestLogrusClientSuite(t *testing.T) {
	if strings.HasPrefix(runtime.Version(), "go1.7") {
		t.Skipf("Skipping due to json.RawMessage incompatibility with go1.7")
		return
	}
	opts := []grpclogrus.Option{
		grpclogrus.WithLevels(customClientCodeToLevel),
	}
	b := newLogrusBaseSuite(t)
	b.logger.Level = logrus.DebugLevel // a lot of our stuff is on debug level by default
	b.InterceptorTestSuite.ClientOpts = []grpc.DialOption{
		grpc.WithUnaryInterceptor(grpclogrus.UnaryClientInterceptor(logrus.NewEntry(b.logger), opts...)),
		grpc.WithStreamInterceptor(grpclogrus.StreamClientInterceptor(logrus.NewEntry(b.logger), opts...)),
	}
	suite.Run(t, &logrusClientSuite{b})
}

type logrusClientSuite struct {
	*logrusBaseSuite
}

func (s *logrusClientSuite) TestPing() {
	_, err := s.Client.Ping(s.SimpleCtx(), goodPing)
	assert.NoError(s.T(), err, "there must be not be an on a successful call")

	msgs := s.getOutputJSONs()
	require.Len(s.T(), msgs, 1, "one log statement should be logged")

	assert.Equal(s.T(), msgs[0]["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
	assert.Equal(s.T(), msgs[0]["grpc.method"], "Ping", "all lines must contain the correct method name")
	assert.Equal(s.T(), msgs[0]["msg"], "finished client unary call", "handler's message must contain the correct message")
	assert.Equal(s.T(), msgs[0]["span.kind"], "client", "all lines must contain the kind of call (client)")
	assert.Equal(s.T(), msgs[0]["level"], "debug", "OK codes must be logged on debug level.")

	assert.Contains(s.T(), msgs[0], "grpc.time_ms", "interceptor log statement should contain execution time (duration in ms)")
}

func (s *logrusClientSuite) TestPingList() {
	stream, err := s.Client.PingList(s.SimpleCtx(), goodPing)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(s.T(), err, "reading stream should not fail")
	}

	msgs := s.getOutputJSONs()
	require.Len(s.T(), msgs, 1, "one log statement should be logged")

	assert.Equal(s.T(), msgs[0]["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
	assert.Equal(s.T(), msgs[0]["grpc.method"], "PingList", "all lines must contain the correct method name")
	assert.Equal(s.T(), msgs[0]["msg"], "finished client streaming call", "handler's message must contain the correct message")
	assert.Equal(s.T(), msgs[0]["span.kind"], "client", "all lines must contain the kind of call (client)")
	assert.Equal(s.T(), msgs[0]["level"], "debug", "OK codes must be logged on debug level.")
	assert.Contains(s.T(), msgs[0], "grpc.time_ms", "interceptor log statement should contain execution time (duration in ms)")
}

func (s *logrusClientSuite) TestPingError_WithCustomLevels() {
	for _, tcase := range []struct {
		code  codes.Code
		level logrus.Level
		msg   string
	}{
		{
			code:  codes.Internal,
			level: logrus.WarnLevel,
			msg:   "Internal must remap to ErrorLevel in DefaultClientCodeToLevel",
		},
		{
			code:  codes.NotFound,
			level: logrus.DebugLevel,
			msg:   "NotFound must remap to InfoLevel in DefaultClientCodeToLevel",
		},
		{
			code:  codes.FailedPrecondition,
			level: logrus.DebugLevel,
			msg:   "FailedPrecondition must remap to WarnLevel in DefaultClientCodeToLevel",
		},
		{
			code:  codes.Unauthenticated,
			level: logrus.ErrorLevel,
			msg:   "Unauthenticated is overwritten to ErrorLevel with customClientCodeToLevel override, which probably didn't work",
		},
	} {
		s.SetupTest()
		_, err := s.Client.PingError(
			s.SimpleCtx(),
			&pbtestproto.PingRequest{Value: "something", ErrorCodeReturned: uint32(tcase.code)})

		assert.Error(s.T(), err, "each call here must return an error")

		msgs := s.getOutputJSONs()
		require.Len(s.T(), msgs, 1, "only a single log message is printed")

		assert.Equal(s.T(), msgs[0]["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
		assert.Equal(s.T(), msgs[0]["grpc.method"], "PingError", "all lines must contain the correct method name")
		assert.Equal(s.T(), msgs[0]["grpc.code"], tcase.code.String(), "all lines must contain a grpc code")
		assert.Equal(s.T(), msgs[0]["level"], tcase.level.String(), tcase.msg)
	}
}

func TestLogrusClientOverrideSuite(t *testing.T) {
	if strings.HasPrefix(runtime.Version(), "go1.7") {
		t.Skip("Skipping due to json.RawMessage incompatibility with go1.7")
		return
	}
	opts := []grpclogrus.Option{
		grpclogrus.WithDurationField(grpclogrus.DurationToDurationField),
	}
	b := newLogrusBaseSuite(t)
	b.logger.Level = logrus.DebugLevel // a lot of our stuff is on debug level by default
	b.InterceptorTestSuite.ClientOpts = []grpc.DialOption{
		grpc.WithUnaryInterceptor(grpclogrus.UnaryClientInterceptor(logrus.NewEntry(b.logger), opts...)),
		grpc.WithStreamInterceptor(grpclogrus.StreamClientInterceptor(logrus.NewEntry(b.logger), opts...)),
	}
	suite.Run(t, &logrusClientOverrideSuite{b})
}

type logrusClientOverrideSuite struct {
	*logrusBaseSuite
}

func (s *logrusClientOverrideSuite) TestPing_HasOverrides() {
	_, err := s.Client.Ping(s.SimpleCtx(), goodPing)
	assert.NoError(s.T(), err, "there must be not be an on a successful call")

	msgs := s.getOutputJSONs()
	require.Len(s.T(), msgs, 1, "one log statement should be logged")
	assert.Equal(s.T(), msgs[0]["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
	assert.Equal(s.T(), msgs[0]["grpc.method"], "Ping", "all lines must contain the correct method name")
	assert.Equal(s.T(), msgs[0]["msg"], "finished client unary call", "handler's message must contain the correct message")

	assert.NotContains(s.T(), msgs[0], "grpc.time_ms", "message must not contain default duration")
	assert.Contains(s.T(), msgs[0], "grpc.duration", "message must contain overridden duration")
}

func (s *logrusClientOverrideSuite) TestPingList_HasOverrides() {
	stream, err := s.Client.PingList(s.SimpleCtx(), goodPing)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(s.T(), err, "reading stream should not fail")
	}

	msgs := s.getOutputJSONs()
	require.Len(s.T(), msgs, 1, "one log statement should be logged")

	assert.Equal(s.T(), msgs[0]["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
	assert.Equal(s.T(), msgs[0]["grpc.method"], "PingList", "all lines must contain the correct method name")
	assert.Equal(s.T(), msgs[0]["msg"], "finished client streaming call", "log message must be correct")
	assert.Equal(s.T(), msgs[0]["span.kind"], "client", "all lines must contain the kind of call (client)")
	assert.Equal(s.T(), msgs[0]["level"], "debug", "OK codes must be logged on debug level.")

	assert.NotContains(s.T(), msgs[0], "grpc.time_ms", "message must not contain default duration")
	assert.Contains(s.T(), msgs[0], "grpc.duration", "message must contain overridden duration")
}
