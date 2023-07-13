package grpc_logrus_test

import (
	"io"
	"io/ioutil"
	"runtime"
	"strings"
	"testing"

	grpcmiddleware "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware"
	grpclogrus "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/logging/logrus"
	grpcctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	pbtestproto "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing/testproto"
	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	nullLogger = &logrus.Logger{
		Out:       ioutil.Discard,
		Formatter: new(logrus.TextFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.PanicLevel,
	}
)

func TestLogrusPayloadSuite(t *testing.T) {
	if strings.HasPrefix(runtime.Version(), "go1.7") {
		t.Skipf("Skipping due to json.RawMessage incompatibility with go1.7")
		return
	}
	alwaysLoggingDeciderServer := func(ctx context.Context, fullMethodName string, servingObject interface{}) bool { return true }
	alwaysLoggingDeciderClient := func(ctx context.Context, fullMethodName string) bool { return true }
	b := newLogrusBaseSuite(t)
	b.InterceptorTestSuite.ClientOpts = []grpc.DialOption{
		grpc.WithUnaryInterceptor(grpclogrus.PayloadUnaryClientInterceptor(logrus.NewEntry(b.logger), alwaysLoggingDeciderClient)),
		grpc.WithStreamInterceptor(grpclogrus.PayloadStreamClientInterceptor(logrus.NewEntry(b.logger), alwaysLoggingDeciderClient)),
	}
	b.InterceptorTestSuite.ServerOpts = []grpc.ServerOption{
		grpcmiddleware.WithStreamServerChain(
			grpcctxtags.StreamServerInterceptor(grpcctxtags.WithFieldExtractor(grpcctxtags.CodeGenRequestFieldExtractor)),
			grpclogrus.StreamServerInterceptor(logrus.NewEntry(nullLogger)),
			grpclogrus.PayloadStreamServerInterceptor(logrus.NewEntry(b.logger), alwaysLoggingDeciderServer)),
		grpcmiddleware.WithUnaryServerChain(
			grpcctxtags.UnaryServerInterceptor(grpcctxtags.WithFieldExtractor(grpcctxtags.CodeGenRequestFieldExtractor)),
			grpclogrus.UnaryServerInterceptor(logrus.NewEntry(nullLogger)),
			grpclogrus.PayloadUnaryServerInterceptor(logrus.NewEntry(b.logger), alwaysLoggingDeciderServer)),
	}
	suite.Run(t, &logrusPayloadSuite{b})
}

type logrusPayloadSuite struct {
	*logrusBaseSuite
}

func (s *logrusPayloadSuite) getServerAndClientMessages(expectedServer int, expectedClient int) (serverMsgs []map[string]interface{}, clientMsgs []map[string]interface{}) {
	msgs := s.getOutputJSONs()
	for _, m := range msgs {
		if m["span.kind"] == "server" {
			serverMsgs = append(serverMsgs, m)
		} else if m["span.kind"] == "client" {
			clientMsgs = append(clientMsgs, m)
		}
	}

	require.Len(s.T(), serverMsgs, expectedServer, "must match expected number of server log messages")
	require.Len(s.T(), clientMsgs, expectedClient, "must match expected number of client log messages")
	return serverMsgs, clientMsgs
}

func (s *logrusPayloadSuite) TestPing_LogsBothRequestAndResponse() {
	_, err := s.Client.Ping(s.SimpleCtx(), goodPing)
	require.NoError(s.T(), err, "there must be not be an on a successful call")
	serverMsgs, clientMsgs := s.getServerAndClientMessages(2, 2)

	for _, m := range append(serverMsgs, clientMsgs...) {
		assert.Equal(s.T(), m["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
		assert.Equal(s.T(), m["grpc.method"], "Ping", "all lines must contain the correct method name")
		assert.Equal(s.T(), m["level"], "info", "all lines must contain method name")
	}

	serverReq, serverResp := serverMsgs[0], serverMsgs[1]
	clientReq, clientResp := clientMsgs[0], clientMsgs[1]
	assert.Contains(s.T(), clientReq, "grpc.request.content", "request payload must be logged in a structured way")
	assert.Contains(s.T(), serverReq, "grpc.request.content", "request payload must be logged in a structured way")
	assert.Contains(s.T(), clientResp, "grpc.response.content", "response payload must be logged in a structured way")
	assert.Contains(s.T(), serverResp, "grpc.response.content", "response payload must be logged in a structured way")
}

func (s *logrusPayloadSuite) TestPingError_LogsOnlyRequestsOnError() {
	_, err := s.Client.PingError(s.SimpleCtx(), &pbtestproto.PingRequest{Value: "something", ErrorCodeReturned: uint32(4)})
	require.Error(s.T(), err, "there must be not be an error on a successful call")

	serverMsgs, clientMsgs := s.getServerAndClientMessages(1, 1)
	for _, m := range append(serverMsgs, clientMsgs...) {
		assert.Equal(s.T(), m["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
		assert.Equal(s.T(), m["grpc.method"], "PingError", "all lines must contain the correct method name")
		assert.Equal(s.T(), m["level"], "info", "all lines must be logged at info level")
	}

	assert.Contains(s.T(), clientMsgs[0], "grpc.request.content", "request payload must be logged by the client")
	assert.Contains(s.T(), serverMsgs[0], "grpc.request.content", "request payload must be logged by the server")
}

func (s *logrusPayloadSuite) TestPingStream_LogsAllRequestsAndResponses() {
	messagesExpected := 20
	stream, err := s.Client.PingStream(s.SimpleCtx())
	require.NoError(s.T(), err, "no error on stream creation")
	for i := 0; i < messagesExpected; i++ {
		require.NoError(s.T(), stream.Send(goodPing), "sending must succeed")
	}
	require.NoError(s.T(), stream.CloseSend(), "no error on close of stream")

	for {
		pong := &pbtestproto.PingResponse{}
		err := stream.RecvMsg(pong)
		if err == io.EOF {
			break
		}
		require.NoError(s.T(), err, "no error on receive")
	}
	serverMsgs, clientMsgs := s.getServerAndClientMessages(2*messagesExpected, 2*messagesExpected)
	for _, m := range append(serverMsgs, clientMsgs...) {
		assert.Equal(s.T(), m["grpc.service"], "mwitkow.testproto.TestService", "all lines must contain the correct service name")
		assert.Equal(s.T(), m["grpc.method"], "PingStream", "all lines must contain the correct method name")
		assert.Equal(s.T(), m["level"], "info", "all lines must be at info log level")

		content := m["grpc.request.content"] != nil || m["grpc.response.content"] != nil
		assert.True(s.T(), content, "all messages must contain a payload")
	}
}
