// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package grpc_auth_test

import (
	"gitee.com/zhaochuninhefei/gmgo/grpc/status"
	"testing"

	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"github.com/stretchr/testify/suite"

	"fmt"

	"time"

	grpcauth "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/auth"
	grpctesting "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing"
	pbtestproto "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/testing/testproto"
	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/util/metautils"
	"gitee.com/zhaochuninhefei/gmgo/grpc/codes"
	"gitee.com/zhaochuninhefei/gmgo/grpc/credentials/oauth"
	"gitee.com/zhaochuninhefei/gmgo/grpc/metadata"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

var (
	commonAuthToken   = "some_good_token"
	overrideAuthToken = "override_token"

	authedMarker = "some_context_marker"
	goodPing     = &pbtestproto.PingRequest{Value: "something", SleepTimeMs: 9999}
)

// TODO(mwitkow): Add auth from metadata client dialer, which requires TLS.

func buildDummyAuthFunction(expectedScheme string, expectedToken string) func(ctx context.Context) (context.Context, error) {
	return func(ctx context.Context) (context.Context, error) {
		token, err := grpcauth.AuthFromMD(ctx, expectedScheme)
		if err != nil {
			return nil, err
		}
		if token != expectedToken {
			// `grpc.Errorf` is deprecated. use status.Errorf instead.
			//return nil, grpc.Errorf(codes.PermissionDenied, "buildDummyAuthFunction bad token")
			return nil, status.Errorf(codes.PermissionDenied, "buildDummyAuthFunction bad token")
		}
		return context.WithValue(ctx, authedMarker, "marker_exists"), nil
	}
}

func assertAuthMarkerExists(t *testing.T, ctx context.Context) {
	assert.Equal(t, "marker_exists", ctx.Value(authedMarker).(string), "auth marker from buildDummyAuthFunction must be passed around")
}

type assertingPingService struct {
	pbtestproto.TestServiceServer
	T *testing.T
}

func (s *assertingPingService) PingError(ctx context.Context, ping *pbtestproto.PingRequest) (*pbtestproto.Empty, error) {
	assertAuthMarkerExists(s.T, ctx)
	return s.TestServiceServer.PingError(ctx, ping)
}

func (s *assertingPingService) PingList(ping *pbtestproto.PingRequest, stream pbtestproto.TestService_PingListServer) error {
	assertAuthMarkerExists(s.T, stream.Context())
	return s.TestServiceServer.PingList(ping, stream)
}

func ctxWithToken(ctx context.Context, scheme string, token string) context.Context {
	md := metadata.Pairs("authorization", fmt.Sprintf("%s %v", scheme, token))
	nCtx := metautils.NiceMD(md).ToOutgoing(ctx)
	return nCtx
}

func TestAuthTestSuite(t *testing.T) {
	authFunc := buildDummyAuthFunction("bearer", commonAuthToken)
	s := &AuthTestSuite{
		InterceptorTestSuite: &grpctesting.InterceptorTestSuite{
			TestService: &assertingPingService{&grpctesting.TestPingService{T: t}, t},
			ServerOpts: []grpc.ServerOption{
				grpc.StreamInterceptor(grpcauth.StreamServerInterceptor(authFunc)),
				grpc.UnaryInterceptor(grpcauth.UnaryServerInterceptor(authFunc)),
			},
		},
	}
	suite.Run(t, s)
}

type AuthTestSuite struct {
	*grpctesting.InterceptorTestSuite
}

func (s *AuthTestSuite) TestUnary_NoAuth() {
	_, err := s.Client.Ping(s.SimpleCtx(), goodPing)
	assert.Error(s.T(), err, "there must be an error")
	// `grpc.Code` is deprecated. Use `status.Code` instead.
	//assert.Equal(s.T(), codes.Unauthenticated, grpc.Code(err), "must error with unauthenticated")
	assert.Equal(s.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (s *AuthTestSuite) TestUnary_BadAuth() {
	_, err := s.Client.Ping(ctxWithToken(s.SimpleCtx(), "bearer", "bad_token"), goodPing)
	assert.Error(s.T(), err, "there must be an error")
	// `grpc.Code` is deprecated. Use `status.Code` instead.
	//assert.Equal(s.T(), codes.PermissionDenied, grpc.Code(err), "must error with permission denied")
	assert.Equal(s.T(), codes.PermissionDenied, status.Code(err), "must error with permission denied")
}

func (s *AuthTestSuite) TestUnary_PassesAuth() {
	_, err := s.Client.Ping(ctxWithToken(s.SimpleCtx(), "bearer", commonAuthToken), goodPing)
	require.NoError(s.T(), err, "no error must occur")
}

func (s *AuthTestSuite) TestUnary_PassesWithPerRpcCredentials() {
	grpcCreds := oauth.TokenSource{TokenSource: &fakeOAuth2TokenSource{accessToken: commonAuthToken}}
	client := s.NewClient(grpc.WithPerRPCCredentials(grpcCreds))
	_, err := client.Ping(s.SimpleCtx(), goodPing)
	require.NoError(s.T(), err, "no error must occur")
}

func (s *AuthTestSuite) TestStream_NoAuth() {
	stream, err := s.Client.PingList(s.SimpleCtx(), goodPing)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	_, err = stream.Recv()
	assert.Error(s.T(), err, "there must be an error")
	// `grpc.Code` is deprecated. Use `status.Code` instead.
	//assert.Equal(s.T(), codes.Unauthenticated, grpc.Code(err), "must error with unauthenticated")
	assert.Equal(s.T(), codes.Unauthenticated, status.Code(err), "must error with unauthenticated")
}

func (s *AuthTestSuite) TestStream_BadAuth() {
	stream, err := s.Client.PingList(ctxWithToken(s.SimpleCtx(), "bearer", "bad_token"), goodPing)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	_, err = stream.Recv()
	assert.Error(s.T(), err, "there must be an error")
	// `grpc.Code` is deprecated. Use `status.Code` instead.
	//assert.Equal(s.T(), codes.PermissionDenied, grpc.Code(err), "must error with permission denied")
	assert.Equal(s.T(), codes.PermissionDenied, status.Code(err), "must error with permission denied")
}

func (s *AuthTestSuite) TestStream_PassesAuth() {
	stream, err := s.Client.PingList(ctxWithToken(s.SimpleCtx(), "Bearer", commonAuthToken), goodPing)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	pong, err := stream.Recv()
	require.NoError(s.T(), err, "no error must occur")
	require.NotNil(s.T(), pong, "pong must not be nil")
}

func (s *AuthTestSuite) TestStream_PassesWithPerRpcCredentials() {
	grpcCreds := oauth.TokenSource{TokenSource: &fakeOAuth2TokenSource{accessToken: commonAuthToken}}
	client := s.NewClient(grpc.WithPerRPCCredentials(grpcCreds))
	stream, err := client.PingList(s.SimpleCtx(), goodPing)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	pong, err := stream.Recv()
	require.NoError(s.T(), err, "no error must occur")
	require.NotNil(s.T(), pong, "pong must not be nil")
}

type authOverrideTestService struct {
	pbtestproto.TestServiceServer
	T *testing.T
}

func (s *authOverrideTestService) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	assert.NotEmpty(s.T, fullMethodName, "method name of caller is passed around")
	return buildDummyAuthFunction("bearer", overrideAuthToken)(ctx)
}

func TestAuthOverrideTestSuite(t *testing.T) {
	authFunc := buildDummyAuthFunction("bearer", commonAuthToken)
	s := &AuthOverrideTestSuite{
		InterceptorTestSuite: &grpctesting.InterceptorTestSuite{
			TestService: &authOverrideTestService{&assertingPingService{&grpctesting.TestPingService{T: t}, t}, t},
			ServerOpts: []grpc.ServerOption{
				grpc.StreamInterceptor(grpcauth.StreamServerInterceptor(authFunc)),
				grpc.UnaryInterceptor(grpcauth.UnaryServerInterceptor(authFunc)),
			},
		},
	}
	suite.Run(t, s)
}

type AuthOverrideTestSuite struct {
	*grpctesting.InterceptorTestSuite
}

func (s *AuthOverrideTestSuite) TestUnary_PassesAuth() {
	_, err := s.Client.Ping(ctxWithToken(s.SimpleCtx(), "bearer", overrideAuthToken), goodPing)
	require.NoError(s.T(), err, "no error must occur")
}

func (s *AuthOverrideTestSuite) TestStream_PassesAuth() {
	stream, err := s.Client.PingList(ctxWithToken(s.SimpleCtx(), "Bearer", overrideAuthToken), goodPing)
	require.NoError(s.T(), err, "should not fail on establishing the stream")
	pong, err := stream.Recv()
	require.NoError(s.T(), err, "no error must occur")
	require.NotNil(s.T(), pong, "pong must not be nil")
}

// fakeOAuth2TokenSource implements a fake oauth2.TokenSource for the purpose of credentials test.
type fakeOAuth2TokenSource struct {
	accessToken string
}

func (ts *fakeOAuth2TokenSource) Token() (*oauth2.Token, error) {
	t := &oauth2.Token{
		AccessToken: ts.accessToken,
		Expiry:      time.Now().Add(1 * time.Minute),
		TokenType:   "bearer",
	}
	return t, nil
}
