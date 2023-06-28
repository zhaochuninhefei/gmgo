package grpc_auth_test

import (
	grpcauth "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/auth"
	grpcctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"gitee.com/zhaochuninhefei/gmgo/grpc/codes"
	"gitee.com/zhaochuninhefei/gmgo/grpc/status"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
)

//goland:noinspection GoUnusedGlobalVariable
var (
	cc *grpc.ClientConn
)

//goland:noinspection GoUnusedParameter
func parseToken(token string) (struct{}, error) {
	return struct{}{}, nil
}

//goland:noinspection GoUnusedParameter
func userClaimFromToken(struct{}) string {
	return "foobar"
}

// Simple example of server initialization code.
func Example_serverConfig() {
	exampleAuthFunc := func(ctx context.Context) (context.Context, error) {
		token, err := grpcauth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return nil, err
		}
		tokenInfo, err := parseToken(token)
		if err != nil {
			// grpc.Errorf is deprecated. Use status.Errorf instead.
			//return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
			return nil, status.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
		}
		grpcctxtags.Extract(ctx).Set("auth.sub", userClaimFromToken(tokenInfo))
		newCtx := context.WithValue(ctx, "tokenInfo", tokenInfo)
		return newCtx, nil
	}

	_ = grpc.NewServer(
		grpc.StreamInterceptor(grpcauth.StreamServerInterceptor(exampleAuthFunc)),
		grpc.UnaryInterceptor(grpcauth.UnaryServerInterceptor(exampleAuthFunc)),
	)
}
