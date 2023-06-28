package grpc_auth_test

import (
	grpc_auth "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/auth"
	grpc_ctxtags "gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/tags"
	"gitee.com/zhaochuninhefei/gmgo/grpc"
	"gitee.com/zhaochuninhefei/gmgo/grpc/codes"
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
		token, err := grpc_auth.AuthFromMD(ctx, "bearer")
		if err != nil {
			return nil, err
		}
		tokenInfo, err := parseToken(token)
		if err != nil {
			return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token: %v", err)
		}
		grpc_ctxtags.Extract(ctx).Set("auth.sub", userClaimFromToken(tokenInfo))
		newCtx := context.WithValue(ctx, "tokenInfo", tokenInfo)
		return newCtx, nil
	}

	_ = grpc.NewServer(
		grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(exampleAuthFunc)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(exampleAuthFunc)),
	)
}
