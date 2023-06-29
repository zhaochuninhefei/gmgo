// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package grpc_auth

import (
	"gitee.com/zhaochuninhefei/gmgo/grpc/status"
	"strings"

	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/util/metautils"
	"gitee.com/zhaochuninhefei/gmgo/grpc/codes"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
)

var (
	headerAuthorize = "authorization"
)

// AuthFromMD is a helper function for extracting the :authorization header from the gRPC metadata of the request.
//
// It expects the `:authorization` header to be of a certain scheme (e.g. `basic`, `bearer`), in a
// case-insensitive format (see rfc2617, sec 1.2). If no such authorization is found, or the token
// is of wrong scheme, an error with gRPC status `Unauthenticated` is returned.
func AuthFromMD(ctx context.Context, expectedScheme string) (string, error) {
	val := metautils.ExtractIncoming(ctx).Get(headerAuthorize)
	if val == "" {
		// `grpc.Errorf` is deprecated. use status.Errorf instead.
		//return "", grpc.Errorf(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
		return "", status.Errorf(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
	}
	splits := strings.SplitN(val, " ", 2)
	if len(splits) < 2 {
		// `grpc.Errorf` is deprecated. use status.Errorf instead.
		//return "", grpc.Errorf(codes.Unauthenticated, "Bad authorization string")
		return "", status.Errorf(codes.Unauthenticated, "Bad authorization string")
	}
	if strings.ToLower(splits[0]) != strings.ToLower(expectedScheme) {
		// `grpc.Errorf` is deprecated. use status.Errorf instead.
		//return "", grpc.Errorf(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
		return "", status.Errorf(codes.Unauthenticated, "Request unauthenticated with "+expectedScheme)
	}
	return splits[1], nil
}
