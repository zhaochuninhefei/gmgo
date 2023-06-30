// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package grpc_auth

import (
	"gitee.com/zhaochuninhefei/gmgo/grpc/status"
	"testing"

	"gitee.com/zhaochuninhefei/gmgo/go-grpc-middleware/util/metautils"
	"gitee.com/zhaochuninhefei/gmgo/grpc/codes"
	"gitee.com/zhaochuninhefei/gmgo/grpc/metadata"
	"gitee.com/zhaochuninhefei/gmgo/net/context"
	"github.com/stretchr/testify/assert"
)

func TestAuthFromMD(t *testing.T) {
	for _, run := range []struct {
		md      metadata.MD
		value   string
		errCode codes.Code
		msg     string
	}{
		{
			md:    metadata.Pairs("authorization", "bearer some_token"),
			value: "some_token",
			msg:   "must extract simple bearer tokens without case checking",
		},
		{
			md:    metadata.Pairs("authorization", "Bearer some_token"),
			value: "some_token",
			msg:   "must extract simple bearer tokens with case checking",
		},
		{
			md:    metadata.Pairs("authorization", "Bearer some multi string bearer"),
			value: "some multi string bearer",
			msg:   "must handle string based bearers",
		},
		{
			md:      metadata.Pairs("authorization", "Basic login:passwd"),
			value:   "",
			errCode: codes.Unauthenticated,
			msg:     "must check authentication type",
		},
		{
			md:      metadata.Pairs("authorization", "Basic login:passwd", "authorization", "bearer some_token"),
			value:   "",
			errCode: codes.Unauthenticated,
			msg:     "must not allow multiple authentication methods",
		},
		{
			md:      metadata.Pairs("authorization", ""),
			value:   "",
			errCode: codes.Unauthenticated,
			msg:     "authorization string must not be empty",
		},
		{
			md:      metadata.Pairs("authorization", "Bearer"),
			value:   "",
			errCode: codes.Unauthenticated,
			msg:     "bearer token must not be empty",
		},
	} {
		ctx := metautils.NiceMD(run.md).ToIncoming(context.TODO())
		out, err := AuthFromMD(ctx, "bearer")
		if run.errCode != codes.OK {
			// `grpc.Code` is deprecated. Use `status.Code` instead.
			//assert.Equal(t, run.errCode, grpc.Code(err), run.msg)
			assert.Equal(t, run.errCode, status.Code(err), run.msg)
		} else {
			assert.NoError(t, err, run.msg)
		}
		assert.Equal(t, run.value, out, run.msg)
	}

}
