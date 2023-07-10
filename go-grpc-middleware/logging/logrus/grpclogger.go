// Copyright 2017 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package grpc_logrus

import (
	"gitee.com/zhaochuninhefei/gmgo/grpc/grpclog"
	"github.com/sirupsen/logrus"
)

// ReplaceGrpcLogger sets the given logrus.Logger as a gRPC-level logger.
// This should be called *before* any other initialization, preferably from init() functions.
func ReplaceGrpcLogger(logger *logrus.Entry) {
	// grpclog.SetLogger is deprecated, use SetLoggerV2 instead.
	//grpclog.SetLogger(logger.WithField("system", SystemField))
	grpclog.SetLoggerV2(NewEntry(logger.WithField("system", SystemField)))
}

type Entry struct {
	logrus.Entry
}

// V 为 Entry 绑定方法 V(l int) bool
func (e *Entry) V(l int) bool {
	// reports whether verbosity level l is at least the requested verbose level.
	return int(e.Logger.Level) >= l
}

func NewEntry(e *logrus.Entry) *Entry {
	return &Entry{*e}
}
