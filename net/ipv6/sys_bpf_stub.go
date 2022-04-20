// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux
// +build !linux

package ipv6

import (
	"gitee.com/zhaochuninhefei/gmgo/net/bpf"
	"gitee.com/zhaochuninhefei/gmgo/net/internal/socket"
)

func (so *sockOpt) setAttachFilter(c *socket.Conn, f []bpf.RawInstruction) error {
	return errNotImplemented
}
