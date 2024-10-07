// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !aix && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !solaris && !windows

package ipv4

import (
	"net"

	"gitee.com/zhaochuninhefei/gmgo/net/internal/socket"
)

func (so *sockOpt) setIPMreq(_ *socket.Conn, _ *net.Interface, _ net.IP) error {
	return errNotImplemented
}

func (so *sockOpt) getMulticastIf(_ *socket.Conn) (*net.Interface, error) {
	return nil, errNotImplemented
}

func (so *sockOpt) setMulticastIf(_ *socket.Conn, _ *net.Interface) error {
	return errNotImplemented
}
