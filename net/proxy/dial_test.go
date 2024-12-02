// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/net/internal/sockstest"
	"gitee.com/zhaochuninhefei/gmgo/net/nettest"
)

func TestDial(t *testing.T) {
	ResetProxyEnv()
	t.Run("DirectWithCancel", func(t *testing.T) {
		defer ResetProxyEnv()
		l, err := nettest.NewLocalListener("tcp")
		if err != nil {
			t.Fatal(err)
		}
		defer func(l net.Listener) {
			_ = l.Close()
		}(l)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c, err := Dial(ctx, l.Addr().Network(), l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("DirectWithTimeout", func(t *testing.T) {
		defer ResetProxyEnv()
		l, err := nettest.NewLocalListener("tcp")
		if err != nil {
			t.Fatal(err)
		}
		defer func(l net.Listener) {
			_ = l.Close()
		}(l)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := Dial(ctx, l.Addr().Network(), l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("DirectWithTimeoutExceeded", func(t *testing.T) {
		defer ResetProxyEnv()
		l, err := nettest.NewLocalListener("tcp")
		if err != nil {
			t.Fatal(err)
		}
		defer func(l net.Listener) {
			_ = l.Close()
		}(l)
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		time.Sleep(time.Millisecond)
		defer cancel()
		c, err := Dial(ctx, l.Addr().Network(), l.Addr().String())
		if err == nil {
			defer func(c net.Conn) {
				_ = c.Close()
			}(c)
			t.Fatal("failed to timeout")
		}
	})
	t.Run("SOCKS5", func(t *testing.T) {
		defer ResetProxyEnv()
		s, err := sockstest.NewServer(sockstest.NoAuthRequired, sockstest.NoProxyRequired)
		if err != nil {
			t.Fatal(err)
		}
		defer func(s *sockstest.Server) {
			_ = s.Close()
		}(s)
		if err = os.Setenv("ALL_PROXY", fmt.Sprintf("socks5://%s", s.Addr().String())); err != nil {
			t.Fatal(err)
		}
		c, err := Dial(context.Background(), s.TargetAddr().Network(), s.TargetAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("SOCKS5WithTimeout", func(t *testing.T) {
		defer ResetProxyEnv()
		s, err := sockstest.NewServer(sockstest.NoAuthRequired, sockstest.NoProxyRequired)
		if err != nil {
			t.Fatal(err)
		}
		defer func(s *sockstest.Server) {
			_ = s.Close()
		}(s)
		if err = os.Setenv("ALL_PROXY", fmt.Sprintf("socks5://%s", s.Addr().String())); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := Dial(ctx, s.TargetAddr().Network(), s.TargetAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	})
	t.Run("SOCKS5WithTimeoutExceeded", func(t *testing.T) {
		defer ResetProxyEnv()
		s, err := sockstest.NewServer(sockstest.NoAuthRequired, sockstest.NoProxyRequired)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err = os.Setenv("ALL_PROXY", fmt.Sprintf("socks5://%s", s.Addr().String())); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		time.Sleep(time.Millisecond)
		defer cancel()
		c, err := Dial(ctx, s.TargetAddr().Network(), s.TargetAddr().String())
		if err == nil {
			defer c.Close()
			t.Fatal("failed to timeout")
		}
	})
}
