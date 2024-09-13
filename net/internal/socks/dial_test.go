// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socks_test

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"gitee.com/zhaochuninhefei/gmgo/net/internal/socks"
	"gitee.com/zhaochuninhefei/gmgo/net/internal/sockstest"
)

func TestDial(t *testing.T) {
	t.Run("Connect", func(t *testing.T) {
		ss, err := sockstest.NewServer(sockstest.NoAuthRequired, sockstest.NoProxyRequired)
		if err != nil {
			t.Fatal(err)
		}
		defer func(ss *sockstest.Server) {
			_ = ss.Close()
		}(ss)
		d := socks.NewDialer(ss.Addr().Network(), ss.Addr().String())
		d.AuthMethods = []socks.AuthMethod{
			socks.AuthMethodNotRequired,
			socks.AuthMethodUsernamePassword,
		}
		d.Authenticate = (&socks.UsernamePassword{
			Username: "username",
			Password: "password",
		}).Authenticate
		c, err := d.DialContext(context.Background(), ss.TargetAddr().Network(), ss.TargetAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.(*socks.Conn).BoundAddr()
		_ = c.Close()
	})
	t.Run("ConnectWithConn", func(t *testing.T) {
		ss, err := sockstest.NewServer(sockstest.NoAuthRequired, sockstest.NoProxyRequired)
		if err != nil {
			t.Fatal(err)
		}
		defer func(ss *sockstest.Server) {
			_ = ss.Close()
		}(ss)
		c, err := net.Dial(ss.Addr().Network(), ss.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func(c net.Conn) {
			_ = c.Close()
		}(c)
		d := socks.NewDialer(ss.Addr().Network(), ss.Addr().String())
		d.AuthMethods = []socks.AuthMethod{
			socks.AuthMethodNotRequired,
			socks.AuthMethodUsernamePassword,
		}
		d.Authenticate = (&socks.UsernamePassword{
			Username: "username",
			Password: "password",
		}).Authenticate
		a, err := d.DialWithConn(context.Background(), c, ss.TargetAddr().Network(), ss.TargetAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.(*socks.Addr); !ok {
			t.Fatalf("got %+v; want socks.Addr", a)
		}
	})
	t.Run("Cancel", func(t *testing.T) {
		ss, err := sockstest.NewServer(sockstest.NoAuthRequired, blackholeCmdFunc)
		if err != nil {
			t.Fatal(err)
		}
		defer func(ss *sockstest.Server) {
			_ = ss.Close()
		}(ss)
		d := socks.NewDialer(ss.Addr().Network(), ss.Addr().String())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dialErr := make(chan error)
		go func() {
			c, err := d.DialContext(ctx, ss.TargetAddr().Network(), ss.TargetAddr().String())
			if err == nil {
				_ = c.Close()
			}
			dialErr <- err
		}()
		time.Sleep(100 * time.Millisecond)
		cancel()
		err = <-dialErr
		if perr, nerr := parseDialError(err); !errors.Is(perr, context.Canceled) && nerr == nil {
			t.Fatalf("got %v; want context.Canceled or equivalent", err)
		}
	})
	t.Run("Deadline", func(t *testing.T) {
		ss, err := sockstest.NewServer(sockstest.NoAuthRequired, blackholeCmdFunc)
		if err != nil {
			t.Fatal(err)
		}
		defer func(ss *sockstest.Server) {
			_ = ss.Close()
		}(ss)
		d := socks.NewDialer(ss.Addr().Network(), ss.Addr().String())
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(100*time.Millisecond))
		defer cancel()
		c, err := d.DialContext(ctx, ss.TargetAddr().Network(), ss.TargetAddr().String())
		if err == nil {
			_ = c.Close()
		}
		if perr, nerr := parseDialError(err); !errors.Is(perr, context.DeadlineExceeded) && nerr == nil {
			t.Fatalf("got %v; want context.DeadlineExceeded or equivalent", err)
		}
	})
	t.Run("WithRogueServer", func(t *testing.T) {
		ss, err := sockstest.NewServer(sockstest.NoAuthRequired, rogueCmdFunc)
		if err != nil {
			t.Fatal(err)
		}
		defer func(ss *sockstest.Server) {
			_ = ss.Close()
		}(ss)
		d := socks.NewDialer(ss.Addr().Network(), ss.Addr().String())
		for i := 0; i < 2*len(rogueCmdList); i++ {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(100*time.Millisecond))
			//goland:noinspection GoDeferInLoop
			defer cancel()
			c, err := d.DialContext(ctx, ss.TargetAddr().Network(), ss.TargetAddr().String())
			if err == nil {
				t.Log(c.(*socks.Conn).BoundAddr())
				_ = c.Close()
				t.Error("should fail")
			}
		}
	})
}

func blackholeCmdFunc(rw io.ReadWriter, b []byte) error {
	if _, err := sockstest.ParseCmdRequest(b); err != nil {
		return err
	}
	var bb [1]byte
	for {
		if _, err := rw.Read(bb[:]); err != nil {
			return err
		}
	}
}

func rogueCmdFunc(rw io.ReadWriter, b []byte) error {
	if _, err := sockstest.ParseCmdRequest(b); err != nil {
		return err
	}
	_, _ = rw.Write(rogueCmdList[rand.Intn(len(rogueCmdList))])
	return nil
}

var rogueCmdList = [][]byte{
	{0x05},
	{0x06, 0x00, 0x00, 0x01, 192, 0, 2, 1, 0x17, 0x4b},
	{0x05, 0x00, 0xff, 0x01, 192, 0, 2, 2, 0x17, 0x4b},
	{0x05, 0x00, 0x00, 0x01, 192, 0, 2, 3},
	{0x05, 0x00, 0x00, 0x03, 0x04, 'F', 'Q', 'D', 'N'},
}

func parseDialError(err error) (perr, nerr error) {
	var e *net.OpError
	if errors.As(err, &e) {
		err = e.Err
		nerr = e
	}
	var e1 *os.SyscallError
	if errors.As(err, &e1) {
		err = e1.Err
	}
	perr = err
	return
}
