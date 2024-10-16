// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows || zos

package ipv6_test

import (
	"errors"
	"os"
	"syscall"
)

func protocolNotSupported(err error) bool {
	//goland:noinspection GoTypeAssertionOnErrors
	switch err := err.(type) {
	case syscall.Errno:
		switch {
		case errors.Is(err, syscall.EPROTONOSUPPORT), errors.Is(err, syscall.ENOPROTOOPT):
			return true
		}
	case *os.SyscallError:
		switch err := err.Err.(type) {
		case syscall.Errno:
			switch {
			case errors.Is(err, syscall.EPROTONOSUPPORT), errors.Is(err, syscall.ENOPROTOOPT):
				return true
			}
		}
	}
	return false
}
