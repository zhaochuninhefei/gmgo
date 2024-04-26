// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build dragonfly || freebsd || linux || netbsd || openbsd

package poll

import (
	"syscall"

	"gitee.com/zhaochuninhefei/gmgo/internal/syscall/unix"
)

func fcntl(fd int, cmd int, arg int) (int, error) {
	r, _, e := syscall.Syscall(unix.FcntlSyscall, uintptr(fd), uintptr(cmd), uintptr(arg))
	if e != 0 {
		return int(r), e
	}
	return int(r), nil
}
