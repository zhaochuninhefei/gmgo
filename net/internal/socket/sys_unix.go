// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package socket

import (
	"syscall"
	"unsafe"
)

//go:linkname syscall_getsockopt syscall.getsockopt
//goland:noinspection GoSnakeCaseUsage,GoUnusedParameter
func syscall_getsockopt(s, level, name int, val unsafe.Pointer, vallen *uint32) error

//go:linkname syscall_setsockopt syscall.setsockopt
//goland:noinspection GoSnakeCaseUsage,GoUnusedParameter
func syscall_setsockopt(s, level, name int, val unsafe.Pointer, vallen uintptr) error

//go:linkname syscall_recvmsg syscall.recvmsg
//goland:noinspection GoSnakeCaseUsage,GoUnusedParameter
func syscall_recvmsg(s int, msg *syscall.Msghdr, flags int) (int, error)

//go:linkname syscall_sendmsg syscall.sendmsg
//goland:noinspection GoSnakeCaseUsage,GoUnusedParameter
func syscall_sendmsg(s int, msg *syscall.Msghdr, flags int) (int, error)

func getsockopt(s uintptr, level, name int, b []byte) (int, error) {
	l := uint32(len(b))
	err := syscall_getsockopt(int(s), level, name, unsafe.Pointer(&b[0]), &l)
	return int(l), err
}

func setsockopt(s uintptr, level, name int, b []byte) error {
	return syscall_setsockopt(int(s), level, name, unsafe.Pointer(&b[0]), uintptr(len(b)))
}

func recvmsg(s uintptr, h *msghdr, flags int) (int, error) {
	return syscall_recvmsg(int(s), (*syscall.Msghdr)(unsafe.Pointer(h)), flags)
}

func sendmsg(s uintptr, h *msghdr, flags int) (int, error) {
	return syscall_sendmsg(int(s), (*syscall.Msghdr)(unsafe.Pointer(h)), flags)
}
