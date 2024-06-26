// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package poll_test

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"testing"
	"time"
)

func TestReadError(t *testing.T) {
	t.Run("ErrNotPollable", func(t *testing.T) {
		f, err := badStateFile()
		if err != nil {
			t.Skip(err)
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)

		// Give scheduler a chance to have two separated
		// goroutines: an event poller and an event waiter.
		time.Sleep(100 * time.Millisecond)

		var b [1]byte
		_, err = f.Read(b[:])
		if perr := parseReadError(err, isBadStateFileError); perr != nil {
			t.Fatal(perr)
		}
	})
}

func parseReadError(nestedErr error, verify func(error) (string, bool)) error {
	err := nestedErr
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		err = opErr.Err
	}
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	var scErr *os.SyscallError
	if errors.As(err, &scErr) {
		err = scErr.Err
	}
	if s, ok := verify(err); !ok {
		return fmt.Errorf("got %v; want %s", nestedErr, s)
	}
	return nil
}
