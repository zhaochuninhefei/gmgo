// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package obscuretestdata contains functionality used by tests to more easily
// work with testdata that must be obscured primarily due to
// golang.org/issue/34986.
package obscuretestdata

import (
	"encoding/base64"
	"io"
	"os"
)

// DecodeToTempFile decodes the named file to a temporary location.
// If successful, it returns the path of the decoded file.
// The caller is responsible for ensuring that the temporary file is removed.
func DecodeToTempFile(name string) (path string, err error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	tmp, err := os.CreateTemp("", "obscuretestdata-decoded-")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, base64.NewDecoder(base64.StdEncoding, f)); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// ReadFile reads the named file and returns its decoded contents.
func ReadFile(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	return io.ReadAll(base64.NewDecoder(base64.StdEncoding, f))
}
