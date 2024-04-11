//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/formatter/cel/v3/cel.proto

package celv3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on Cel with the rules defined in the proto
// definition for this message. If any rules are violated, the first error
// encountered is returned, or nil if there are no violations.
func (m *Cel) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Cel with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in CelMultiError, or nil if none found.
func (m *Cel) ValidateAll() error {
	return m.validate(true)
}

func (m *Cel) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return CelMultiError(errors)
	}

	return nil
}

// CelMultiError is an error wrapping multiple validation errors returned by
// Cel.ValidateAll() if the designated constraints aren't met.
type CelMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m CelMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m CelMultiError) AllErrors() []error { return m }

// CelValidationError is the validation error returned by Cel.Validate if the
// designated constraints aren't met.
type CelValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CelValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CelValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CelValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CelValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CelValidationError) ErrorName() string { return "CelValidationError" }

// Error satisfies the builtin error interface
func (e CelValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCel.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CelValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CelValidationError{}
