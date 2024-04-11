//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: contrib/envoy/extensions/vcl/v3alpha/vcl_socket_interface.proto

package v3alpha

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

// Validate checks the field values on VclSocketInterface with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *VclSocketInterface) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on VclSocketInterface with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// VclSocketInterfaceMultiError, or nil if none found.
func (m *VclSocketInterface) ValidateAll() error {
	return m.validate(true)
}

func (m *VclSocketInterface) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return VclSocketInterfaceMultiError(errors)
	}

	return nil
}

// VclSocketInterfaceMultiError is an error wrapping multiple validation errors
// returned by VclSocketInterface.ValidateAll() if the designated constraints
// aren't met.
type VclSocketInterfaceMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m VclSocketInterfaceMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m VclSocketInterfaceMultiError) AllErrors() []error { return m }

// VclSocketInterfaceValidationError is the validation error returned by
// VclSocketInterface.Validate if the designated constraints aren't met.
type VclSocketInterfaceValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e VclSocketInterfaceValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e VclSocketInterfaceValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e VclSocketInterfaceValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e VclSocketInterfaceValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e VclSocketInterfaceValidationError) ErrorName() string {
	return "VclSocketInterfaceValidationError"
}

// Error satisfies the builtin error interface
func (e VclSocketInterfaceValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sVclSocketInterface.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = VclSocketInterfaceValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = VclSocketInterfaceValidationError{}
