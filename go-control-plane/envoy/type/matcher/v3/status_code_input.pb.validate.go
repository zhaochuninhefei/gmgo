//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/type/matcher/v3/status_code_input.proto

package matcherv3

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

// Validate checks the field values on HttpResponseStatusCodeMatchInput with
// the rules defined in the proto definition for this message. If any rules
// are violated, the first error encountered is returned, or nil if there are
// no violations.
func (m *HttpResponseStatusCodeMatchInput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HttpResponseStatusCodeMatchInput with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// HttpResponseStatusCodeMatchInputMultiError, or nil if none found.
func (m *HttpResponseStatusCodeMatchInput) ValidateAll() error {
	return m.validate(true)
}

func (m *HttpResponseStatusCodeMatchInput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return HttpResponseStatusCodeMatchInputMultiError(errors)
	}

	return nil
}

// HttpResponseStatusCodeMatchInputMultiError is an error wrapping multiple
// validation errors returned by
// HttpResponseStatusCodeMatchInput.ValidateAll() if the designated
// constraints aren't met.
type HttpResponseStatusCodeMatchInputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HttpResponseStatusCodeMatchInputMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HttpResponseStatusCodeMatchInputMultiError) AllErrors() []error { return m }

// HttpResponseStatusCodeMatchInputValidationError is the validation error
// returned by HttpResponseStatusCodeMatchInput.Validate if the designated
// constraints aren't met.
type HttpResponseStatusCodeMatchInputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpResponseStatusCodeMatchInputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpResponseStatusCodeMatchInputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpResponseStatusCodeMatchInputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpResponseStatusCodeMatchInputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpResponseStatusCodeMatchInputValidationError) ErrorName() string {
	return "HttpResponseStatusCodeMatchInputValidationError"
}

// Error satisfies the builtin error interface
func (e HttpResponseStatusCodeMatchInputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpResponseStatusCodeMatchInput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpResponseStatusCodeMatchInputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpResponseStatusCodeMatchInputValidationError{}

// Validate checks the field values on HttpResponseStatusCodeClassMatchInput
// with the rules defined in the proto definition for this message. If any
// rules are violated, the first error encountered is returned, or nil if
// there are no violations.
func (m *HttpResponseStatusCodeClassMatchInput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HttpResponseStatusCodeClassMatchInput
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// HttpResponseStatusCodeClassMatchInputMultiError, or nil if none found.
func (m *HttpResponseStatusCodeClassMatchInput) ValidateAll() error {
	return m.validate(true)
}

func (m *HttpResponseStatusCodeClassMatchInput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return HttpResponseStatusCodeClassMatchInputMultiError(errors)
	}

	return nil
}

// HttpResponseStatusCodeClassMatchInputMultiError is an error wrapping
// multiple validation errors returned by
// HttpResponseStatusCodeClassMatchInput.ValidateAll() if the designated
// constraints aren't met.
type HttpResponseStatusCodeClassMatchInputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HttpResponseStatusCodeClassMatchInputMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HttpResponseStatusCodeClassMatchInputMultiError) AllErrors() []error { return m }

// HttpResponseStatusCodeClassMatchInputValidationError is the validation error
// returned by HttpResponseStatusCodeClassMatchInput.Validate if the
// designated constraints aren't met.
type HttpResponseStatusCodeClassMatchInputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpResponseStatusCodeClassMatchInputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpResponseStatusCodeClassMatchInputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpResponseStatusCodeClassMatchInputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpResponseStatusCodeClassMatchInputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpResponseStatusCodeClassMatchInputValidationError) ErrorName() string {
	return "HttpResponseStatusCodeClassMatchInputValidationError"
}

// Error satisfies the builtin error interface
func (e HttpResponseStatusCodeClassMatchInputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpResponseStatusCodeClassMatchInput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpResponseStatusCodeClassMatchInputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpResponseStatusCodeClassMatchInputValidationError{}
