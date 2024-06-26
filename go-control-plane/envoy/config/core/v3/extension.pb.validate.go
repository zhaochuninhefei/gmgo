//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/core/v3/extension.proto

package corev3

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

// Validate checks the field values on TypedExtensionConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *TypedExtensionConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on TypedExtensionConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// TypedExtensionConfigMultiError, or nil if none found.
func (m *TypedExtensionConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *TypedExtensionConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetName()) < 1 {
		err := TypedExtensionConfigValidationError{
			field:  "Name",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if m.GetTypedConfig() == nil {
		err := TypedExtensionConfigValidationError{
			field:  "TypedConfig",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if a := m.GetTypedConfig(); a != nil {

	}

	if len(errors) > 0 {
		return TypedExtensionConfigMultiError(errors)
	}

	return nil
}

// TypedExtensionConfigMultiError is an error wrapping multiple validation
// errors returned by TypedExtensionConfig.ValidateAll() if the designated
// constraints aren't met.
type TypedExtensionConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m TypedExtensionConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m TypedExtensionConfigMultiError) AllErrors() []error { return m }

// TypedExtensionConfigValidationError is the validation error returned by
// TypedExtensionConfig.Validate if the designated constraints aren't met.
type TypedExtensionConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TypedExtensionConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TypedExtensionConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TypedExtensionConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TypedExtensionConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TypedExtensionConfigValidationError) ErrorName() string {
	return "TypedExtensionConfigValidationError"
}

// Error satisfies the builtin error interface
func (e TypedExtensionConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTypedExtensionConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TypedExtensionConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TypedExtensionConfigValidationError{}
