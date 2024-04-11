//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/internal_redirect/previous_routes/v3/previous_routes_config.proto

package previous_routesv3

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

// Validate checks the field values on PreviousRoutesConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *PreviousRoutesConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on PreviousRoutesConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// PreviousRoutesConfigMultiError, or nil if none found.
func (m *PreviousRoutesConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *PreviousRoutesConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return PreviousRoutesConfigMultiError(errors)
	}

	return nil
}

// PreviousRoutesConfigMultiError is an error wrapping multiple validation
// errors returned by PreviousRoutesConfig.ValidateAll() if the designated
// constraints aren't met.
type PreviousRoutesConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m PreviousRoutesConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m PreviousRoutesConfigMultiError) AllErrors() []error { return m }

// PreviousRoutesConfigValidationError is the validation error returned by
// PreviousRoutesConfig.Validate if the designated constraints aren't met.
type PreviousRoutesConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e PreviousRoutesConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e PreviousRoutesConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e PreviousRoutesConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e PreviousRoutesConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e PreviousRoutesConfigValidationError) ErrorName() string {
	return "PreviousRoutesConfigValidationError"
}

// Error satisfies the builtin error interface
func (e PreviousRoutesConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPreviousRoutesConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = PreviousRoutesConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = PreviousRoutesConfigValidationError{}
