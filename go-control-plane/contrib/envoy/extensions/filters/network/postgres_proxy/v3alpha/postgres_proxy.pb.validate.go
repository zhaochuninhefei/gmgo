//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: contrib/envoy/extensions/filters/network/postgres_proxy/v3alpha/postgres_proxy.proto

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

// Validate checks the field values on PostgresProxy with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *PostgresProxy) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on PostgresProxy with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in PostgresProxyMultiError, or
// nil if none found.
func (m *PostgresProxy) ValidateAll() error {
	return m.validate(true)
}

func (m *PostgresProxy) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetStatPrefix()) < 1 {
		err := PostgresProxyValidationError{
			field:  "StatPrefix",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetEnableSqlParsing()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, PostgresProxyValidationError{
					field:  "EnableSqlParsing",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, PostgresProxyValidationError{
					field:  "EnableSqlParsing",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetEnableSqlParsing()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return PostgresProxyValidationError{
				field:  "EnableSqlParsing",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for TerminateSsl

	// no validation rules for UpstreamSsl

	if len(errors) > 0 {
		return PostgresProxyMultiError(errors)
	}

	return nil
}

// PostgresProxyMultiError is an error wrapping multiple validation errors
// returned by PostgresProxy.ValidateAll() if the designated constraints
// aren't met.
type PostgresProxyMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m PostgresProxyMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m PostgresProxyMultiError) AllErrors() []error { return m }

// PostgresProxyValidationError is the validation error returned by
// PostgresProxy.Validate if the designated constraints aren't met.
type PostgresProxyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e PostgresProxyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e PostgresProxyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e PostgresProxyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e PostgresProxyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e PostgresProxyValidationError) ErrorName() string { return "PostgresProxyValidationError" }

// Error satisfies the builtin error interface
func (e PostgresProxyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sPostgresProxy.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = PostgresProxyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = PostgresProxyValidationError{}
