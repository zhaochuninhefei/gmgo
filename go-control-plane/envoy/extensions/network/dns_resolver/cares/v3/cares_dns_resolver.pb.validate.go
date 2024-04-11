//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/network/dns_resolver/cares/v3/cares_dns_resolver.proto

package caresv3

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

// Validate checks the field values on CaresDnsResolverConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *CaresDnsResolverConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on CaresDnsResolverConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// CaresDnsResolverConfigMultiError, or nil if none found.
func (m *CaresDnsResolverConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *CaresDnsResolverConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(m.GetResolvers()) < 1 {
		err := CaresDnsResolverConfigValidationError{
			field:  "Resolvers",
			reason: "value must contain at least 1 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetResolvers() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, CaresDnsResolverConfigValidationError{
						field:  fmt.Sprintf("Resolvers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, CaresDnsResolverConfigValidationError{
						field:  fmt.Sprintf("Resolvers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return CaresDnsResolverConfigValidationError{
					field:  fmt.Sprintf("Resolvers[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	// no validation rules for UseResolversAsFallback

	// no validation rules for FilterUnroutableFamilies

	if all {
		switch v := interface{}(m.GetDnsResolverOptions()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, CaresDnsResolverConfigValidationError{
					field:  "DnsResolverOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, CaresDnsResolverConfigValidationError{
					field:  "DnsResolverOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetDnsResolverOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return CaresDnsResolverConfigValidationError{
				field:  "DnsResolverOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return CaresDnsResolverConfigMultiError(errors)
	}

	return nil
}

// CaresDnsResolverConfigMultiError is an error wrapping multiple validation
// errors returned by CaresDnsResolverConfig.ValidateAll() if the designated
// constraints aren't met.
type CaresDnsResolverConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m CaresDnsResolverConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m CaresDnsResolverConfigMultiError) AllErrors() []error { return m }

// CaresDnsResolverConfigValidationError is the validation error returned by
// CaresDnsResolverConfig.Validate if the designated constraints aren't met.
type CaresDnsResolverConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CaresDnsResolverConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CaresDnsResolverConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CaresDnsResolverConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CaresDnsResolverConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CaresDnsResolverConfigValidationError) ErrorName() string {
	return "CaresDnsResolverConfigValidationError"
}

// Error satisfies the builtin error interface
func (e CaresDnsResolverConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCaresDnsResolverConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CaresDnsResolverConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CaresDnsResolverConfigValidationError{}
