//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/http/header_validators/envoy_default/v3/header_validator.proto

package envoy_defaultv3

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

// Validate checks the field values on HeaderValidatorConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *HeaderValidatorConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HeaderValidatorConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// HeaderValidatorConfigMultiError, or nil if none found.
func (m *HeaderValidatorConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *HeaderValidatorConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetHttp1ProtocolOptions()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, HeaderValidatorConfigValidationError{
					field:  "Http1ProtocolOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, HeaderValidatorConfigValidationError{
					field:  "Http1ProtocolOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetHttp1ProtocolOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return HeaderValidatorConfigValidationError{
				field:  "Http1ProtocolOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetUriPathNormalizationOptions()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, HeaderValidatorConfigValidationError{
					field:  "UriPathNormalizationOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, HeaderValidatorConfigValidationError{
					field:  "UriPathNormalizationOptions",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetUriPathNormalizationOptions()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return HeaderValidatorConfigValidationError{
				field:  "UriPathNormalizationOptions",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for RestrictHttpMethods

	// no validation rules for HeadersWithUnderscoresAction

	// no validation rules for StripFragmentFromPath

	if len(errors) > 0 {
		return HeaderValidatorConfigMultiError(errors)
	}

	return nil
}

// HeaderValidatorConfigMultiError is an error wrapping multiple validation
// errors returned by HeaderValidatorConfig.ValidateAll() if the designated
// constraints aren't met.
type HeaderValidatorConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HeaderValidatorConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HeaderValidatorConfigMultiError) AllErrors() []error { return m }

// HeaderValidatorConfigValidationError is the validation error returned by
// HeaderValidatorConfig.Validate if the designated constraints aren't met.
type HeaderValidatorConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HeaderValidatorConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HeaderValidatorConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HeaderValidatorConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HeaderValidatorConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HeaderValidatorConfigValidationError) ErrorName() string {
	return "HeaderValidatorConfigValidationError"
}

// Error satisfies the builtin error interface
func (e HeaderValidatorConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHeaderValidatorConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HeaderValidatorConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HeaderValidatorConfigValidationError{}

// Validate checks the field values on
// HeaderValidatorConfig_UriPathNormalizationOptions with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *HeaderValidatorConfig_UriPathNormalizationOptions) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on
// HeaderValidatorConfig_UriPathNormalizationOptions with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in
// HeaderValidatorConfig_UriPathNormalizationOptionsMultiError, or nil if none found.
func (m *HeaderValidatorConfig_UriPathNormalizationOptions) ValidateAll() error {
	return m.validate(true)
}

func (m *HeaderValidatorConfig_UriPathNormalizationOptions) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for SkipPathNormalization

	// no validation rules for SkipMergingSlashes

	if _, ok := HeaderValidatorConfig_UriPathNormalizationOptions_PathWithEscapedSlashesAction_name[int32(m.GetPathWithEscapedSlashesAction())]; !ok {
		err := HeaderValidatorConfig_UriPathNormalizationOptionsValidationError{
			field:  "PathWithEscapedSlashesAction",
			reason: "value must be one of the defined enum values",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return HeaderValidatorConfig_UriPathNormalizationOptionsMultiError(errors)
	}

	return nil
}

// HeaderValidatorConfig_UriPathNormalizationOptionsMultiError is an error
// wrapping multiple validation errors returned by
// HeaderValidatorConfig_UriPathNormalizationOptions.ValidateAll() if the
// designated constraints aren't met.
type HeaderValidatorConfig_UriPathNormalizationOptionsMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HeaderValidatorConfig_UriPathNormalizationOptionsMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HeaderValidatorConfig_UriPathNormalizationOptionsMultiError) AllErrors() []error { return m }

// HeaderValidatorConfig_UriPathNormalizationOptionsValidationError is the
// validation error returned by
// HeaderValidatorConfig_UriPathNormalizationOptions.Validate if the
// designated constraints aren't met.
type HeaderValidatorConfig_UriPathNormalizationOptionsValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HeaderValidatorConfig_UriPathNormalizationOptionsValidationError) Field() string {
	return e.field
}

// Reason function returns reason value.
func (e HeaderValidatorConfig_UriPathNormalizationOptionsValidationError) Reason() string {
	return e.reason
}

// Cause function returns cause value.
func (e HeaderValidatorConfig_UriPathNormalizationOptionsValidationError) Cause() error {
	return e.cause
}

// Key function returns key value.
func (e HeaderValidatorConfig_UriPathNormalizationOptionsValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HeaderValidatorConfig_UriPathNormalizationOptionsValidationError) ErrorName() string {
	return "HeaderValidatorConfig_UriPathNormalizationOptionsValidationError"
}

// Error satisfies the builtin error interface
func (e HeaderValidatorConfig_UriPathNormalizationOptionsValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHeaderValidatorConfig_UriPathNormalizationOptions.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HeaderValidatorConfig_UriPathNormalizationOptionsValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HeaderValidatorConfig_UriPathNormalizationOptionsValidationError{}

// Validate checks the field values on
// HeaderValidatorConfig_Http1ProtocolOptions with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *HeaderValidatorConfig_Http1ProtocolOptions) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on
// HeaderValidatorConfig_Http1ProtocolOptions with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in
// HeaderValidatorConfig_Http1ProtocolOptionsMultiError, or nil if none found.
func (m *HeaderValidatorConfig_Http1ProtocolOptions) ValidateAll() error {
	return m.validate(true)
}

func (m *HeaderValidatorConfig_Http1ProtocolOptions) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for AllowChunkedLength

	if len(errors) > 0 {
		return HeaderValidatorConfig_Http1ProtocolOptionsMultiError(errors)
	}

	return nil
}

// HeaderValidatorConfig_Http1ProtocolOptionsMultiError is an error wrapping
// multiple validation errors returned by
// HeaderValidatorConfig_Http1ProtocolOptions.ValidateAll() if the designated
// constraints aren't met.
type HeaderValidatorConfig_Http1ProtocolOptionsMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HeaderValidatorConfig_Http1ProtocolOptionsMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HeaderValidatorConfig_Http1ProtocolOptionsMultiError) AllErrors() []error { return m }

// HeaderValidatorConfig_Http1ProtocolOptionsValidationError is the validation
// error returned by HeaderValidatorConfig_Http1ProtocolOptions.Validate if
// the designated constraints aren't met.
type HeaderValidatorConfig_Http1ProtocolOptionsValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HeaderValidatorConfig_Http1ProtocolOptionsValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HeaderValidatorConfig_Http1ProtocolOptionsValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HeaderValidatorConfig_Http1ProtocolOptionsValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HeaderValidatorConfig_Http1ProtocolOptionsValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HeaderValidatorConfig_Http1ProtocolOptionsValidationError) ErrorName() string {
	return "HeaderValidatorConfig_Http1ProtocolOptionsValidationError"
}

// Error satisfies the builtin error interface
func (e HeaderValidatorConfig_Http1ProtocolOptionsValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHeaderValidatorConfig_Http1ProtocolOptions.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HeaderValidatorConfig_Http1ProtocolOptionsValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HeaderValidatorConfig_Http1ProtocolOptionsValidationError{}
