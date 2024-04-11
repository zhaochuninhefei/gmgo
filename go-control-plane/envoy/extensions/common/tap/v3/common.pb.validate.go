//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/common/tap/v3/common.proto

package tapv3

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

// Validate checks the field values on CommonExtensionConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *CommonExtensionConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on CommonExtensionConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// CommonExtensionConfigMultiError, or nil if none found.
func (m *CommonExtensionConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *CommonExtensionConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	oneofConfigTypePresent := false
	switch v := m.ConfigType.(type) {
	case *CommonExtensionConfig_AdminConfig:
		if v == nil {
			err := CommonExtensionConfigValidationError{
				field:  "ConfigType",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofConfigTypePresent = true

		if all {
			switch v := interface{}(m.GetAdminConfig()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, CommonExtensionConfigValidationError{
						field:  "AdminConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, CommonExtensionConfigValidationError{
						field:  "AdminConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetAdminConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return CommonExtensionConfigValidationError{
					field:  "AdminConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *CommonExtensionConfig_StaticConfig:
		if v == nil {
			err := CommonExtensionConfigValidationError{
				field:  "ConfigType",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofConfigTypePresent = true

		if all {
			switch v := interface{}(m.GetStaticConfig()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, CommonExtensionConfigValidationError{
						field:  "StaticConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, CommonExtensionConfigValidationError{
						field:  "StaticConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetStaticConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return CommonExtensionConfigValidationError{
					field:  "StaticConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}
	if !oneofConfigTypePresent {
		err := CommonExtensionConfigValidationError{
			field:  "ConfigType",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return CommonExtensionConfigMultiError(errors)
	}

	return nil
}

// CommonExtensionConfigMultiError is an error wrapping multiple validation
// errors returned by CommonExtensionConfig.ValidateAll() if the designated
// constraints aren't met.
type CommonExtensionConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m CommonExtensionConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m CommonExtensionConfigMultiError) AllErrors() []error { return m }

// CommonExtensionConfigValidationError is the validation error returned by
// CommonExtensionConfig.Validate if the designated constraints aren't met.
type CommonExtensionConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CommonExtensionConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CommonExtensionConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CommonExtensionConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CommonExtensionConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CommonExtensionConfigValidationError) ErrorName() string {
	return "CommonExtensionConfigValidationError"
}

// Error satisfies the builtin error interface
func (e CommonExtensionConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCommonExtensionConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CommonExtensionConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CommonExtensionConfigValidationError{}

// Validate checks the field values on AdminConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *AdminConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on AdminConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in AdminConfigMultiError, or
// nil if none found.
func (m *AdminConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *AdminConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetConfigId()) < 1 {
		err := AdminConfigValidationError{
			field:  "ConfigId",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return AdminConfigMultiError(errors)
	}

	return nil
}

// AdminConfigMultiError is an error wrapping multiple validation errors
// returned by AdminConfig.ValidateAll() if the designated constraints aren't met.
type AdminConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m AdminConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m AdminConfigMultiError) AllErrors() []error { return m }

// AdminConfigValidationError is the validation error returned by
// AdminConfig.Validate if the designated constraints aren't met.
type AdminConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AdminConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AdminConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AdminConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AdminConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AdminConfigValidationError) ErrorName() string { return "AdminConfigValidationError" }

// Error satisfies the builtin error interface
func (e AdminConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAdminConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AdminConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AdminConfigValidationError{}
