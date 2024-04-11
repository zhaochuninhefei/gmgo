//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/filters/http/proto_message_logging/v3/config.proto

package proto_message_loggingv3

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

// Validate checks the field values on ProtoMessageLoggingConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *ProtoMessageLoggingConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ProtoMessageLoggingConfig with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ProtoMessageLoggingConfigMultiError, or nil if none found.
func (m *ProtoMessageLoggingConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *ProtoMessageLoggingConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Mode

	{
		sorted_keys := make([]string, len(m.GetLoggingByMethod()))
		i := 0
		for key := range m.GetLoggingByMethod() {
			sorted_keys[i] = key
			i++
		}
		sort.Slice(sorted_keys, func(i, j int) bool { return sorted_keys[i] < sorted_keys[j] })
		for _, key := range sorted_keys {
			val := m.GetLoggingByMethod()[key]
			_ = val

			// no validation rules for LoggingByMethod[key]

			if all {
				switch v := interface{}(val).(type) {
				case interface{ ValidateAll() error }:
					if err := v.ValidateAll(); err != nil {
						errors = append(errors, ProtoMessageLoggingConfigValidationError{
							field:  fmt.Sprintf("LoggingByMethod[%v]", key),
							reason: "embedded message failed validation",
							cause:  err,
						})
					}
				case interface{ Validate() error }:
					if err := v.Validate(); err != nil {
						errors = append(errors, ProtoMessageLoggingConfigValidationError{
							field:  fmt.Sprintf("LoggingByMethod[%v]", key),
							reason: "embedded message failed validation",
							cause:  err,
						})
					}
				}
			} else if v, ok := interface{}(val).(interface{ Validate() error }); ok {
				if err := v.Validate(); err != nil {
					return ProtoMessageLoggingConfigValidationError{
						field:  fmt.Sprintf("LoggingByMethod[%v]", key),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}

		}
	}

	switch v := m.DescriptorSet.(type) {
	case *ProtoMessageLoggingConfig_DataSource:
		if v == nil {
			err := ProtoMessageLoggingConfigValidationError{
				field:  "DescriptorSet",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetDataSource()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ProtoMessageLoggingConfigValidationError{
						field:  "DataSource",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ProtoMessageLoggingConfigValidationError{
						field:  "DataSource",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetDataSource()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ProtoMessageLoggingConfigValidationError{
					field:  "DataSource",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *ProtoMessageLoggingConfig_ProtoDescriptorTypedMetadata:
		if v == nil {
			err := ProtoMessageLoggingConfigValidationError{
				field:  "DescriptorSet",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		// no validation rules for ProtoDescriptorTypedMetadata
	default:
		_ = v // ensures v is used
	}

	if len(errors) > 0 {
		return ProtoMessageLoggingConfigMultiError(errors)
	}

	return nil
}

// ProtoMessageLoggingConfigMultiError is an error wrapping multiple validation
// errors returned by ProtoMessageLoggingConfig.ValidateAll() if the
// designated constraints aren't met.
type ProtoMessageLoggingConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ProtoMessageLoggingConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ProtoMessageLoggingConfigMultiError) AllErrors() []error { return m }

// ProtoMessageLoggingConfigValidationError is the validation error returned by
// ProtoMessageLoggingConfig.Validate if the designated constraints aren't met.
type ProtoMessageLoggingConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ProtoMessageLoggingConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ProtoMessageLoggingConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ProtoMessageLoggingConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ProtoMessageLoggingConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ProtoMessageLoggingConfigValidationError) ErrorName() string {
	return "ProtoMessageLoggingConfigValidationError"
}

// Error satisfies the builtin error interface
func (e ProtoMessageLoggingConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sProtoMessageLoggingConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ProtoMessageLoggingConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ProtoMessageLoggingConfigValidationError{}

// Validate checks the field values on MethodLogging with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *MethodLogging) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on MethodLogging with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in MethodLoggingMultiError, or
// nil if none found.
func (m *MethodLogging) ValidateAll() error {
	return m.validate(true)
}

func (m *MethodLogging) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for RequestLoggingByField

	// no validation rules for ResponseLoggingByField

	if len(errors) > 0 {
		return MethodLoggingMultiError(errors)
	}

	return nil
}

// MethodLoggingMultiError is an error wrapping multiple validation errors
// returned by MethodLogging.ValidateAll() if the designated constraints
// aren't met.
type MethodLoggingMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m MethodLoggingMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m MethodLoggingMultiError) AllErrors() []error { return m }

// MethodLoggingValidationError is the validation error returned by
// MethodLogging.Validate if the designated constraints aren't met.
type MethodLoggingValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e MethodLoggingValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e MethodLoggingValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e MethodLoggingValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e MethodLoggingValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e MethodLoggingValidationError) ErrorName() string { return "MethodLoggingValidationError" }

// Error satisfies the builtin error interface
func (e MethodLoggingValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sMethodLogging.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = MethodLoggingValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = MethodLoggingValidationError{}
