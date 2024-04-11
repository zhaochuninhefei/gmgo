//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/route/v3/scoped_route.proto

package routev3

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

// Validate checks the field values on ScopedRouteConfiguration with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *ScopedRouteConfiguration) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ScopedRouteConfiguration with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ScopedRouteConfigurationMultiError, or nil if none found.
func (m *ScopedRouteConfiguration) ValidateAll() error {
	return m.validate(true)
}

func (m *ScopedRouteConfiguration) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for OnDemand

	if utf8.RuneCountInString(m.GetName()) < 1 {
		err := ScopedRouteConfigurationValidationError{
			field:  "Name",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	// no validation rules for RouteConfigurationName

	if all {
		switch v := interface{}(m.GetRouteConfiguration()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ScopedRouteConfigurationValidationError{
					field:  "RouteConfiguration",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ScopedRouteConfigurationValidationError{
					field:  "RouteConfiguration",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetRouteConfiguration()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ScopedRouteConfigurationValidationError{
				field:  "RouteConfiguration",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if m.GetKey() == nil {
		err := ScopedRouteConfigurationValidationError{
			field:  "Key",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetKey()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ScopedRouteConfigurationValidationError{
					field:  "Key",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ScopedRouteConfigurationValidationError{
					field:  "Key",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetKey()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ScopedRouteConfigurationValidationError{
				field:  "Key",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return ScopedRouteConfigurationMultiError(errors)
	}

	return nil
}

// ScopedRouteConfigurationMultiError is an error wrapping multiple validation
// errors returned by ScopedRouteConfiguration.ValidateAll() if the designated
// constraints aren't met.
type ScopedRouteConfigurationMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ScopedRouteConfigurationMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ScopedRouteConfigurationMultiError) AllErrors() []error { return m }

// ScopedRouteConfigurationValidationError is the validation error returned by
// ScopedRouteConfiguration.Validate if the designated constraints aren't met.
type ScopedRouteConfigurationValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ScopedRouteConfigurationValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ScopedRouteConfigurationValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ScopedRouteConfigurationValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ScopedRouteConfigurationValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ScopedRouteConfigurationValidationError) ErrorName() string {
	return "ScopedRouteConfigurationValidationError"
}

// Error satisfies the builtin error interface
func (e ScopedRouteConfigurationValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sScopedRouteConfiguration.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ScopedRouteConfigurationValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ScopedRouteConfigurationValidationError{}

// Validate checks the field values on ScopedRouteConfiguration_Key with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *ScopedRouteConfiguration_Key) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ScopedRouteConfiguration_Key with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ScopedRouteConfiguration_KeyMultiError, or nil if none found.
func (m *ScopedRouteConfiguration_Key) ValidateAll() error {
	return m.validate(true)
}

func (m *ScopedRouteConfiguration_Key) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(m.GetFragments()) < 1 {
		err := ScopedRouteConfiguration_KeyValidationError{
			field:  "Fragments",
			reason: "value must contain at least 1 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetFragments() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ScopedRouteConfiguration_KeyValidationError{
						field:  fmt.Sprintf("Fragments[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ScopedRouteConfiguration_KeyValidationError{
						field:  fmt.Sprintf("Fragments[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ScopedRouteConfiguration_KeyValidationError{
					field:  fmt.Sprintf("Fragments[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return ScopedRouteConfiguration_KeyMultiError(errors)
	}

	return nil
}

// ScopedRouteConfiguration_KeyMultiError is an error wrapping multiple
// validation errors returned by ScopedRouteConfiguration_Key.ValidateAll() if
// the designated constraints aren't met.
type ScopedRouteConfiguration_KeyMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ScopedRouteConfiguration_KeyMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ScopedRouteConfiguration_KeyMultiError) AllErrors() []error { return m }

// ScopedRouteConfiguration_KeyValidationError is the validation error returned
// by ScopedRouteConfiguration_Key.Validate if the designated constraints
// aren't met.
type ScopedRouteConfiguration_KeyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ScopedRouteConfiguration_KeyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ScopedRouteConfiguration_KeyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ScopedRouteConfiguration_KeyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ScopedRouteConfiguration_KeyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ScopedRouteConfiguration_KeyValidationError) ErrorName() string {
	return "ScopedRouteConfiguration_KeyValidationError"
}

// Error satisfies the builtin error interface
func (e ScopedRouteConfiguration_KeyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sScopedRouteConfiguration_Key.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ScopedRouteConfiguration_KeyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ScopedRouteConfiguration_KeyValidationError{}

// Validate checks the field values on ScopedRouteConfiguration_Key_Fragment
// with the rules defined in the proto definition for this message. If any
// rules are violated, the first error encountered is returned, or nil if
// there are no violations.
func (m *ScopedRouteConfiguration_Key_Fragment) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ScopedRouteConfiguration_Key_Fragment
// with the rules defined in the proto definition for this message. If any
// rules are violated, the result is a list of violation errors wrapped in
// ScopedRouteConfiguration_Key_FragmentMultiError, or nil if none found.
func (m *ScopedRouteConfiguration_Key_Fragment) ValidateAll() error {
	return m.validate(true)
}

func (m *ScopedRouteConfiguration_Key_Fragment) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	oneofTypePresent := false
	switch v := m.Type.(type) {
	case *ScopedRouteConfiguration_Key_Fragment_StringKey:
		if v == nil {
			err := ScopedRouteConfiguration_Key_FragmentValidationError{
				field:  "Type",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofTypePresent = true
		// no validation rules for StringKey
	default:
		_ = v // ensures v is used
	}
	if !oneofTypePresent {
		err := ScopedRouteConfiguration_Key_FragmentValidationError{
			field:  "Type",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return ScopedRouteConfiguration_Key_FragmentMultiError(errors)
	}

	return nil
}

// ScopedRouteConfiguration_Key_FragmentMultiError is an error wrapping
// multiple validation errors returned by
// ScopedRouteConfiguration_Key_Fragment.ValidateAll() if the designated
// constraints aren't met.
type ScopedRouteConfiguration_Key_FragmentMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ScopedRouteConfiguration_Key_FragmentMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ScopedRouteConfiguration_Key_FragmentMultiError) AllErrors() []error { return m }

// ScopedRouteConfiguration_Key_FragmentValidationError is the validation error
// returned by ScopedRouteConfiguration_Key_Fragment.Validate if the
// designated constraints aren't met.
type ScopedRouteConfiguration_Key_FragmentValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ScopedRouteConfiguration_Key_FragmentValidationError) ErrorName() string {
	return "ScopedRouteConfiguration_Key_FragmentValidationError"
}

// Error satisfies the builtin error interface
func (e ScopedRouteConfiguration_Key_FragmentValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sScopedRouteConfiguration_Key_Fragment.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ScopedRouteConfiguration_Key_FragmentValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ScopedRouteConfiguration_Key_FragmentValidationError{}
