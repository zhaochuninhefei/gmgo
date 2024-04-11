//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/api/v2/route.proto

package apiv2

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

// Validate checks the field values on RouteConfiguration with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *RouteConfiguration) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on RouteConfiguration with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// RouteConfigurationMultiError, or nil if none found.
func (m *RouteConfiguration) ValidateAll() error {
	return m.validate(true)
}

func (m *RouteConfiguration) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Name

	for idx, item := range m.GetVirtualHosts() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, RouteConfigurationValidationError{
						field:  fmt.Sprintf("VirtualHosts[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, RouteConfigurationValidationError{
						field:  fmt.Sprintf("VirtualHosts[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RouteConfigurationValidationError{
					field:  fmt.Sprintf("VirtualHosts[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if all {
		switch v := interface{}(m.GetVhds()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, RouteConfigurationValidationError{
					field:  "Vhds",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, RouteConfigurationValidationError{
					field:  "Vhds",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetVhds()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return RouteConfigurationValidationError{
				field:  "Vhds",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	for idx, item := range m.GetInternalOnlyHeaders() {
		_, _ = idx, item

		if !_RouteConfiguration_InternalOnlyHeaders_Pattern.MatchString(item) {
			err := RouteConfigurationValidationError{
				field:  fmt.Sprintf("InternalOnlyHeaders[%v]", idx),
				reason: "value does not match regex pattern \"^[^\\x00\\n\\r]*$\"",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if len(m.GetResponseHeadersToAdd()) > 1000 {
		err := RouteConfigurationValidationError{
			field:  "ResponseHeadersToAdd",
			reason: "value must contain no more than 1000 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetResponseHeadersToAdd() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, RouteConfigurationValidationError{
						field:  fmt.Sprintf("ResponseHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, RouteConfigurationValidationError{
						field:  fmt.Sprintf("ResponseHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RouteConfigurationValidationError{
					field:  fmt.Sprintf("ResponseHeadersToAdd[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetResponseHeadersToRemove() {
		_, _ = idx, item

		if !_RouteConfiguration_ResponseHeadersToRemove_Pattern.MatchString(item) {
			err := RouteConfigurationValidationError{
				field:  fmt.Sprintf("ResponseHeadersToRemove[%v]", idx),
				reason: "value does not match regex pattern \"^[^\\x00\\n\\r]*$\"",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if len(m.GetRequestHeadersToAdd()) > 1000 {
		err := RouteConfigurationValidationError{
			field:  "RequestHeadersToAdd",
			reason: "value must contain no more than 1000 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetRequestHeadersToAdd() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, RouteConfigurationValidationError{
						field:  fmt.Sprintf("RequestHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, RouteConfigurationValidationError{
						field:  fmt.Sprintf("RequestHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RouteConfigurationValidationError{
					field:  fmt.Sprintf("RequestHeadersToAdd[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetRequestHeadersToRemove() {
		_, _ = idx, item

		if !_RouteConfiguration_RequestHeadersToRemove_Pattern.MatchString(item) {
			err := RouteConfigurationValidationError{
				field:  fmt.Sprintf("RequestHeadersToRemove[%v]", idx),
				reason: "value does not match regex pattern \"^[^\\x00\\n\\r]*$\"",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	// no validation rules for MostSpecificHeaderMutationsWins

	if all {
		switch v := interface{}(m.GetValidateClusters()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, RouteConfigurationValidationError{
					field:  "ValidateClusters",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, RouteConfigurationValidationError{
					field:  "ValidateClusters",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetValidateClusters()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return RouteConfigurationValidationError{
				field:  "ValidateClusters",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return RouteConfigurationMultiError(errors)
	}

	return nil
}

// RouteConfigurationMultiError is an error wrapping multiple validation errors
// returned by RouteConfiguration.ValidateAll() if the designated constraints
// aren't met.
type RouteConfigurationMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m RouteConfigurationMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m RouteConfigurationMultiError) AllErrors() []error { return m }

// RouteConfigurationValidationError is the validation error returned by
// RouteConfiguration.Validate if the designated constraints aren't met.
type RouteConfigurationValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RouteConfigurationValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RouteConfigurationValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RouteConfigurationValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RouteConfigurationValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RouteConfigurationValidationError) ErrorName() string {
	return "RouteConfigurationValidationError"
}

// Error satisfies the builtin error interface
func (e RouteConfigurationValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRouteConfiguration.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RouteConfigurationValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RouteConfigurationValidationError{}

var _RouteConfiguration_InternalOnlyHeaders_Pattern = regexp.MustCompile("^[^\x00\n\r]*$")

var _RouteConfiguration_ResponseHeadersToRemove_Pattern = regexp.MustCompile("^[^\x00\n\r]*$")

var _RouteConfiguration_RequestHeadersToRemove_Pattern = regexp.MustCompile("^[^\x00\n\r]*$")

// Validate checks the field values on Vhds with the rules defined in the proto
// definition for this message. If any rules are violated, the first error
// encountered is returned, or nil if there are no violations.
func (m *Vhds) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Vhds with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in VhdsMultiError, or nil if none found.
func (m *Vhds) ValidateAll() error {
	return m.validate(true)
}

func (m *Vhds) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetConfigSource() == nil {
		err := VhdsValidationError{
			field:  "ConfigSource",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetConfigSource()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, VhdsValidationError{
					field:  "ConfigSource",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, VhdsValidationError{
					field:  "ConfigSource",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetConfigSource()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return VhdsValidationError{
				field:  "ConfigSource",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return VhdsMultiError(errors)
	}

	return nil
}

// VhdsMultiError is an error wrapping multiple validation errors returned by
// Vhds.ValidateAll() if the designated constraints aren't met.
type VhdsMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m VhdsMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m VhdsMultiError) AllErrors() []error { return m }

// VhdsValidationError is the validation error returned by Vhds.Validate if the
// designated constraints aren't met.
type VhdsValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e VhdsValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e VhdsValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e VhdsValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e VhdsValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e VhdsValidationError) ErrorName() string { return "VhdsValidationError" }

// Error satisfies the builtin error interface
func (e VhdsValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sVhds.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = VhdsValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = VhdsValidationError{}
