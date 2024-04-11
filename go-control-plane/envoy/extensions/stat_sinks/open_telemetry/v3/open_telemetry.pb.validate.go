//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/stat_sinks/open_telemetry/v3/open_telemetry.proto

package open_telemetryv3

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

// Validate checks the field values on SinkConfig with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *SinkConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on SinkConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in SinkConfigMultiError, or
// nil if none found.
func (m *SinkConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *SinkConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for ReportCountersAsDeltas

	// no validation rules for ReportHistogramsAsDeltas

	if all {
		switch v := interface{}(m.GetEmitTagsAsAttributes()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, SinkConfigValidationError{
					field:  "EmitTagsAsAttributes",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, SinkConfigValidationError{
					field:  "EmitTagsAsAttributes",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetEmitTagsAsAttributes()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return SinkConfigValidationError{
				field:  "EmitTagsAsAttributes",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetUseTagExtractedName()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, SinkConfigValidationError{
					field:  "UseTagExtractedName",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, SinkConfigValidationError{
					field:  "UseTagExtractedName",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetUseTagExtractedName()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return SinkConfigValidationError{
				field:  "UseTagExtractedName",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for Prefix

	oneofProtocolSpecifierPresent := false
	switch v := m.ProtocolSpecifier.(type) {
	case *SinkConfig_GrpcService:
		if v == nil {
			err := SinkConfigValidationError{
				field:  "ProtocolSpecifier",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofProtocolSpecifierPresent = true

		if m.GetGrpcService() == nil {
			err := SinkConfigValidationError{
				field:  "GrpcService",
				reason: "value is required",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetGrpcService()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, SinkConfigValidationError{
						field:  "GrpcService",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, SinkConfigValidationError{
						field:  "GrpcService",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetGrpcService()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return SinkConfigValidationError{
					field:  "GrpcService",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}
	if !oneofProtocolSpecifierPresent {
		err := SinkConfigValidationError{
			field:  "ProtocolSpecifier",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return SinkConfigMultiError(errors)
	}

	return nil
}

// SinkConfigMultiError is an error wrapping multiple validation errors
// returned by SinkConfig.ValidateAll() if the designated constraints aren't met.
type SinkConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m SinkConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m SinkConfigMultiError) AllErrors() []error { return m }

// SinkConfigValidationError is the validation error returned by
// SinkConfig.Validate if the designated constraints aren't met.
type SinkConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e SinkConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e SinkConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e SinkConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e SinkConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e SinkConfigValidationError) ErrorName() string { return "SinkConfigValidationError" }

// Error satisfies the builtin error interface
func (e SinkConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sSinkConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = SinkConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = SinkConfigValidationError{}
