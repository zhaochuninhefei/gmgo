//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/access_loggers/file/v3/file.proto

package filev3

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

// Validate checks the field values on FileAccessLog with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *FileAccessLog) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on FileAccessLog with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in FileAccessLogMultiError, or
// nil if none found.
func (m *FileAccessLog) ValidateAll() error {
	return m.validate(true)
}

func (m *FileAccessLog) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetPath()) < 1 {
		err := FileAccessLogValidationError{
			field:  "Path",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	switch v := m.AccessLogFormat.(type) {
	case *FileAccessLog_Format:
		if v == nil {
			err := FileAccessLogValidationError{
				field:  "AccessLogFormat",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		// no validation rules for Format
	case *FileAccessLog_JsonFormat:
		if v == nil {
			err := FileAccessLogValidationError{
				field:  "AccessLogFormat",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetJsonFormat()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, FileAccessLogValidationError{
						field:  "JsonFormat",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, FileAccessLogValidationError{
						field:  "JsonFormat",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetJsonFormat()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return FileAccessLogValidationError{
					field:  "JsonFormat",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *FileAccessLog_TypedJsonFormat:
		if v == nil {
			err := FileAccessLogValidationError{
				field:  "AccessLogFormat",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetTypedJsonFormat()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, FileAccessLogValidationError{
						field:  "TypedJsonFormat",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, FileAccessLogValidationError{
						field:  "TypedJsonFormat",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetTypedJsonFormat()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return FileAccessLogValidationError{
					field:  "TypedJsonFormat",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *FileAccessLog_LogFormat:
		if v == nil {
			err := FileAccessLogValidationError{
				field:  "AccessLogFormat",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if m.GetLogFormat() == nil {
			err := FileAccessLogValidationError{
				field:  "LogFormat",
				reason: "value is required",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetLogFormat()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, FileAccessLogValidationError{
						field:  "LogFormat",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, FileAccessLogValidationError{
						field:  "LogFormat",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetLogFormat()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return FileAccessLogValidationError{
					field:  "LogFormat",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}

	if len(errors) > 0 {
		return FileAccessLogMultiError(errors)
	}

	return nil
}

// FileAccessLogMultiError is an error wrapping multiple validation errors
// returned by FileAccessLog.ValidateAll() if the designated constraints
// aren't met.
type FileAccessLogMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m FileAccessLogMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m FileAccessLogMultiError) AllErrors() []error { return m }

// FileAccessLogValidationError is the validation error returned by
// FileAccessLog.Validate if the designated constraints aren't met.
type FileAccessLogValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e FileAccessLogValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e FileAccessLogValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e FileAccessLogValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e FileAccessLogValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e FileAccessLogValidationError) ErrorName() string { return "FileAccessLogValidationError" }

// Error satisfies the builtin error interface
func (e FileAccessLogValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sFileAccessLog.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = FileAccessLogValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = FileAccessLogValidationError{}
