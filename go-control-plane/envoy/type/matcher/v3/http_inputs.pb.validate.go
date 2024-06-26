//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/type/matcher/v3/http_inputs.proto

package matcherv3

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

// Validate checks the field values on HttpRequestHeaderMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *HttpRequestHeaderMatchInput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HttpRequestHeaderMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// HttpRequestHeaderMatchInputMultiError, or nil if none found.
func (m *HttpRequestHeaderMatchInput) ValidateAll() error {
	return m.validate(true)
}

func (m *HttpRequestHeaderMatchInput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if !_HttpRequestHeaderMatchInput_HeaderName_Pattern.MatchString(m.GetHeaderName()) {
		err := HttpRequestHeaderMatchInputValidationError{
			field:  "HeaderName",
			reason: "value does not match regex pattern \"^[^\\x00\\n\\r]*$\"",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return HttpRequestHeaderMatchInputMultiError(errors)
	}

	return nil
}

// HttpRequestHeaderMatchInputMultiError is an error wrapping multiple
// validation errors returned by HttpRequestHeaderMatchInput.ValidateAll() if
// the designated constraints aren't met.
type HttpRequestHeaderMatchInputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HttpRequestHeaderMatchInputMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HttpRequestHeaderMatchInputMultiError) AllErrors() []error { return m }

// HttpRequestHeaderMatchInputValidationError is the validation error returned
// by HttpRequestHeaderMatchInput.Validate if the designated constraints
// aren't met.
type HttpRequestHeaderMatchInputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpRequestHeaderMatchInputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpRequestHeaderMatchInputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpRequestHeaderMatchInputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpRequestHeaderMatchInputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpRequestHeaderMatchInputValidationError) ErrorName() string {
	return "HttpRequestHeaderMatchInputValidationError"
}

// Error satisfies the builtin error interface
func (e HttpRequestHeaderMatchInputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpRequestHeaderMatchInput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpRequestHeaderMatchInputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpRequestHeaderMatchInputValidationError{}

var _HttpRequestHeaderMatchInput_HeaderName_Pattern = regexp.MustCompile("^[^\x00\n\r]*$")

// Validate checks the field values on HttpRequestTrailerMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *HttpRequestTrailerMatchInput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HttpRequestTrailerMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// HttpRequestTrailerMatchInputMultiError, or nil if none found.
func (m *HttpRequestTrailerMatchInput) ValidateAll() error {
	return m.validate(true)
}

func (m *HttpRequestTrailerMatchInput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if !_HttpRequestTrailerMatchInput_HeaderName_Pattern.MatchString(m.GetHeaderName()) {
		err := HttpRequestTrailerMatchInputValidationError{
			field:  "HeaderName",
			reason: "value does not match regex pattern \"^[^\\x00\\n\\r]*$\"",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return HttpRequestTrailerMatchInputMultiError(errors)
	}

	return nil
}

// HttpRequestTrailerMatchInputMultiError is an error wrapping multiple
// validation errors returned by HttpRequestTrailerMatchInput.ValidateAll() if
// the designated constraints aren't met.
type HttpRequestTrailerMatchInputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HttpRequestTrailerMatchInputMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HttpRequestTrailerMatchInputMultiError) AllErrors() []error { return m }

// HttpRequestTrailerMatchInputValidationError is the validation error returned
// by HttpRequestTrailerMatchInput.Validate if the designated constraints
// aren't met.
type HttpRequestTrailerMatchInputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpRequestTrailerMatchInputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpRequestTrailerMatchInputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpRequestTrailerMatchInputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpRequestTrailerMatchInputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpRequestTrailerMatchInputValidationError) ErrorName() string {
	return "HttpRequestTrailerMatchInputValidationError"
}

// Error satisfies the builtin error interface
func (e HttpRequestTrailerMatchInputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpRequestTrailerMatchInput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpRequestTrailerMatchInputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpRequestTrailerMatchInputValidationError{}

var _HttpRequestTrailerMatchInput_HeaderName_Pattern = regexp.MustCompile("^[^\x00\n\r]*$")

// Validate checks the field values on HttpResponseHeaderMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *HttpResponseHeaderMatchInput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HttpResponseHeaderMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// HttpResponseHeaderMatchInputMultiError, or nil if none found.
func (m *HttpResponseHeaderMatchInput) ValidateAll() error {
	return m.validate(true)
}

func (m *HttpResponseHeaderMatchInput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if !_HttpResponseHeaderMatchInput_HeaderName_Pattern.MatchString(m.GetHeaderName()) {
		err := HttpResponseHeaderMatchInputValidationError{
			field:  "HeaderName",
			reason: "value does not match regex pattern \"^[^\\x00\\n\\r]*$\"",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return HttpResponseHeaderMatchInputMultiError(errors)
	}

	return nil
}

// HttpResponseHeaderMatchInputMultiError is an error wrapping multiple
// validation errors returned by HttpResponseHeaderMatchInput.ValidateAll() if
// the designated constraints aren't met.
type HttpResponseHeaderMatchInputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HttpResponseHeaderMatchInputMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HttpResponseHeaderMatchInputMultiError) AllErrors() []error { return m }

// HttpResponseHeaderMatchInputValidationError is the validation error returned
// by HttpResponseHeaderMatchInput.Validate if the designated constraints
// aren't met.
type HttpResponseHeaderMatchInputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpResponseHeaderMatchInputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpResponseHeaderMatchInputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpResponseHeaderMatchInputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpResponseHeaderMatchInputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpResponseHeaderMatchInputValidationError) ErrorName() string {
	return "HttpResponseHeaderMatchInputValidationError"
}

// Error satisfies the builtin error interface
func (e HttpResponseHeaderMatchInputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpResponseHeaderMatchInput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpResponseHeaderMatchInputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpResponseHeaderMatchInputValidationError{}

var _HttpResponseHeaderMatchInput_HeaderName_Pattern = regexp.MustCompile("^[^\x00\n\r]*$")

// Validate checks the field values on HttpResponseTrailerMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *HttpResponseTrailerMatchInput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HttpResponseTrailerMatchInput with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// HttpResponseTrailerMatchInputMultiError, or nil if none found.
func (m *HttpResponseTrailerMatchInput) ValidateAll() error {
	return m.validate(true)
}

func (m *HttpResponseTrailerMatchInput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if !_HttpResponseTrailerMatchInput_HeaderName_Pattern.MatchString(m.GetHeaderName()) {
		err := HttpResponseTrailerMatchInputValidationError{
			field:  "HeaderName",
			reason: "value does not match regex pattern \"^[^\\x00\\n\\r]*$\"",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return HttpResponseTrailerMatchInputMultiError(errors)
	}

	return nil
}

// HttpResponseTrailerMatchInputMultiError is an error wrapping multiple
// validation errors returned by HttpResponseTrailerMatchInput.ValidateAll()
// if the designated constraints aren't met.
type HttpResponseTrailerMatchInputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HttpResponseTrailerMatchInputMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HttpResponseTrailerMatchInputMultiError) AllErrors() []error { return m }

// HttpResponseTrailerMatchInputValidationError is the validation error
// returned by HttpResponseTrailerMatchInput.Validate if the designated
// constraints aren't met.
type HttpResponseTrailerMatchInputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpResponseTrailerMatchInputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpResponseTrailerMatchInputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpResponseTrailerMatchInputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpResponseTrailerMatchInputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpResponseTrailerMatchInputValidationError) ErrorName() string {
	return "HttpResponseTrailerMatchInputValidationError"
}

// Error satisfies the builtin error interface
func (e HttpResponseTrailerMatchInputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpResponseTrailerMatchInput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpResponseTrailerMatchInputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpResponseTrailerMatchInputValidationError{}

var _HttpResponseTrailerMatchInput_HeaderName_Pattern = regexp.MustCompile("^[^\x00\n\r]*$")

// Validate checks the field values on HttpRequestQueryParamMatchInput with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *HttpRequestQueryParamMatchInput) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on HttpRequestQueryParamMatchInput with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// HttpRequestQueryParamMatchInputMultiError, or nil if none found.
func (m *HttpRequestQueryParamMatchInput) ValidateAll() error {
	return m.validate(true)
}

func (m *HttpRequestQueryParamMatchInput) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetQueryParam()) < 1 {
		err := HttpRequestQueryParamMatchInputValidationError{
			field:  "QueryParam",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return HttpRequestQueryParamMatchInputMultiError(errors)
	}

	return nil
}

// HttpRequestQueryParamMatchInputMultiError is an error wrapping multiple
// validation errors returned by HttpRequestQueryParamMatchInput.ValidateAll()
// if the designated constraints aren't met.
type HttpRequestQueryParamMatchInputMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m HttpRequestQueryParamMatchInputMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m HttpRequestQueryParamMatchInputMultiError) AllErrors() []error { return m }

// HttpRequestQueryParamMatchInputValidationError is the validation error
// returned by HttpRequestQueryParamMatchInput.Validate if the designated
// constraints aren't met.
type HttpRequestQueryParamMatchInputValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e HttpRequestQueryParamMatchInputValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e HttpRequestQueryParamMatchInputValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e HttpRequestQueryParamMatchInputValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e HttpRequestQueryParamMatchInputValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e HttpRequestQueryParamMatchInputValidationError) ErrorName() string {
	return "HttpRequestQueryParamMatchInputValidationError"
}

// Error satisfies the builtin error interface
func (e HttpRequestQueryParamMatchInputValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sHttpRequestQueryParamMatchInput.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = HttpRequestQueryParamMatchInputValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = HttpRequestQueryParamMatchInputValidationError{}
