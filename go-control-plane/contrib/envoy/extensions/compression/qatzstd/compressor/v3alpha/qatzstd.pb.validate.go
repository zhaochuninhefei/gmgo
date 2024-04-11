//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: contrib/envoy/extensions/compression/qatzstd/compressor/v3alpha/qatzstd.proto

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

// Validate checks the field values on Qatzstd with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *Qatzstd) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Qatzstd with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in QatzstdMultiError, or nil if none found.
func (m *Qatzstd) ValidateAll() error {
	return m.validate(true)
}

func (m *Qatzstd) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if wrapper := m.GetCompressionLevel(); wrapper != nil {

		if val := wrapper.GetValue(); val < 1 || val > 22 {
			err := QatzstdValidationError{
				field:  "CompressionLevel",
				reason: "value must be inside range [1, 22]",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	// no validation rules for EnableChecksum

	if _, ok := Qatzstd_Strategy_name[int32(m.GetStrategy())]; !ok {
		err := QatzstdValidationError{
			field:  "Strategy",
			reason: "value must be one of the defined enum values",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if wrapper := m.GetChunkSize(); wrapper != nil {

		if val := wrapper.GetValue(); val < 4096 || val > 65536 {
			err := QatzstdValidationError{
				field:  "ChunkSize",
				reason: "value must be inside range [4096, 65536]",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	// no validation rules for EnableQatZstd

	if wrapper := m.GetQatZstdFallbackThreshold(); wrapper != nil {

		if val := wrapper.GetValue(); val < 0 || val > 65536 {
			err := QatzstdValidationError{
				field:  "QatZstdFallbackThreshold",
				reason: "value must be inside range [0, 65536]",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if len(errors) > 0 {
		return QatzstdMultiError(errors)
	}

	return nil
}

// QatzstdMultiError is an error wrapping multiple validation errors returned
// by Qatzstd.ValidateAll() if the designated constraints aren't met.
type QatzstdMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m QatzstdMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m QatzstdMultiError) AllErrors() []error { return m }

// QatzstdValidationError is the validation error returned by Qatzstd.Validate
// if the designated constraints aren't met.
type QatzstdValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e QatzstdValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e QatzstdValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e QatzstdValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e QatzstdValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e QatzstdValidationError) ErrorName() string { return "QatzstdValidationError" }

// Error satisfies the builtin error interface
func (e QatzstdValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sQatzstd.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = QatzstdValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = QatzstdValidationError{}