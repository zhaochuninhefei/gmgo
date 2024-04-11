//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: contrib/envoy/extensions/filters/network/generic_proxy/codecs/kafka/v3/kafka.proto

package kafkav3

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

// Validate checks the field values on KafkaCodecConfig with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *KafkaCodecConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on KafkaCodecConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// KafkaCodecConfigMultiError, or nil if none found.
func (m *KafkaCodecConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *KafkaCodecConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return KafkaCodecConfigMultiError(errors)
	}

	return nil
}

// KafkaCodecConfigMultiError is an error wrapping multiple validation errors
// returned by KafkaCodecConfig.ValidateAll() if the designated constraints
// aren't met.
type KafkaCodecConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m KafkaCodecConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m KafkaCodecConfigMultiError) AllErrors() []error { return m }

// KafkaCodecConfigValidationError is the validation error returned by
// KafkaCodecConfig.Validate if the designated constraints aren't met.
type KafkaCodecConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e KafkaCodecConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e KafkaCodecConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e KafkaCodecConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e KafkaCodecConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e KafkaCodecConfigValidationError) ErrorName() string { return "KafkaCodecConfigValidationError" }

// Error satisfies the builtin error interface
func (e KafkaCodecConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sKafkaCodecConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = KafkaCodecConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = KafkaCodecConfigValidationError{}
