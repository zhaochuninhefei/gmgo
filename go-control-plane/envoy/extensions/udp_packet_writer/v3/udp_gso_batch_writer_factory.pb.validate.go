//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/udp_packet_writer/v3/udp_gso_batch_writer_factory.proto

package udp_packet_writerv3

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

// Validate checks the field values on UdpGsoBatchWriterFactory with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *UdpGsoBatchWriterFactory) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on UdpGsoBatchWriterFactory with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// UdpGsoBatchWriterFactoryMultiError, or nil if none found.
func (m *UdpGsoBatchWriterFactory) ValidateAll() error {
	return m.validate(true)
}

func (m *UdpGsoBatchWriterFactory) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(errors) > 0 {
		return UdpGsoBatchWriterFactoryMultiError(errors)
	}

	return nil
}

// UdpGsoBatchWriterFactoryMultiError is an error wrapping multiple validation
// errors returned by UdpGsoBatchWriterFactory.ValidateAll() if the designated
// constraints aren't met.
type UdpGsoBatchWriterFactoryMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m UdpGsoBatchWriterFactoryMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m UdpGsoBatchWriterFactoryMultiError) AllErrors() []error { return m }

// UdpGsoBatchWriterFactoryValidationError is the validation error returned by
// UdpGsoBatchWriterFactory.Validate if the designated constraints aren't met.
type UdpGsoBatchWriterFactoryValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e UdpGsoBatchWriterFactoryValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e UdpGsoBatchWriterFactoryValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e UdpGsoBatchWriterFactoryValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e UdpGsoBatchWriterFactoryValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e UdpGsoBatchWriterFactoryValidationError) ErrorName() string {
	return "UdpGsoBatchWriterFactoryValidationError"
}

// Error satisfies the builtin error interface
func (e UdpGsoBatchWriterFactoryValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sUdpGsoBatchWriterFactory.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = UdpGsoBatchWriterFactoryValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = UdpGsoBatchWriterFactoryValidationError{}
