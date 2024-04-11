//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/filter/network/zookeeper_proxy/v1alpha1/zookeeper_proxy.proto

package v1alpha1

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

// Validate checks the field values on ZooKeeperProxy with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *ZooKeeperProxy) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ZooKeeperProxy with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in ZooKeeperProxyMultiError,
// or nil if none found.
func (m *ZooKeeperProxy) ValidateAll() error {
	return m.validate(true)
}

func (m *ZooKeeperProxy) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(m.GetStatPrefix()) < 1 {
		err := ZooKeeperProxyValidationError{
			field:  "StatPrefix",
			reason: "value length must be at least 1 bytes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	// no validation rules for AccessLog

	if all {
		switch v := interface{}(m.GetMaxPacketBytes()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ZooKeeperProxyValidationError{
					field:  "MaxPacketBytes",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ZooKeeperProxyValidationError{
					field:  "MaxPacketBytes",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetMaxPacketBytes()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ZooKeeperProxyValidationError{
				field:  "MaxPacketBytes",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return ZooKeeperProxyMultiError(errors)
	}

	return nil
}

// ZooKeeperProxyMultiError is an error wrapping multiple validation errors
// returned by ZooKeeperProxy.ValidateAll() if the designated constraints
// aren't met.
type ZooKeeperProxyMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ZooKeeperProxyMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ZooKeeperProxyMultiError) AllErrors() []error { return m }

// ZooKeeperProxyValidationError is the validation error returned by
// ZooKeeperProxy.Validate if the designated constraints aren't met.
type ZooKeeperProxyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ZooKeeperProxyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ZooKeeperProxyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ZooKeeperProxyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ZooKeeperProxyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ZooKeeperProxyValidationError) ErrorName() string { return "ZooKeeperProxyValidationError" }

// Error satisfies the builtin error interface
func (e ZooKeeperProxyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sZooKeeperProxy.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ZooKeeperProxyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ZooKeeperProxyValidationError{}
