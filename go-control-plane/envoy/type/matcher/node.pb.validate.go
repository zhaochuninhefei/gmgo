//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/type/matcher/node.proto

package matcher

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

// Validate checks the field values on NodeMatcher with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *NodeMatcher) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on NodeMatcher with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in NodeMatcherMultiError, or
// nil if none found.
func (m *NodeMatcher) ValidateAll() error {
	return m.validate(true)
}

func (m *NodeMatcher) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetNodeId()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, NodeMatcherValidationError{
					field:  "NodeId",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, NodeMatcherValidationError{
					field:  "NodeId",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetNodeId()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return NodeMatcherValidationError{
				field:  "NodeId",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	for idx, item := range m.GetNodeMetadatas() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, NodeMatcherValidationError{
						field:  fmt.Sprintf("NodeMetadatas[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, NodeMatcherValidationError{
						field:  fmt.Sprintf("NodeMetadatas[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return NodeMatcherValidationError{
					field:  fmt.Sprintf("NodeMetadatas[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return NodeMatcherMultiError(errors)
	}

	return nil
}

// NodeMatcherMultiError is an error wrapping multiple validation errors
// returned by NodeMatcher.ValidateAll() if the designated constraints aren't met.
type NodeMatcherMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m NodeMatcherMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m NodeMatcherMultiError) AllErrors() []error { return m }

// NodeMatcherValidationError is the validation error returned by
// NodeMatcher.Validate if the designated constraints aren't met.
type NodeMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e NodeMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e NodeMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e NodeMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e NodeMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e NodeMatcherValidationError) ErrorName() string { return "NodeMatcherValidationError" }

// Error satisfies the builtin error interface
func (e NodeMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sNodeMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = NodeMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = NodeMatcherValidationError{}
