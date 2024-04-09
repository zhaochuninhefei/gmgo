// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/clusters/dynamic_forward_proxy/v3/cluster.proto

package dynamic_forward_proxyv3

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

	v3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/cluster/v3"
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

	_ = v3.Cluster_LbPolicy(0)
)

// Validate checks the field values on ClusterConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *ClusterConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ClusterConfig with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in ClusterConfigMultiError, or
// nil if none found.
func (m *ClusterConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *ClusterConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for AllowInsecureClusterOptions

	// no validation rules for AllowCoalescedConnections

	switch v := m.ClusterImplementationSpecifier.(type) {
	case *ClusterConfig_DnsCacheConfig:
		if v == nil {
			err := ClusterConfigValidationError{
				field:  "ClusterImplementationSpecifier",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetDnsCacheConfig()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ClusterConfigValidationError{
						field:  "DnsCacheConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ClusterConfigValidationError{
						field:  "DnsCacheConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetDnsCacheConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterConfigValidationError{
					field:  "DnsCacheConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *ClusterConfig_SubClustersConfig:
		if v == nil {
			err := ClusterConfigValidationError{
				field:  "ClusterImplementationSpecifier",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetSubClustersConfig()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ClusterConfigValidationError{
						field:  "SubClustersConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ClusterConfigValidationError{
						field:  "SubClustersConfig",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetSubClustersConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ClusterConfigValidationError{
					field:  "SubClustersConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}

	if len(errors) > 0 {
		return ClusterConfigMultiError(errors)
	}

	return nil
}

// ClusterConfigMultiError is an error wrapping multiple validation errors
// returned by ClusterConfig.ValidateAll() if the designated constraints
// aren't met.
type ClusterConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ClusterConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ClusterConfigMultiError) AllErrors() []error { return m }

// ClusterConfigValidationError is the validation error returned by
// ClusterConfig.Validate if the designated constraints aren't met.
type ClusterConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ClusterConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ClusterConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ClusterConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ClusterConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ClusterConfigValidationError) ErrorName() string { return "ClusterConfigValidationError" }

// Error satisfies the builtin error interface
func (e ClusterConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sClusterConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ClusterConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ClusterConfigValidationError{}

// Validate checks the field values on SubClustersConfig with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *SubClustersConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on SubClustersConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// SubClustersConfigMultiError, or nil if none found.
func (m *SubClustersConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *SubClustersConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if _, ok := v3.Cluster_LbPolicy_name[int32(m.GetLbPolicy())]; !ok {
		err := SubClustersConfigValidationError{
			field:  "LbPolicy",
			reason: "value must be one of the defined enum values",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if wrapper := m.GetMaxSubClusters(); wrapper != nil {

		if wrapper.GetValue() <= 0 {
			err := SubClustersConfigValidationError{
				field:  "MaxSubClusters",
				reason: "value must be greater than 0",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if d := m.GetSubClusterTtl(); d != nil {
		dur, err := d.AsDuration(), d.CheckValid()
		if err != nil {
			err = SubClustersConfigValidationError{
				field:  "SubClusterTtl",
				reason: "value is not a valid duration",
				cause:  err,
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		} else {

			gt := time.Duration(0*time.Second + 0*time.Nanosecond)

			if dur <= gt {
				err := SubClustersConfigValidationError{
					field:  "SubClusterTtl",
					reason: "value must be greater than 0s",
				}
				if !all {
					return err
				}
				errors = append(errors, err)
			}

		}
	}

	for idx, item := range m.GetPreresolveClusters() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, SubClustersConfigValidationError{
						field:  fmt.Sprintf("PreresolveClusters[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, SubClustersConfigValidationError{
						field:  fmt.Sprintf("PreresolveClusters[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return SubClustersConfigValidationError{
					field:  fmt.Sprintf("PreresolveClusters[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return SubClustersConfigMultiError(errors)
	}

	return nil
}

// SubClustersConfigMultiError is an error wrapping multiple validation errors
// returned by SubClustersConfig.ValidateAll() if the designated constraints
// aren't met.
type SubClustersConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m SubClustersConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m SubClustersConfigMultiError) AllErrors() []error { return m }

// SubClustersConfigValidationError is the validation error returned by
// SubClustersConfig.Validate if the designated constraints aren't met.
type SubClustersConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e SubClustersConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e SubClustersConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e SubClustersConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e SubClustersConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e SubClustersConfigValidationError) ErrorName() string {
	return "SubClustersConfigValidationError"
}

// Error satisfies the builtin error interface
func (e SubClustersConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sSubClustersConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = SubClustersConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = SubClustersConfigValidationError{}
