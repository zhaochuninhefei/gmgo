//go:build !disable_pgv

// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: contrib/envoy/extensions/filters/http/golang/v3alpha/golang.proto

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

// Validate checks the field values on Config with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *Config) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Config with the rules defined in the
// proto definition for this message. If any rules are violated, the result is
// a list of violation errors wrapped in ConfigMultiError, or nil if none found.
func (m *Config) ValidateAll() error {
	return m.validate(true)
}

func (m *Config) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetLibraryId()) < 1 {
		err := ConfigValidationError{
			field:  "LibraryId",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetLibraryPath()) < 1 {
		err := ConfigValidationError{
			field:  "LibraryPath",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetPluginName()) < 1 {
		err := ConfigValidationError{
			field:  "PluginName",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetPluginConfig()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "PluginConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ConfigValidationError{
					field:  "PluginConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetPluginConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ConfigValidationError{
				field:  "PluginConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if _, ok := Config_MergePolicy_name[int32(m.GetMergePolicy())]; !ok {
		err := ConfigValidationError{
			field:  "MergePolicy",
			reason: "value must be one of the defined enum values",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return ConfigMultiError(errors)
	}

	return nil
}

// ConfigMultiError is an error wrapping multiple validation errors returned by
// Config.ValidateAll() if the designated constraints aren't met.
type ConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ConfigMultiError) AllErrors() []error { return m }

// ConfigValidationError is the validation error returned by Config.Validate if
// the designated constraints aren't met.
type ConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ConfigValidationError) ErrorName() string { return "ConfigValidationError" }

// Error satisfies the builtin error interface
func (e ConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ConfigValidationError{}

// Validate checks the field values on RouterPlugin with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *RouterPlugin) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on RouterPlugin with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in RouterPluginMultiError, or
// nil if none found.
func (m *RouterPlugin) ValidateAll() error {
	return m.validate(true)
}

func (m *RouterPlugin) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	oneofOverridePresent := false
	switch v := m.Override.(type) {
	case *RouterPlugin_Disabled:
		if v == nil {
			err := RouterPluginValidationError{
				field:  "Override",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofOverridePresent = true

		if m.GetDisabled() != true {
			err := RouterPluginValidationError{
				field:  "Disabled",
				reason: "value must equal true",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	case *RouterPlugin_Config:
		if v == nil {
			err := RouterPluginValidationError{
				field:  "Override",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofOverridePresent = true

		if all {
			switch v := interface{}(m.GetConfig()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, RouterPluginValidationError{
						field:  "Config",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, RouterPluginValidationError{
						field:  "Config",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RouterPluginValidationError{
					field:  "Config",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}
	if !oneofOverridePresent {
		err := RouterPluginValidationError{
			field:  "Override",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return RouterPluginMultiError(errors)
	}

	return nil
}

// RouterPluginMultiError is an error wrapping multiple validation errors
// returned by RouterPlugin.ValidateAll() if the designated constraints aren't met.
type RouterPluginMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m RouterPluginMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m RouterPluginMultiError) AllErrors() []error { return m }

// RouterPluginValidationError is the validation error returned by
// RouterPlugin.Validate if the designated constraints aren't met.
type RouterPluginValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RouterPluginValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RouterPluginValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RouterPluginValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RouterPluginValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RouterPluginValidationError) ErrorName() string { return "RouterPluginValidationError" }

// Error satisfies the builtin error interface
func (e RouterPluginValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRouterPlugin.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RouterPluginValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RouterPluginValidationError{}

// Validate checks the field values on ConfigsPerRoute with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *ConfigsPerRoute) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ConfigsPerRoute with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// ConfigsPerRouteMultiError, or nil if none found.
func (m *ConfigsPerRoute) ValidateAll() error {
	return m.validate(true)
}

func (m *ConfigsPerRoute) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	{
		sorted_keys := make([]string, len(m.GetPluginsConfig()))
		i := 0
		for key := range m.GetPluginsConfig() {
			sorted_keys[i] = key
			i++
		}
		sort.Slice(sorted_keys, func(i, j int) bool { return sorted_keys[i] < sorted_keys[j] })
		for _, key := range sorted_keys {
			val := m.GetPluginsConfig()[key]
			_ = val

			// no validation rules for PluginsConfig[key]

			if all {
				switch v := interface{}(val).(type) {
				case interface{ ValidateAll() error }:
					if err := v.ValidateAll(); err != nil {
						errors = append(errors, ConfigsPerRouteValidationError{
							field:  fmt.Sprintf("PluginsConfig[%v]", key),
							reason: "embedded message failed validation",
							cause:  err,
						})
					}
				case interface{ Validate() error }:
					if err := v.Validate(); err != nil {
						errors = append(errors, ConfigsPerRouteValidationError{
							field:  fmt.Sprintf("PluginsConfig[%v]", key),
							reason: "embedded message failed validation",
							cause:  err,
						})
					}
				}
			} else if v, ok := interface{}(val).(interface{ Validate() error }); ok {
				if err := v.Validate(); err != nil {
					return ConfigsPerRouteValidationError{
						field:  fmt.Sprintf("PluginsConfig[%v]", key),
						reason: "embedded message failed validation",
						cause:  err,
					}
				}
			}

		}
	}

	if len(errors) > 0 {
		return ConfigsPerRouteMultiError(errors)
	}

	return nil
}

// ConfigsPerRouteMultiError is an error wrapping multiple validation errors
// returned by ConfigsPerRoute.ValidateAll() if the designated constraints
// aren't met.
type ConfigsPerRouteMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ConfigsPerRouteMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ConfigsPerRouteMultiError) AllErrors() []error { return m }

// ConfigsPerRouteValidationError is the validation error returned by
// ConfigsPerRoute.Validate if the designated constraints aren't met.
type ConfigsPerRouteValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ConfigsPerRouteValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ConfigsPerRouteValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ConfigsPerRouteValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ConfigsPerRouteValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ConfigsPerRouteValidationError) ErrorName() string { return "ConfigsPerRouteValidationError" }

// Error satisfies the builtin error interface
func (e ConfigsPerRouteValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sConfigsPerRoute.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ConfigsPerRouteValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ConfigsPerRouteValidationError{}
