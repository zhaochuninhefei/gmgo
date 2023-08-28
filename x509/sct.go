package x509

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// sct.go 此处仅为`certinfo.go`的`CertificateText`函数提供对其他包含SCT扩展信息的x509证书解析对应的SCT情报，
//  并不是为`x509`包提供完整的SCT扩展信息功能。
//
// x509证书中的扩展信息 `1.3.6.1.4.1.11129.2.4.2`是用来存储证书透明度（Certificate Transparency，CT）的签名证书时间戳（Signed Certificate Timestamp，SCT）的列表。
// 证书透明度是一种机制，用于检测和防止错误或恶意的证书颁发。
// 签名证书时间戳是一种证明，表明一个证书已经被提交到一个公开的、可审计的CT日志服务器。
// 这样，浏览器可以验证一个证书是否在CT日志中存在，从而增加了证书的可信度。
//
// SCT的使用场景主要是在TLS协议中，它可以让客户端检查服务器证书是否被记录在公开的CT日志中。
// golang的`x509`包的主要目标是提供与公共信任的TLS证书生态系统和其策略和约束的兼容性，而不是支持所有可能的X509扩展。
//
// x509证书中的扩展信息 `1.3.6.1.4.1.11129.2.4.2`的格式是由RFC 6962第3.3节定义的。它是一个ASN.1结构，包含一个或多个SCT结构。每个SCT结构包含以下字段¹：
//  - 版本：一个字节，表示SCT的版本号。
//  - 日志ID：一个32字节的哈希值，表示CT日志服务器的公钥。
//  - 时间戳：一个64位的整数，表示SCT的生成时间。
//  - 扩展：一个可选的字段，表示SCT的额外信息。
//  - 签名：一个ECDSA或RSA签名，表示CT日志服务器对SCT的认可。
//
// RFC 6962第3.3节: `https://datatracker.ietf.org/doc/html/rfc6962#page-13`

// 扩展信息 Signed Certificate Timestamps 证书签名时间戳 : 1.3.6.1.4.1.11129.2.4.2
var oidExtensionSCT = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// SerializedSCT represents a single TLS-encoded signed certificate timestamp, from RFC6962 s3.3.
type SerializedSCT struct {
	Val []byte `tls:"minlen:1,maxlen:65535"`
}

// SignedCertificateTimestampList is a list of signed certificate timestamps, from RFC6962 s3.3.
type SignedCertificateTimestampList struct {
	SCTList []SerializedSCT `tls:"minlen:1,maxlen:65335"`
}

func UnmarshalSCT(b []byte, val interface{}) ([]byte, error) {
	return UnmarshalWithParams(b, val, "")
}

// UnmarshalWithParams allows field parameters to be specified for the
// top-level element. The form of the params is the same as the field tags.
func UnmarshalWithParams(b []byte, val interface{}, params string) ([]byte, error) {
	info, err := fieldTagToFieldInfo(params, "")
	if err != nil {
		return nil, err
	}
	// The passed in interface{} is a pointer (to allow the value to be written
	// to); extract the pointed-to object as a reflect.Value, so parseField
	// can do various introspection things.
	v := reflect.ValueOf(val).Elem()
	offset, err := parseField(v, b, 0, info)
	if err != nil {
		return nil, err
	}
	return b[offset:], nil
}

// Given a tag string, return a fieldInfo describing the field.
func fieldTagToFieldInfo(str string, name string) (*fieldInfo, error) {
	var info *fieldInfo
	// Iterate over clauses in the tag, ignoring any that don't parse properly.
	for _, part := range strings.Split(str, ",") {
		switch {
		case strings.HasPrefix(part, "maxval:"):
			if v, err := strconv.ParseUint(part[7:], 10, 64); err == nil {
				info = &fieldInfo{count: byteCount(v), countSet: true}
			}
		case strings.HasPrefix(part, "size:"):
			if sz, err := strconv.ParseUint(part[5:], 10, 32); err == nil {
				info = &fieldInfo{count: uint(sz), countSet: true}
			}
		case strings.HasPrefix(part, "maxlen:"):
			v, err := strconv.ParseUint(part[7:], 10, 64)
			if err != nil {
				continue
			}
			if info == nil {
				info = &fieldInfo{}
			}
			info.count = byteCount(v)
			info.countSet = true
			info.maxlen = v
		case strings.HasPrefix(part, "minlen:"):
			v, err := strconv.ParseUint(part[7:], 10, 64)
			if err != nil {
				continue
			}
			if info == nil {
				info = &fieldInfo{}
			}
			info.minlen = v
		case strings.HasPrefix(part, "selector:"):
			if info == nil {
				info = &fieldInfo{}
			}
			info.selector = part[9:]
		case strings.HasPrefix(part, "val:"):
			v, err := strconv.ParseUint(part[4:], 10, 64)
			if err != nil {
				continue
			}
			if info == nil {
				info = &fieldInfo{}
			}
			info.val = v
		}
	}
	if info != nil {
		info.name = name
		if info.selector == "" {
			if info.count < 1 {
				return nil, structuralError{name, "field of unknown size in " + str}
			} else if info.count > 8 {
				return nil, structuralError{name, "specified size too large in " + str}
			} else if info.minlen > info.maxlen {
				return nil, structuralError{name, "specified length range inverted in " + str}
			} else if info.val > 0 {
				return nil, structuralError{name, "specified selector value but not field in " + str}
			}
		}
	} else if name != "" {
		info = &fieldInfo{name: name}
	}
	return info, nil
}

type fieldInfo struct {
	count    uint // Number of bytes
	countSet bool
	minlen   uint64 // Only relevant for slices
	maxlen   uint64 // Only relevant for slices
	selector string // Only relevant for select sub-values
	val      uint64 // Only relevant for select sub-values
	name     string // Used for better error messages
}

func (i *fieldInfo) fieldName() string {
	if i == nil {
		return ""
	}
	return i.name
}

// Check that a value fits into a field described by a fieldInfo structure.
func (i *fieldInfo) check(val uint64, fldName string) error {
	if val >= (1 << (8 * i.count)) {
		return structuralError{fldName, fmt.Sprintf("value %d too large for size", val)}
	}
	if i.maxlen != 0 {
		if val < i.minlen {
			return structuralError{fldName, fmt.Sprintf("value %d too small for minimum %d", val, i.minlen)}
		}
		if val > i.maxlen {
			return structuralError{fldName, fmt.Sprintf("value %d too large for maximum %d", val, i.maxlen)}
		}
	}
	return nil
}

// A structuralError suggests that the TLS data is valid, but the Go type
// which is receiving it doesn't match.
type structuralError struct {
	field string
	msg   string
}

func (e structuralError) Error() string {
	var prefix string
	if e.field != "" {
		prefix = e.field + ": "
	}
	return "tls: structure error: " + prefix + e.msg
}

// Return the number of bytes needed to encode values up to (and including) x.
func byteCount(x uint64) uint {
	switch {
	case x < 0x100:
		return 1
	case x < 0x10000:
		return 2
	case x < 0x1000000:
		return 3
	case x < 0x100000000:
		return 4
	case x < 0x10000000000:
		return 5
	case x < 0x1000000000000:
		return 6
	case x < 0x100000000000000:
		return 7
	default:
		return 8
	}
}

// Uint24 is an unsigned 3-byte integer.
type Uint24 uint32

// Enum is an unsigned integer.
type Enum uint64

var (
	uint8Type  = reflect.TypeOf(uint8(0))
	uint16Type = reflect.TypeOf(uint16(0))
	uint24Type = reflect.TypeOf(Uint24(0))
	uint32Type = reflect.TypeOf(uint32(0))
	uint64Type = reflect.TypeOf(uint64(0))
	enumType   = reflect.TypeOf(Enum(0))
)

// A syntaxError suggests that the TLS data is invalid.
type syntaxError struct {
	field string
	msg   string
}

func (e syntaxError) Error() string {
	var prefix string
	if e.field != "" {
		prefix = e.field + ": "
	}
	return "tls: syntax error: " + prefix + e.msg
}

// parseField is the main parsing function. Given a byte slice and an offset
// (in bytes) into the data, it will try to parse a suitable ASN.1 value out
// and store it in the given Value.
func parseField(v reflect.Value, data []byte, initOffset int, info *fieldInfo) (int, error) {
	offset := initOffset
	rest := data[offset:]

	fieldType := v.Type()
	// First look for known fixed types.
	switch fieldType {
	case uint8Type:
		if len(rest) < 1 {
			return offset, syntaxError{info.fieldName(), "truncated uint8"}
		}
		v.SetUint(uint64(rest[0]))
		offset++
		return offset, nil
	case uint16Type:
		if len(rest) < 2 {
			return offset, syntaxError{info.fieldName(), "truncated uint16"}
		}
		v.SetUint(uint64(binary.BigEndian.Uint16(rest)))
		offset += 2
		return offset, nil
	case uint24Type:
		if len(rest) < 3 {
			return offset, syntaxError{info.fieldName(), "truncated uint24"}
		}
		v.SetUint(uint64(data[0])<<16 | uint64(data[1])<<8 | uint64(data[2]))
		offset += 3
		return offset, nil
	case uint32Type:
		if len(rest) < 4 {
			return offset, syntaxError{info.fieldName(), "truncated uint32"}
		}
		v.SetUint(uint64(binary.BigEndian.Uint32(rest)))
		offset += 4
		return offset, nil
	case uint64Type:
		if len(rest) < 8 {
			return offset, syntaxError{info.fieldName(), "truncated uint64"}
		}
		v.SetUint(binary.BigEndian.Uint64(rest))
		offset += 8
		return offset, nil
	}

	// Now deal with user-defined types.
	switch v.Kind() {
	case enumType.Kind():
		// Assume that anything of the same kind as Enum is an Enum, so that
		// users can alias types of their own to Enum.
		val, err := readVarUint(rest, info)
		if err != nil {
			return offset, err
		}
		v.SetUint(val)
		offset += int(info.count)
		return offset, nil
	case reflect.Struct:
		structType := fieldType
		// TLS includes a select(Enum) {..} construct, where the value of an enum
		// indicates which variant field is present (like a C union). We require
		// that the enum value be an earlier field in the same structure (the selector),
		// and that each of the possible variant destination fields be pointers.
		// So the Go mapping looks like:
		//     type variantType struct {
		//         Which  tls.Enum  `tls:"size:1"`                // this is the selector
		//         Val1   *type1    `tls:"selector:Which,val:1"`  // this is a destination
		//         Val2   *type2    `tls:"selector:Which,val:1"`  // this is a destination
		//     }

		// To deal with this, we track any enum-like fields and their values...
		enums := make(map[string]uint64)
		// .. and we track which selector names we've seen (in the destination field tags),
		// and whether a destination for that selector has been chosen.
		selectorSeen := make(map[string]bool)
		for i := 0; i < structType.NumField(); i++ {
			// Find information about this field.
			tag := structType.Field(i).Tag.Get("tls")
			fieldInfo, err := fieldTagToFieldInfo(tag, structType.Field(i).Name)
			if err != nil {
				return offset, err
			}

			destination := v.Field(i)
			if fieldInfo.selector != "" {
				// This is a possible select(Enum) destination, so first check that the referenced
				// selector field has already been seen earlier in the struct.
				choice, ok := enums[fieldInfo.selector]
				if !ok {
					return offset, structuralError{fieldInfo.name, "selector not seen: " + fieldInfo.selector}
				}
				if structType.Field(i).Type.Kind() != reflect.Ptr {
					return offset, structuralError{fieldInfo.name, "choice field not a pointer type"}
				}
				// Is this the first mention of the selector field name?  If so, remember it.
				seen, ok := selectorSeen[fieldInfo.selector]
				if !ok {
					selectorSeen[fieldInfo.selector] = false
				}
				if choice != fieldInfo.val {
					// This destination field was not the chosen one, so make it nil (we checked
					// it was a pointer above).
					v.Field(i).Set(reflect.Zero(structType.Field(i).Type))
					continue
				}
				if seen {
					// We already saw a different destination field receive the value for this
					// selector value, which indicates a badly annotated structure.
					return offset, structuralError{fieldInfo.name, "duplicate selector value for " + fieldInfo.selector}
				}
				selectorSeen[fieldInfo.selector] = true
				// Make an object of the pointed-to type and parse into that.
				v.Field(i).Set(reflect.New(structType.Field(i).Type.Elem()))
				destination = v.Field(i).Elem()
			}
			offset, err = parseField(destination, data, offset, fieldInfo)
			if err != nil {
				return offset, err
			}

			// Remember any possible tls.Enum values encountered in case they are selectors.
			if structType.Field(i).Type.Kind() == enumType.Kind() {
				enums[structType.Field(i).Name] = v.Field(i).Uint()
			}

		}

		// Now we have seen all fields in the structure, check that all select(Enum) {..} selector
		// fields found a destination to put their data in.
		for selector, seen := range selectorSeen {
			if !seen {
				return offset, syntaxError{info.fieldName(), selector + ": unhandled value for selector"}
			}
		}
		return offset, nil
	case reflect.Array:
		datalen := v.Len()

		if datalen > len(rest) {
			return offset, syntaxError{info.fieldName(), "truncated array"}
		}
		inner := rest[:datalen]
		offset += datalen
		if fieldType.Elem().Kind() != reflect.Uint8 {
			// Only byte/uint8 arrays are supported
			return offset, structuralError{info.fieldName(), "unsupported array type: " + v.Type().String()}
		}
		reflect.Copy(v, reflect.ValueOf(inner))
		return offset, nil

	case reflect.Slice:
		sliceType := fieldType
		// Slices represent variable-length vectors, which are prefixed by a length field.
		// The fieldInfo indicates the size of that length field.
		varlen, err := readVarUint(rest, info)
		if err != nil {
			return offset, err
		}
		datalen := int(varlen)
		offset += int(info.count)
		rest = rest[info.count:]

		if datalen > len(rest) {
			return offset, syntaxError{info.fieldName(), "truncated slice"}
		}
		inner := rest[:datalen]
		offset += datalen
		if fieldType.Elem().Kind() == reflect.Uint8 {
			// Fast version for []byte
			v.Set(reflect.MakeSlice(sliceType, datalen, datalen))
			reflect.Copy(v, reflect.ValueOf(inner))
			return offset, nil
		}

		v.Set(reflect.MakeSlice(sliceType, 0, datalen))
		single := reflect.New(sliceType.Elem())
		for innerOffset := 0; innerOffset < len(inner); {
			var err error
			innerOffset, err = parseField(single.Elem(), inner, innerOffset, nil)
			if err != nil {
				return offset, err
			}
			v.Set(reflect.Append(v, single.Elem()))
		}
		return offset, nil

	default:
		return offset, structuralError{info.fieldName(), fmt.Sprintf("unsupported type: %s of kind %s", fieldType, v.Kind())}
	}
}

// readVarUint reads an big-endian unsigned integer of the given size in
// bytes.
func readVarUint(data []byte, info *fieldInfo) (uint64, error) {
	if info == nil || !info.countSet {
		return 0, structuralError{info.fieldName(), "no field size information available"}
	}
	if len(data) < int(info.count) {
		return 0, syntaxError{info.fieldName(), "truncated variable-length integer"}
	}
	var result uint64
	for i := uint(0); i < info.count; i++ {
		result = (result << 8) | uint64(data[i])
	}
	if err := info.check(result, info.name); err != nil {
		return 0, err
	}
	return result, nil
}
