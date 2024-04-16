// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: envoy/extensions/http/header_formatters/preserve_case/v3/preserve_case.proto

package preserve_casev3

import (
	_ "gitee.com/zhaochuninhefei/gmgo/cncf_xds_go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders int32

const (
	// Use LowerCase on Envoy added headers.
	PreserveCaseFormatterConfig_DEFAULT PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders = 0
	// Use ProperCaseHeaderKeyFormatter on Envoy added headers that upper cases the first character
	// in each word. The first character as well as any alpha character following a special
	// character is upper cased.
	PreserveCaseFormatterConfig_PROPER_CASE PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders = 1
)

// Enum value maps for PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders.
var (
	PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders_name = map[int32]string{
		0: "DEFAULT",
		1: "PROPER_CASE",
	}
	PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders_value = map[string]int32{
		"DEFAULT":     0,
		"PROPER_CASE": 1,
	}
)

func (x PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders) Enum() *PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders {
	p := new(PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders)
	*p = x
	return p
}

func (x PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders) Descriptor() protoreflect.EnumDescriptor {
	return file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_enumTypes[0].Descriptor()
}

func (PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders) Type() protoreflect.EnumType {
	return &file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_enumTypes[0]
}

func (x PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders.Descriptor instead.
func (PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders) EnumDescriptor() ([]byte, []int) {
	return file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescGZIP(), []int{0, 0}
}

// Configuration for the preserve case header formatter.
// See the :ref:`header casing <config_http_conn_man_header_casing>` configuration guide for more
// information.
type PreserveCaseFormatterConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Allows forwarding reason phrase text.
	// This is off by default, and a standard reason phrase is used for a corresponding HTTP response code.
	ForwardReasonPhrase bool `protobuf:"varint,1,opt,name=forward_reason_phrase,json=forwardReasonPhrase,proto3" json:"forward_reason_phrase,omitempty"`
	// Type of formatter to use on headers which are added by Envoy (which are lower case by default).
	// The default type is DEFAULT, use LowerCase on Envoy headers.
	FormatterTypeOnEnvoyHeaders PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders `protobuf:"varint,2,opt,name=formatter_type_on_envoy_headers,json=formatterTypeOnEnvoyHeaders,proto3,enum=envoy.extensions.http.header_formatters.preserve_case.v3.PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders" json:"formatter_type_on_envoy_headers,omitempty"`
}

func (x *PreserveCaseFormatterConfig) Reset() {
	*x = PreserveCaseFormatterConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreserveCaseFormatterConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreserveCaseFormatterConfig) ProtoMessage() {}

func (x *PreserveCaseFormatterConfig) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreserveCaseFormatterConfig.ProtoReflect.Descriptor instead.
func (*PreserveCaseFormatterConfig) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescGZIP(), []int{0}
}

func (x *PreserveCaseFormatterConfig) GetForwardReasonPhrase() bool {
	if x != nil {
		return x.ForwardReasonPhrase
	}
	return false
}

func (x *PreserveCaseFormatterConfig) GetFormatterTypeOnEnvoyHeaders() PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders {
	if x != nil {
		return x.FormatterTypeOnEnvoyHeaders
	}
	return PreserveCaseFormatterConfig_DEFAULT
}

var File_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto protoreflect.FileDescriptor

var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc = []byte{
	0x0a, 0x4c, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x66,
	0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x70, 0x72, 0x65, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x38,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x66, 0x6f, 0x72,
	0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x5f, 0x63, 0x61, 0x73, 0x65, 0x2e, 0x76, 0x33, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xd2, 0x02, 0x0a, 0x1b, 0x50, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x43, 0x61, 0x73,
	0x65, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x32, 0x0a, 0x15, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x5f, 0x72, 0x65, 0x61, 0x73,
	0x6f, 0x6e, 0x5f, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x13, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x50, 0x68,
	0x72, 0x61, 0x73, 0x65, 0x12, 0xc1, 0x01, 0x0a, 0x1f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74,
	0x65, 0x72, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x6f, 0x6e, 0x5f, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x71,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x66, 0x6f,
	0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x50, 0x72, 0x65, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x43, 0x61, 0x73, 0x65, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x54,
	0x79, 0x70, 0x65, 0x4f, 0x6e, 0x45, 0x6e, 0x76, 0x6f, 0x79, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x73, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x82, 0x01, 0x02, 0x10, 0x01, 0x52, 0x1b, 0x66, 0x6f, 0x72,
	0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x4f, 0x6e, 0x45, 0x6e, 0x76, 0x6f,
	0x79, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x22, 0x3b, 0x0a, 0x1b, 0x46, 0x6f, 0x72, 0x6d,
	0x61, 0x74, 0x74, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x4f, 0x6e, 0x45, 0x6e, 0x76, 0x6f, 0x79,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x12, 0x0b, 0x0a, 0x07, 0x44, 0x45, 0x46, 0x41, 0x55,
	0x4c, 0x54, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b, 0x50, 0x52, 0x4f, 0x50, 0x45, 0x52, 0x5f, 0x43,
	0x41, 0x53, 0x45, 0x10, 0x01, 0x42, 0xd6, 0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02,
	0x0a, 0x46, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x66, 0x6f, 0x72,
	0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x5f, 0x63, 0x61, 0x73, 0x65, 0x2e, 0x76, 0x33, 0x42, 0x11, 0x50, 0x72, 0x65, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x43, 0x61, 0x73, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x6f, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d,
	0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x68, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x70, 0x72,
	0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x2f, 0x76, 0x33, 0x3b, 0x70,
	0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x76, 0x33, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescOnce sync.Once
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData = file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc
)

func file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescGZIP() []byte {
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData)
	})
	return file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData
}

var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_goTypes = []interface{}{
	(PreserveCaseFormatterConfig_FormatterTypeOnEnvoyHeaders)(0), // 0: envoy.extensions.http.header_formatters.preserve_case.v3.PreserveCaseFormatterConfig.FormatterTypeOnEnvoyHeaders
	(*PreserveCaseFormatterConfig)(nil),                          // 1: envoy.extensions.http.header_formatters.preserve_case.v3.PreserveCaseFormatterConfig
}
var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_depIdxs = []int32{
	0, // 0: envoy.extensions.http.header_formatters.preserve_case.v3.PreserveCaseFormatterConfig.formatter_type_on_envoy_headers:type_name -> envoy.extensions.http.header_formatters.preserve_case.v3.PreserveCaseFormatterConfig.FormatterTypeOnEnvoyHeaders
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_init() }
func file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_init() {
	if File_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreserveCaseFormatterConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_depIdxs,
		EnumInfos:         file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_enumTypes,
		MessageInfos:      file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes,
	}.Build()
	File_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto = out.File
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc = nil
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_goTypes = nil
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_depIdxs = nil
}
