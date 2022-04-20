// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.16.0
// source: envoy/extensions/common/matching/v3/extension_matcher.proto

package envoy_extensions_common_matching_v3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	v31 "github.com/cncf/xds/go/xds/type/matcher/v3"
	_ "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/annotations"
	v3 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/common/matcher/v3"
	v32 "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/config/core/v3"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// Wrapper around an existing extension that provides an associated matcher. This allows
// decorating an existing extension with a matcher, which can be used to match against
// relevant protocol data.
//
// [#alpha:]
type ExtensionWithMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The associated matcher. This is deprecated in favor of xds_matcher.
	//
	// Deprecated: Do not use.
	Matcher *v3.Matcher `protobuf:"bytes,1,opt,name=matcher,proto3" json:"matcher,omitempty"`
	// The associated matcher.
	XdsMatcher *v31.Matcher `protobuf:"bytes,3,opt,name=xds_matcher,json=xdsMatcher,proto3" json:"xds_matcher,omitempty"`
	// The underlying extension config.
	ExtensionConfig *v32.TypedExtensionConfig `protobuf:"bytes,2,opt,name=extension_config,json=extensionConfig,proto3" json:"extension_config,omitempty"`
}

func (x *ExtensionWithMatcher) Reset() {
	*x = ExtensionWithMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_common_matching_v3_extension_matcher_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExtensionWithMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExtensionWithMatcher) ProtoMessage() {}

func (x *ExtensionWithMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_common_matching_v3_extension_matcher_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExtensionWithMatcher.ProtoReflect.Descriptor instead.
func (*ExtensionWithMatcher) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescGZIP(), []int{0}
}

// Deprecated: Do not use.
func (x *ExtensionWithMatcher) GetMatcher() *v3.Matcher {
	if x != nil {
		return x.Matcher
	}
	return nil
}

func (x *ExtensionWithMatcher) GetXdsMatcher() *v31.Matcher {
	if x != nil {
		return x.XdsMatcher
	}
	return nil
}

func (x *ExtensionWithMatcher) GetExtensionConfig() *v32.TypedExtensionConfig {
	if x != nil {
		return x.ExtensionConfig
	}
	return nil
}

var File_envoy_extensions_common_matching_v3_extension_matcher_proto protoreflect.FileDescriptor

var file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDesc = []byte{
	0x0a, 0x3b, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x69,
	0x6e, 0x67, 0x2f, 0x76, 0x33, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x5f,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x23, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x2e,
	0x76, 0x33, 0x1a, 0x2c, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2f,
	0x76, 0x33, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x24, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63,
	0x6f, 0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x78, 0x64, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65,
	0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x2f, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x64, 0x65, 0x70,
	0x72, 0x65, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d,
	0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76,
	0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x86, 0x02, 0x0a, 0x14, 0x45, 0x78, 0x74, 0x65, 0x6e,
	0x73, 0x69, 0x6f, 0x6e, 0x57, 0x69, 0x74, 0x68, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12,
	0x4e, 0x0a, 0x07, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x27, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76,
	0x33, 0x2e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x42, 0x0b, 0x18, 0x01, 0x92, 0xc7, 0x86,
	0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x52, 0x07, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12,
	0x3d, 0x0a, 0x0b, 0x78, 0x64, 0x73, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x78, 0x64, 0x73, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x4d, 0x61, 0x74, 0x63, 0x68,
	0x65, 0x72, 0x52, 0x0a, 0x78, 0x64, 0x73, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12, 0x5f,
	0x0a, 0x10, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e,
	0x54, 0x79, 0x70, 0x65, 0x64, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10, 0x01, 0x52, 0x0f,
	0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42,
	0x54, 0x0a, 0x31, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x69, 0x6e,
	0x67, 0x2e, 0x76, 0x33, 0x42, 0x15, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x4d,
	0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0xba, 0x80, 0xc8,
	0xd1, 0x06, 0x02, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescOnce sync.Once
	file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescData = file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDesc
)

func file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescGZIP() []byte {
	file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescData)
	})
	return file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDescData
}

var file_envoy_extensions_common_matching_v3_extension_matcher_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_common_matching_v3_extension_matcher_proto_goTypes = []interface{}{
	(*ExtensionWithMatcher)(nil),     // 0: envoy.extensions.common.matching.v3.ExtensionWithMatcher
	(*v3.Matcher)(nil),               // 1: envoy.config.common.matcher.v3.Matcher
	(*v31.Matcher)(nil),              // 2: xds.type.matcher.v3.Matcher
	(*v32.TypedExtensionConfig)(nil), // 3: envoy.config.core.v3.TypedExtensionConfig
}
var file_envoy_extensions_common_matching_v3_extension_matcher_proto_depIdxs = []int32{
	1, // 0: envoy.extensions.common.matching.v3.ExtensionWithMatcher.matcher:type_name -> envoy.config.common.matcher.v3.Matcher
	2, // 1: envoy.extensions.common.matching.v3.ExtensionWithMatcher.xds_matcher:type_name -> xds.type.matcher.v3.Matcher
	3, // 2: envoy.extensions.common.matching.v3.ExtensionWithMatcher.extension_config:type_name -> envoy.config.core.v3.TypedExtensionConfig
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_envoy_extensions_common_matching_v3_extension_matcher_proto_init() }
func file_envoy_extensions_common_matching_v3_extension_matcher_proto_init() {
	if File_envoy_extensions_common_matching_v3_extension_matcher_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_common_matching_v3_extension_matcher_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExtensionWithMatcher); i {
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
			RawDescriptor: file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_common_matching_v3_extension_matcher_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_common_matching_v3_extension_matcher_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_common_matching_v3_extension_matcher_proto_msgTypes,
	}.Build()
	File_envoy_extensions_common_matching_v3_extension_matcher_proto = out.File
	file_envoy_extensions_common_matching_v3_extension_matcher_proto_rawDesc = nil
	file_envoy_extensions_common_matching_v3_extension_matcher_proto_goTypes = nil
	file_envoy_extensions_common_matching_v3_extension_matcher_proto_depIdxs = nil
}
