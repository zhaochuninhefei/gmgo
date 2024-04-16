// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: envoy/extensions/filters/http/set_metadata/v3/set_metadata.proto

package set_metadatav3

import (
	_ "gitee.com/zhaochuninhefei/gmgo/cncf_xds_go/udpa/annotations"
	_ "gitee.com/zhaochuninhefei/gmgo/go-control-plane/envoy/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	structpb "google.golang.org/protobuf/types/known/structpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Metadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The metadata namespace.
	MetadataNamespace string `protobuf:"bytes,1,opt,name=metadata_namespace,json=metadataNamespace,proto3" json:"metadata_namespace,omitempty"`
	// Allow the filter to overwrite or merge with an existing value in the namespace.
	AllowOverwrite bool `protobuf:"varint,2,opt,name=allow_overwrite,json=allowOverwrite,proto3" json:"allow_overwrite,omitempty"`
	// The value to place at the namespace. If “allow_overwrite“, this will
	// overwrite or merge with any existing values in that namespace. See
	// :ref:`the filter documentation <config_http_filters_set_metadata>` for
	// more information on how this value is merged with potentially existing
	// ones if “allow_overwrite“ is configured. Only one of “value“ and
	// “typed_value“ may be set.
	Value *structpb.Struct `protobuf:"bytes,3,opt,name=value,proto3" json:"value,omitempty"`
	// The value to place at the namespace. If “allow_overwrite“, this will
	// overwrite any existing values in that namespace. Only one of “value“ and
	// “typed_value“ may be set.
	TypedValue *anypb.Any `protobuf:"bytes,4,opt,name=typed_value,json=typedValue,proto3" json:"typed_value,omitempty"`
}

func (x *Metadata) Reset() {
	*x = Metadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Metadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Metadata) ProtoMessage() {}

func (x *Metadata) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Metadata.ProtoReflect.Descriptor instead.
func (*Metadata) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescGZIP(), []int{0}
}

func (x *Metadata) GetMetadataNamespace() string {
	if x != nil {
		return x.MetadataNamespace
	}
	return ""
}

func (x *Metadata) GetAllowOverwrite() bool {
	if x != nil {
		return x.AllowOverwrite
	}
	return false
}

func (x *Metadata) GetValue() *structpb.Struct {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *Metadata) GetTypedValue() *anypb.Any {
	if x != nil {
		return x.TypedValue
	}
	return nil
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The metadata namespace.
	// This field is deprecated; please use “metadata“ as replacement.
	//
	// Deprecated: Marked as deprecated in envoy/extensions/filters/http/set_metadata/v3/set_metadata.proto.
	MetadataNamespace string `protobuf:"bytes,1,opt,name=metadata_namespace,json=metadataNamespace,proto3" json:"metadata_namespace,omitempty"`
	// The untyped value to update the dynamic metadata namespace with. See
	// :ref:`the filter documentation <config_http_filters_set_metadata>` for
	// more information on how this value is merged with potentially existing
	// ones.
	// This field is deprecated; please use “metadata“ as replacement.
	//
	// Deprecated: Marked as deprecated in envoy/extensions/filters/http/set_metadata/v3/set_metadata.proto.
	Value *structpb.Struct `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	// Defines changes to be made to dynamic metadata.
	Metadata []*Metadata `protobuf:"bytes,3,rep,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescGZIP(), []int{1}
}

// Deprecated: Marked as deprecated in envoy/extensions/filters/http/set_metadata/v3/set_metadata.proto.
func (x *Config) GetMetadataNamespace() string {
	if x != nil {
		return x.MetadataNamespace
	}
	return ""
}

// Deprecated: Marked as deprecated in envoy/extensions/filters/http/set_metadata/v3/set_metadata.proto.
func (x *Config) GetValue() *structpb.Struct {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *Config) GetMetadata() []*Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDesc = []byte{
	0x0a, 0x40, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f,
	0x73, 0x65, 0x74, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x76, 0x33, 0x2f,
	0x73, 0x65, 0x74, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x2d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74,
	0x70, 0x2e, 0x73, 0x65, 0x74, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76,
	0x33, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74,
	0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x64, 0x65,
	0x70, 0x72, 0x65, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd1, 0x01, 0x0a, 0x08, 0x4d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x12, 0x36, 0x0a, 0x12, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x11, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x27, 0x0a, 0x0f,
	0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x6f, 0x76, 0x65, 0x72, 0x77, 0x72, 0x69, 0x74, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x4f, 0x76, 0x65, 0x72,
	0x77, 0x72, 0x69, 0x74, 0x65, 0x12, 0x2d, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x12, 0x35, 0x0a, 0x0b, 0x74, 0x79, 0x70, 0x65, 0x64, 0x5f, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52,
	0x0a, 0x74, 0x79, 0x70, 0x65, 0x64, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x22, 0xd5, 0x01, 0x0a, 0x06,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x3a, 0x0a, 0x12, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52,
	0x11, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x12, 0x3a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x17, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8,
	0x04, 0x03, 0x33, 0x2e, 0x30, 0x18, 0x01, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x53,
	0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x37, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70,
	0x2e, 0x73, 0x65, 0x74, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x33,
	0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x42, 0xbe, 0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x0a, 0x3b,
	0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x73, 0x65, 0x74, 0x5f,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x33, 0x42, 0x10, 0x53, 0x65, 0x74,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a,
	0x63, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x73, 0x65, 0x74, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x2f, 0x76, 0x33, 0x3b, 0x73, 0x65, 0x74, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescData = file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDesc
)

func file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescData)
	})
	return file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDescData
}

var file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_goTypes = []interface{}{
	(*Metadata)(nil),        // 0: envoy.extensions.filters.http.set_metadata.v3.Metadata
	(*Config)(nil),          // 1: envoy.extensions.filters.http.set_metadata.v3.Config
	(*structpb.Struct)(nil), // 2: google.protobuf.Struct
	(*anypb.Any)(nil),       // 3: google.protobuf.Any
}
var file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_depIdxs = []int32{
	2, // 0: envoy.extensions.filters.http.set_metadata.v3.Metadata.value:type_name -> google.protobuf.Struct
	3, // 1: envoy.extensions.filters.http.set_metadata.v3.Metadata.typed_value:type_name -> google.protobuf.Any
	2, // 2: envoy.extensions.filters.http.set_metadata.v3.Config.value:type_name -> google.protobuf.Struct
	0, // 3: envoy.extensions.filters.http.set_metadata.v3.Config.metadata:type_name -> envoy.extensions.filters.http.set_metadata.v3.Metadata
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_init() }
func file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_init() {
	if File_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Metadata); i {
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
		file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
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
			RawDescriptor: file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto = out.File
	file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_rawDesc = nil
	file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_goTypes = nil
	file_envoy_extensions_filters_http_set_metadata_v3_set_metadata_proto_depIdxs = nil
}
