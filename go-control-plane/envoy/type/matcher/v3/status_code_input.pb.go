// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.4
// source: envoy/type/matcher/v3/status_code_input.proto

package matcherv3

import (
	_ "gitee.com/zhaochuninhefei/gmgo/cncf_xds_go/udpa/annotations"
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

// Match input indicates that matching should be done on the response status
// code.
type HttpResponseStatusCodeMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *HttpResponseStatusCodeMatchInput) Reset() {
	*x = HttpResponseStatusCodeMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_type_matcher_v3_status_code_input_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HttpResponseStatusCodeMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HttpResponseStatusCodeMatchInput) ProtoMessage() {}

func (x *HttpResponseStatusCodeMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_type_matcher_v3_status_code_input_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HttpResponseStatusCodeMatchInput.ProtoReflect.Descriptor instead.
func (*HttpResponseStatusCodeMatchInput) Descriptor() ([]byte, []int) {
	return file_envoy_type_matcher_v3_status_code_input_proto_rawDescGZIP(), []int{0}
}

// Match input indicates that the matching should be done on the class of the
// response status code. For eg: 1xx, 2xx, 3xx, 4xx or 5xx.
type HttpResponseStatusCodeClassMatchInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *HttpResponseStatusCodeClassMatchInput) Reset() {
	*x = HttpResponseStatusCodeClassMatchInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_type_matcher_v3_status_code_input_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HttpResponseStatusCodeClassMatchInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HttpResponseStatusCodeClassMatchInput) ProtoMessage() {}

func (x *HttpResponseStatusCodeClassMatchInput) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_type_matcher_v3_status_code_input_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HttpResponseStatusCodeClassMatchInput.ProtoReflect.Descriptor instead.
func (*HttpResponseStatusCodeClassMatchInput) Descriptor() ([]byte, []int) {
	return file_envoy_type_matcher_v3_status_code_input_proto_rawDescGZIP(), []int{1}
}

var File_envoy_type_matcher_v3_status_code_input_proto protoreflect.FileDescriptor

var file_envoy_type_matcher_v3_status_code_input_proto_rawDesc = []byte{
	0x0a, 0x2d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x63,
	0x6f, 0x64, 0x65, 0x5f, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x15, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x22, 0x0a, 0x20, 0x48, 0x74, 0x74, 0x70, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65, 0x4d,
	0x61, 0x74, 0x63, 0x68, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x27, 0x0a, 0x25, 0x48, 0x74, 0x74,
	0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43,
	0x6f, 0x64, 0x65, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x49, 0x6e, 0x70,
	0x75, 0x74, 0x42, 0x8d, 0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x0a, 0x23, 0x69,
	0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e,
	0x76, 0x33, 0x42, 0x14, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65, 0x49, 0x6e,
	0x70, 0x75, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x46, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6d, 0x61,
	0x74, 0x63, 0x68, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x3b, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72,
	0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_type_matcher_v3_status_code_input_proto_rawDescOnce sync.Once
	file_envoy_type_matcher_v3_status_code_input_proto_rawDescData = file_envoy_type_matcher_v3_status_code_input_proto_rawDesc
)

func file_envoy_type_matcher_v3_status_code_input_proto_rawDescGZIP() []byte {
	file_envoy_type_matcher_v3_status_code_input_proto_rawDescOnce.Do(func() {
		file_envoy_type_matcher_v3_status_code_input_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_type_matcher_v3_status_code_input_proto_rawDescData)
	})
	return file_envoy_type_matcher_v3_status_code_input_proto_rawDescData
}

var file_envoy_type_matcher_v3_status_code_input_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_envoy_type_matcher_v3_status_code_input_proto_goTypes = []interface{}{
	(*HttpResponseStatusCodeMatchInput)(nil),      // 0: envoy.type.matcher.v3.HttpResponseStatusCodeMatchInput
	(*HttpResponseStatusCodeClassMatchInput)(nil), // 1: envoy.type.matcher.v3.HttpResponseStatusCodeClassMatchInput
}
var file_envoy_type_matcher_v3_status_code_input_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_envoy_type_matcher_v3_status_code_input_proto_init() }
func file_envoy_type_matcher_v3_status_code_input_proto_init() {
	if File_envoy_type_matcher_v3_status_code_input_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_type_matcher_v3_status_code_input_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HttpResponseStatusCodeMatchInput); i {
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
		file_envoy_type_matcher_v3_status_code_input_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HttpResponseStatusCodeClassMatchInput); i {
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
			RawDescriptor: file_envoy_type_matcher_v3_status_code_input_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_type_matcher_v3_status_code_input_proto_goTypes,
		DependencyIndexes: file_envoy_type_matcher_v3_status_code_input_proto_depIdxs,
		MessageInfos:      file_envoy_type_matcher_v3_status_code_input_proto_msgTypes,
	}.Build()
	File_envoy_type_matcher_v3_status_code_input_proto = out.File
	file_envoy_type_matcher_v3_status_code_input_proto_rawDesc = nil
	file_envoy_type_matcher_v3_status_code_input_proto_goTypes = nil
	file_envoy_type_matcher_v3_status_code_input_proto_depIdxs = nil
}
